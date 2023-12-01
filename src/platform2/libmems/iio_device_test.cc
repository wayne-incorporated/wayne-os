// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <optional>

#include <gtest/gtest.h>

#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>

#include "libmems/common_types.h"
#include "libmems/test_fakes.h"

namespace libmems {

namespace {

constexpr char kFakeChannelName1[] = "fake_channel1";
constexpr char kFakeChannelName2[] = "fake_channel2";

constexpr char kFakeDeviceName[] = "iio:device0";
constexpr int kFakeDeviceId = 0;

constexpr char kTrigger0Attr[] = "trigger0";
constexpr char kTrigger1Attr[] = "trigger1";
constexpr char kTrigger12Attr[] = "trigger12";

constexpr char kDevice0Attr[] = "iio:device0";
constexpr char kDevice1Attr[] = "iio:device1";
constexpr char kDevice12Attr[] = "iio:device12";

class IioDeviceTest : public fakes::FakeIioDevice, public ::testing::Test {
 public:
  static std::optional<int> GetIdAfterPrefix(const char* id_str,
                                             const char* prefix) {
    return IioDevice::GetIdAfterPrefix(id_str, prefix);
  }

  IioDeviceTest()
      : fakes::FakeIioDevice(nullptr, kFakeDeviceName, kFakeDeviceId),
        ::testing::Test() {}

 protected:
  void SetUp() override {
    auto channel1 =
        std::make_unique<fakes::FakeIioChannel>(kFakeChannelName1, false);
    channel1_ = channel1.get();
    AddChannel(std::move(channel1));

    auto channel2 =
        std::make_unique<fakes::FakeIioChannel>(kFakeChannelName2, false);
    channel2_ = channel2.get();
    AddChannel(std::move(channel2));
  }

  fakes::FakeIioChannel* channel1_;
  fakes::FakeIioChannel* channel2_;
};

TEST_F(IioDeviceTest, GetAbsoluteSysPath) {
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());
  base::FilePath foo_dir = temp_dir.GetPath().Append("foo_dir");
  base::FilePath bar_dir = temp_dir.GetPath().Append("bar_dir");
  ASSERT_TRUE(base::CreateDirectory(foo_dir));
  ASSERT_TRUE(base::CreateDirectory(bar_dir));
  base::FilePath link_from = foo_dir.Append("from_file"), link_to;

  ASSERT_TRUE(base::CreateTemporaryFileInDir(bar_dir, &link_to));
  ASSERT_TRUE(base::CreateSymbolicLink(
      base::FilePath("../bar_dir").Append(link_to.BaseName()), link_from))
      << "Failed to create file symlink.";

  SetPath(link_from);

  auto sys_path = GetAbsoluteSysPath();
  EXPECT_TRUE(sys_path.has_value());
  EXPECT_EQ(sys_path->value().compare(link_to.value()), 0);
}

TEST_F(IioDeviceTest, GetIdAfterPrefixTest) {
  EXPECT_EQ(GetIdAfterPrefix(kTrigger0Attr, kTriggerIdPrefix), 0);
  EXPECT_EQ(GetIdAfterPrefix(kTrigger1Attr, kTriggerIdPrefix), 1);
  EXPECT_EQ(GetIdAfterPrefix(kTrigger12Attr, kTriggerIdPrefix), 12);

  EXPECT_EQ(GetIdAfterPrefix(kDevice0Attr, kDeviceIdPrefix), 0);
  EXPECT_EQ(GetIdAfterPrefix(kDevice1Attr, kDeviceIdPrefix), 1);
  EXPECT_EQ(GetIdAfterPrefix(kDevice12Attr, kDeviceIdPrefix), 12);
}

TEST_F(IioDeviceTest, GetAllChannels) {
  auto channels = GetAllChannels();
  EXPECT_EQ(channels.size(), 2);
  EXPECT_EQ(channels[0], channel1_);
  EXPECT_EQ(channels[1], channel2_);
}

TEST_F(IioDeviceTest, GetChannelByIndex) {
  EXPECT_EQ(GetChannel(0), channel1_);
  EXPECT_EQ(GetChannel(1), channel2_);
}

TEST_F(IioDeviceTest, GetChannelByName) {
  EXPECT_EQ(GetChannel(kFakeChannelName1), channel1_);
  EXPECT_EQ(GetChannel(kFakeChannelName2), channel2_);
}

class IioDeviceTestOnMinMaxFrequencyWithParam
    : public ::testing::TestWithParam<
          std::tuple<std::string, bool, double, double>> {
 protected:
  void SetUp() override {
    device_ = std::make_unique<libmems::fakes::FakeIioDevice>(
        nullptr, kFakeDeviceName, kFakeDeviceId);

    EXPECT_TRUE(device_->WriteStringAttribute(kSamplingFrequencyAvailable,
                                              std::get<0>(GetParam())));

    result_ = device_->GetMinMaxFrequency(&min_freq_, &max_freq_);
  }

  std::unique_ptr<libmems::fakes::FakeIioDevice> device_;
  bool result_;
  double min_freq_ = -1;
  double max_freq_ = -1;
};

TEST_P(IioDeviceTestOnMinMaxFrequencyWithParam, ParseMinMaxFrequency) {
  EXPECT_EQ(result_, std::get<1>(GetParam()));
  if (!result_)
    return;

  EXPECT_EQ(min_freq_, std::get<2>(GetParam()));
  EXPECT_EQ(max_freq_, std::get<3>(GetParam()));
}

INSTANTIATE_TEST_SUITE_P(
    IioDeviceTestOnMinMaxFrequencyWithParamRun,
    IioDeviceTestOnMinMaxFrequencyWithParam,
    ::testing::Values(
        std::make_tuple("  ", false, 0.0, 0.0),
        std::make_tuple("  0abc  ", false, 0.0, 0.0),
        std::make_tuple(" 0.0001 ", false, 0.0, 0.0),
        std::make_tuple("0.5  ", true, 0.5, 0.5),
        std::make_tuple("  1000  ", true, 1000.0, 1000.0),
        std::make_tuple("1.0 100.0 ", true, 1.0, 100.0),
        std::make_tuple("1.0 10.0 100.0 ", true, 1.0, 100.0),
        std::make_tuple("1.0 a b c 100.0 ", true, 1.0, 100.0),
        std::make_tuple("0.0 a b c 100.0 ", false, 0.0, 0.0),
        std::make_tuple("0.0 1.0 100.0 ", true, 1.0, 100.0),
        std::make_tuple("0.0 2.0 a b c 100.0 ", true, 2.0, 100.0)));

class IioDeviceTestOnLocationWithParam
    : public ::testing::TestWithParam<std::tuple<std::optional<std::string>,
                                                 std::optional<std::string>,
                                                 std::optional<std::string>>> {
 protected:
  void SetUp() override {
    device_ = std::make_unique<libmems::fakes::FakeIioDevice>(
        nullptr, kFakeDeviceName, kFakeDeviceId);

    if (std::get<0>(GetParam()).has_value()) {
      EXPECT_TRUE(device_->WriteStringAttribute(
          kLabelAttr, std::get<0>(GetParam()).value()));
    }
    if (std::get<1>(GetParam()).has_value()) {
      EXPECT_TRUE(device_->WriteStringAttribute(
          kLocationAttr, std::get<1>(GetParam()).value()));
    }
  }

  std::unique_ptr<libmems::fakes::FakeIioDevice> device_;
};

TEST_P(IioDeviceTestOnLocationWithParam, GetLocation) {
  EXPECT_EQ(device_->GetLocation(), std::get<2>(GetParam()));
}

INSTANTIATE_TEST_SUITE_P(
    IioDeviceTestOnLocationWithParamRun,
    IioDeviceTestOnLocationWithParam,
    ::testing::Values(std::make_tuple(std::nullopt, std::nullopt, std::nullopt),
                      std::make_tuple(std::nullopt, "base", "base"),
                      std::make_tuple(std::nullopt, "lid", "lid"),
                      std::make_tuple(std::nullopt, "camera", "camera"),
                      std::make_tuple("accel-base", std::nullopt, "base"),
                      std::make_tuple("accel-display", "base", "lid"),
                      std::make_tuple("accel-camera", "lid", "camera")));

}  // namespace

}  // namespace libmems
