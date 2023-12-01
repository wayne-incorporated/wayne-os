// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <array>
#include <memory>
#include <string>
#include <vector>

#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/strings/string_number_conversions.h>
#include <base/test/task_environment.h>
#include <gtest/gtest.h>

#include "mojo/core/embedder/embedder.h"
#include "rmad/utils/iio_ec_sensor_utils_impl.h"
#include "rmad/utils/mock_mojo_service_utils.h"
#include "rmad/utils/mock_sensor_device.h"
#include "rmad/utils/mojo_service_utils.h"

using testing::_;
using testing::DoAll;
using testing::Return;
using testing::SetArgPointee;
using testing::StrictMock;
using testing::WithArg;

namespace {

constexpr char kTestIioSysfsPrefix[] = "iio_test_";
constexpr int kNumberOfIioEntries = 19;

constexpr char kTestFreqAvailableLocation[] = "test_freq_available_location";
constexpr char kTestScaleLocation[] = "test_scale_location";
constexpr char kTestSysValueLocation[] = "test_sys_value_location";

constexpr char kTestIntName[] = "test_int";
constexpr char kTestFloatName[] = "test_float";
constexpr char kTestFloatRangeName[] = "test_float_range";
constexpr char kTestDiscreteSetName[] = "test_discrete_set";
constexpr char kTestTrailingSpaceName[] = "test_trailing_space";
constexpr char kTestInvalidName[] = "test_invalid";
constexpr char kTestNotAvailableName[] = "test_not_available";
constexpr char kTestInitFailedName[] = "test_init_failed";

// Used for test cases at initialization.
constexpr std::array<const char*, 7> kIioEcProperties = {
    "location",
    "name",
    "sampling_frequency_available",
    "scale",
    "test_sys_entry1",
    "test_sys_entry2",
    "test_sys_entry3"};
constexpr std::array<std::array<const char*, 7>, kNumberOfIioEntries>
    kIioEcEntries = {{
        {"", kTestIntName, "0 13 208", "1.0"},
        {kTestFreqAvailableLocation, "", "0 13 208", "1.0"},
        {kTestFreqAvailableLocation, kTestIntName, "208", "1.0"},
        {kTestFreqAvailableLocation, kTestFloatName, "208.0", "1.0"},
        {kTestFreqAvailableLocation, kTestFloatRangeName, "0.0 13.0 208.0",
         "1.0"},
        {kTestFreqAvailableLocation, kTestDiscreteSetName, "0.0 13.0 26.0 52.0",
         "1.0"},
        {kTestFreqAvailableLocation, kTestTrailingSpaceName,
         "0.0 13.0 26.0 52.0   ", "1.0"},
        {kTestFreqAvailableLocation, kTestInvalidName, "123 abc", "1.0"},
        {kTestFreqAvailableLocation, kTestNotAvailableName, "", "1.0"},
        {kTestScaleLocation, kTestIntName, "0.0 13.0 208.0", "1"},
        {kTestScaleLocation, kTestFloatName, "0.0 13.0 208.0", "1.0"},
        {kTestScaleLocation, kTestTrailingSpaceName, "0.0 13.0 208.0", "1.0 "},
        {kTestScaleLocation, kTestInvalidName, "0.0 13.0 208.0", "1.0 abc"},
        {kTestScaleLocation, kTestNotAvailableName, "0.0 13.0 208.0", ""},
        {kTestSysValueLocation, kTestIntName, "0.0 13.0 208.0", "1.0", "1", "2",
         "3"},
        {kTestSysValueLocation, kTestFloatName, "0.0 13.0 208.0", "1.0", "1.0",
         "2.0", "3.0"},
        {kTestSysValueLocation, kTestInitFailedName, "0.0 13.0 208.0",
         "1.0 abc", "1.0", "2.0", "3.0"},
        {kTestSysValueLocation, kTestNotAvailableName, "0.0 13.0 208.0", "1.0",
         "1.0", "2.0", ""},
        {kTestSysValueLocation, kTestInvalidName, "0.0 13.0 208.0", "1.0",
         "1.0", "2.0", ""},
    }};

const std::vector<std::string> kTestSysEntries = {
    "test_sys_entry1", "test_sys_entry2", "test_sys_entry3"};
constexpr std::array<double, 3> kTestSysValues = {1.0, 2.0, 3.0};

const std::vector<std::string> kTestChannels = {"channel1", "channel2",
                                                "channel3"};
constexpr int kTestSamples = 3;
constexpr int kNumberFirstReadsDiscarded = 10;

}  // namespace

namespace rmad {

class IioEcSensorUtilsImplTest : public testing::Test {
 public:
  IioEcSensorUtilsImplTest() = default;

  std::unique_ptr<IioEcSensorUtilsImpl> CreateIioEcSensorUtils(
      const std::string& location, const std::string& name) {
    return std::make_unique<IioEcSensorUtilsImpl>(
        mojo_service_, location, name,
        temp_dir_.GetPath().Append(kTestIioSysfsPrefix).MaybeAsASCII());
  }

  std::unique_ptr<IioEcSensorUtilsImpl> CreateIioEcSensorUtils(
      scoped_refptr<MojoServiceUtils> mojo_service,
      const std::string& location,
      const std::string& name) {
    return std::make_unique<IioEcSensorUtilsImpl>(
        mojo_service, location, name,
        temp_dir_.GetPath().Append(kTestIioSysfsPrefix).MaybeAsASCII());
  }

 protected:
  void SetUp() override {
    mojo::core::Init();

    ASSERT_TRUE(temp_dir_.CreateUniqueTempDir());
    base::FilePath base_path = temp_dir_.GetPath();
    for (int i = 0; i < kNumberOfIioEntries; i++) {
      std::string dirname = kTestIioSysfsPrefix + base::NumberToString(i);
      base::FilePath dir_path = base_path.AppendASCII(dirname);
      EXPECT_TRUE(base::CreateDirectory(dir_path));

      for (int j = 0; j < kIioEcProperties.size(); j++) {
        if (kIioEcEntries[i][j]) {
          base::FilePath file_path = dir_path.AppendASCII(kIioEcProperties[j]);
          base::WriteFile(file_path, kIioEcEntries[i][j],
                          strlen(kIioEcEntries[i][j]));
        }
      }
    }
  }

  scoped_refptr<MojoServiceUtils> mojo_service_;
  base::ScopedTempDir temp_dir_;
  base::test::TaskEnvironment task_environment_;
};

TEST_F(IioEcSensorUtilsImplTest, GetAvgData_Sucess) {
  auto mock_mojo_service =
      base::MakeRefCounted<StrictMock<MockMojoServiceUtils>>();
  auto mock_sensor_device = StrictMock<MockSensorDevice>();

  EXPECT_CALL(mock_sensor_device, GetAllChannelIds(_))
      .Times(1)
      .WillOnce(WithArg<0>(
          [](base::OnceCallback<void(const std::vector<std::string>&)> cb) {
            std::move(cb).Run(kTestChannels);
          }));
  EXPECT_CALL(mock_sensor_device, SetTimeout(_)).Times(1);
  EXPECT_CALL(mock_sensor_device, SetFrequency(_, _)).Times(1);
  EXPECT_CALL(mock_sensor_device, SetChannelsEnabled(_, _, _))
      .Times(1)
      .WillOnce(WithArg<2>(
          [](base::OnceCallback<void(const std::vector<int32_t>&)> cb) {
            std::move(cb).Run({});
          }));
  EXPECT_CALL(mock_sensor_device, StartReadingSamples(_))
      .Times(1)
      .WillOnce(WithArg<0>(
          [](mojo::PendingRemote<cros::mojom::SensorDeviceSamplesObserver>
                 observer) {
            mojo::Remote<cros::mojom::SensorDeviceSamplesObserver> remote;
            remote.Bind(std::move(observer));
            auto samples_in_total = kNumberFirstReadsDiscarded + kTestSamples;
            for (int i = 0; i < samples_in_total; ++i) {
              remote->OnSampleUpdated({{0, 1}, {1, 1}, {2, 1}});
            }
            remote.FlushForTesting();
          }));
  EXPECT_CALL(mock_sensor_device, StopReadingSamples()).Times(1);

  EXPECT_CALL(*mock_mojo_service, GetSensorDevice(_))
      .Times(6)
      .WillRepeatedly(Return(&mock_sensor_device));

  auto iio_ec_sensor_utils = CreateIioEcSensorUtils(
      mock_mojo_service, kTestFreqAvailableLocation, kTestIntName);

  EXPECT_TRUE(iio_ec_sensor_utils->IsInitialized());
  EXPECT_TRUE(iio_ec_sensor_utils->GetAvgData(base::DoNothing(), kTestChannels,
                                              kTestSamples));
}

TEST_F(IioEcSensorUtilsImplTest, Initialize_FreqAvailableInt_Success) {
  auto iio_ec_sensor_utils =
      CreateIioEcSensorUtils(kTestFreqAvailableLocation, kTestIntName);

  EXPECT_TRUE(iio_ec_sensor_utils->IsInitialized());
  EXPECT_EQ(iio_ec_sensor_utils->GetLocation(), kTestFreqAvailableLocation);
  EXPECT_EQ(iio_ec_sensor_utils->GetName(), kTestIntName);
}

TEST_F(IioEcSensorUtilsImplTest, Initialize_FreqAvailableFloat_Success) {
  auto iio_ec_sensor_utils =
      CreateIioEcSensorUtils(kTestFreqAvailableLocation, kTestFloatName);

  EXPECT_TRUE(iio_ec_sensor_utils->IsInitialized());
  EXPECT_EQ(iio_ec_sensor_utils->GetLocation(), kTestFreqAvailableLocation);
  EXPECT_EQ(iio_ec_sensor_utils->GetName(), kTestFloatName);
}

TEST_F(IioEcSensorUtilsImplTest, Initialize_FreqAvailableFloatRange_Success) {
  auto iio_ec_sensor_utils =
      CreateIioEcSensorUtils(kTestFreqAvailableLocation, kTestFloatRangeName);

  EXPECT_TRUE(iio_ec_sensor_utils->IsInitialized());
  EXPECT_EQ(iio_ec_sensor_utils->GetLocation(), kTestFreqAvailableLocation);
  EXPECT_EQ(iio_ec_sensor_utils->GetName(), kTestFloatRangeName);
}

TEST_F(IioEcSensorUtilsImplTest, Initialize_FreqAvailableDiscreteSet_Success) {
  auto iio_ec_sensor_utils =
      CreateIioEcSensorUtils(kTestFreqAvailableLocation, kTestDiscreteSetName);

  EXPECT_TRUE(iio_ec_sensor_utils->IsInitialized());
  EXPECT_EQ(iio_ec_sensor_utils->GetLocation(), kTestFreqAvailableLocation);
  EXPECT_EQ(iio_ec_sensor_utils->GetName(), kTestDiscreteSetName);
}

TEST_F(IioEcSensorUtilsImplTest,
       Initialize_FreqAvailableTrailingSpace_Success) {
  auto iio_ec_sensor_utils = CreateIioEcSensorUtils(kTestFreqAvailableLocation,
                                                    kTestTrailingSpaceName);

  EXPECT_TRUE(iio_ec_sensor_utils->IsInitialized());
  EXPECT_EQ(iio_ec_sensor_utils->GetLocation(), kTestFreqAvailableLocation);
  EXPECT_EQ(iio_ec_sensor_utils->GetName(), kTestTrailingSpaceName);
}

TEST_F(IioEcSensorUtilsImplTest, Initialize_FreqAvailableInvalid_Failed) {
  auto iio_ec_sensor_utils =
      CreateIioEcSensorUtils(kTestFreqAvailableLocation, kTestInvalidName);

  EXPECT_FALSE(iio_ec_sensor_utils->IsInitialized());
}

TEST_F(IioEcSensorUtilsImplTest, Initialize_FreqAvailableNotAvailable_Failed) {
  auto iio_ec_sensor_utils =
      CreateIioEcSensorUtils(kTestFreqAvailableLocation, kTestNotAvailableName);

  EXPECT_FALSE(iio_ec_sensor_utils->IsInitialized());
}

TEST_F(IioEcSensorUtilsImplTest, Initialize_ScaleInt_Success) {
  auto iio_ec_sensor_utils =
      CreateIioEcSensorUtils(kTestScaleLocation, kTestIntName);

  EXPECT_TRUE(iio_ec_sensor_utils->IsInitialized());
  EXPECT_EQ(iio_ec_sensor_utils->GetLocation(), kTestScaleLocation);
  EXPECT_EQ(iio_ec_sensor_utils->GetName(), kTestIntName);
}

TEST_F(IioEcSensorUtilsImplTest, Initialize_ScaleFloat_Success) {
  auto iio_ec_sensor_utils =
      CreateIioEcSensorUtils(kTestScaleLocation, kTestFloatName);

  EXPECT_TRUE(iio_ec_sensor_utils->IsInitialized());
  EXPECT_EQ(iio_ec_sensor_utils->GetLocation(), kTestScaleLocation);
  EXPECT_EQ(iio_ec_sensor_utils->GetName(), kTestFloatName);
}

TEST_F(IioEcSensorUtilsImplTest, Initialize_ScaleTrailingSpace_Success) {
  auto iio_ec_sensor_utils =
      CreateIioEcSensorUtils(kTestScaleLocation, kTestTrailingSpaceName);

  EXPECT_TRUE(iio_ec_sensor_utils->IsInitialized());
  EXPECT_EQ(iio_ec_sensor_utils->GetLocation(), kTestScaleLocation);
  EXPECT_EQ(iio_ec_sensor_utils->GetName(), kTestTrailingSpaceName);
}

TEST_F(IioEcSensorUtilsImplTest, Initialize_ScaleInvalid_Failed) {
  auto iio_ec_sensor_utils =
      CreateIioEcSensorUtils(kTestScaleLocation, kTestInvalidName);

  EXPECT_FALSE(iio_ec_sensor_utils->IsInitialized());
}

TEST_F(IioEcSensorUtilsImplTest, Initialize_ScaleNotAvailable_Failed) {
  auto iio_ec_sensor_utils =
      CreateIioEcSensorUtils(kTestScaleLocation, kTestNotAvailableName);

  EXPECT_FALSE(iio_ec_sensor_utils->IsInitialized());
}

TEST_F(IioEcSensorUtilsImplTest, GetSysValue_Int_Success) {
  auto iio_ec_sensor_utils =
      CreateIioEcSensorUtils(kTestSysValueLocation, kTestIntName);

  std::vector<double> values;
  EXPECT_TRUE(iio_ec_sensor_utils->GetSysValues(kTestSysEntries, &values));
  EXPECT_EQ(values.size(), kTestSysEntries.size());
  for (int i = 0; i < kTestSysEntries.size(); i++) {
    EXPECT_DOUBLE_EQ(values[i], kTestSysValues[i]);
  }
}

TEST_F(IioEcSensorUtilsImplTest, GetSysValue_Float_Success) {
  auto iio_ec_sensor_utils =
      CreateIioEcSensorUtils(kTestSysValueLocation, kTestFloatName);

  std::vector<double> values;
  EXPECT_TRUE(iio_ec_sensor_utils->GetSysValues(kTestSysEntries, &values));
  EXPECT_EQ(values.size(), kTestSysEntries.size());
  for (int i = 0; i < kTestSysEntries.size(); i++) {
    EXPECT_DOUBLE_EQ(values[i], kTestSysValues[i]);
  }
}

TEST_F(IioEcSensorUtilsImplTest, GetSysValue_NotInitialized_Failed) {
  auto iio_ec_sensor_utils =
      CreateIioEcSensorUtils(kTestSysValueLocation, kTestInitFailedName);

  std::vector<double> values;
  EXPECT_FALSE(iio_ec_sensor_utils->GetSysValues(kTestSysEntries, &values));
}

TEST_F(IioEcSensorUtilsImplTest, GetSysValue_EntryNotAvailable_Failed) {
  auto iio_ec_sensor_utils =
      CreateIioEcSensorUtils(kTestSysValueLocation, kTestNotAvailableName);

  std::vector<double> values;
  EXPECT_FALSE(iio_ec_sensor_utils->GetSysValues(kTestSysEntries, &values));
}

TEST_F(IioEcSensorUtilsImplTest, GetSysValue_InvalidValue_Failed) {
  auto iio_ec_sensor_utils =
      CreateIioEcSensorUtils(kTestSysValueLocation, kTestInvalidName);

  std::vector<double> values;
  EXPECT_FALSE(iio_ec_sensor_utils->GetSysValues(kTestSysEntries, &values));
}

}  // namespace rmad
