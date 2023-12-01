// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <gtest/gtest.h>

#include <memory>

#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/strings/stringprintf.h>
#include <libmems/common_types.h>

#include "mems_setup/configuration.h"
#include "mems_setup/delegate.h"
#include "mems_setup/sensor_location.h"
#include "mems_setup/test_fakes.h"
#include "mems_setup/test_helper.h"

using mems_setup::testing::SensorTestBase;

namespace mems_setup {

namespace {

static gid_t kIioserviceGroupId = 777;

constexpr int kDeviceId = 1;

constexpr char kSystemPath[] = "/proximity-sensor/semtech-config/0/file";

constexpr char kFakeDevlink[] = "/dev/proximity_lte";
constexpr char kProximityConfigPath[] =
    "/usr/share/chromeos-assets/proximity-sensor/bugzzy/"
    "semtech_config_cellular.json";
constexpr char kProximityConfigJson[] =
    "{\"channelConfig\": [{\"channel\" : \"1\", \"hardwaregain\" : 2, "
    "\"threshFalling\" : 1014, \"threshFallingHysteresis\" : 73, "
    "\"threshRising\" : 1014, \"threshRisingHysteresis\" : 72}], "
    "\"threshFallingPeriod\" : 2, \"threshRisingPeriod\" : 2}";

constexpr char kDevlinkPrefix[] = "/dev/proximity-%s";
constexpr char kProximityConfigPrefix[] =
    "/usr/share/chromeos-assets/proximity-sensor/bugzzy/"
    "semtech_config_%s.json";

class ProximityTest : public SensorTestBase, public ::testing::Test {
 public:
  ProximityTest() : SensorTestBase("sx9360", kDeviceId) {
    SetAbsolutePath();
    mock_delegate_->AddGroup(GetConfiguration()->GetGroupNameForSysfs(),
                             kIioserviceGroupId);

    mock_delegate_->SetStringToFile(base::FilePath(kProximityConfigPath),
                                    kProximityConfigJson);

    mock_delegate_->GetFakeCrosConfig()->SetString(
        kSystemPath, libsar::SarConfigReader::kSystemPathProperty,
        kProximityConfigPath);

    mock_delegate_->SetMockDevlink(kFakeDevlink);
  }

  void SetAbsolutePath() {
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

    mock_device_->SetPath(link_from);
  }

  base::ScopedTempDir temp_dir;
};

TEST_F(ProximityTest, SetEvents) {
  SetSingleSensor(kBaseSensorLocation);
  EXPECT_TRUE(GetConfiguration()->Configure());

  EXPECT_TRUE(mock_device_->GetChannel("proximity1")
                  ->ReadNumberAttribute("hardwaregain")
                  .has_value());
  EXPECT_EQ(2, mock_device_->GetChannel("proximity1")
                   ->ReadNumberAttribute("hardwaregain")
                   .value());

  EXPECT_TRUE(
      mock_device_
          ->ReadNumberAttribute("events/in_proximity1_thresh_either_value")
          .has_value());
  EXPECT_EQ(1014, mock_device_
                      ->ReadNumberAttribute(
                          "events/in_proximity1_thresh_either_value")
                      .value());

  EXPECT_FALSE(
      mock_device_
          ->ReadNumberAttribute("events/in_proximity1_thresh_either_hysteresis")
          .has_value());
  EXPECT_TRUE(mock_device_
                  ->ReadNumberAttribute(
                      "events/in_proximity1_thresh_falling_hysteresis")
                  .has_value());
  EXPECT_TRUE(
      mock_device_
          ->ReadNumberAttribute("events/in_proximity1_thresh_rising_hysteresis")
          .has_value());
  EXPECT_EQ(73, mock_device_
                    ->ReadNumberAttribute(
                        "events/in_proximity1_thresh_falling_hysteresis")
                    .value());
  EXPECT_EQ(72, mock_device_
                    ->ReadNumberAttribute(
                        "events/in_proximity1_thresh_rising_hysteresis")
                    .value());

  EXPECT_TRUE(mock_device_->ReadNumberAttribute("events/thresh_either_period")
                  .has_value());
  EXPECT_EQ(
      2,
      mock_device_->ReadNumberAttribute("events/thresh_either_period").value());
}

class ProximityTestWithParam : public SensorTestBase,
                               public ::testing::TestWithParam<
                                   std::tuple<std::string, std::string, bool>> {
 public:
  ProximityTestWithParam() : SensorTestBase("sx9360", kDeviceId) {
    SetAbsolutePath();
    mock_delegate_->AddGroup(GetConfiguration()->GetGroupNameForSysfs(),
                             kIioserviceGroupId);

    std::string proximity_config_path = base::StringPrintf(
        kProximityConfigPrefix, std::get<1>(GetParam()).c_str());
    mock_delegate_->SetStringToFile(base::FilePath(proximity_config_path),
                                    kProximityConfigJson);

    mock_delegate_->GetFakeCrosConfig()->SetString(
        kSystemPath, libsar::SarConfigReader::kSystemPathProperty,
        proximity_config_path);

    mock_delegate_->SetMockDevlink(
        base::StringPrintf(kDevlinkPrefix, std::get<0>(GetParam()).c_str()));
  }

  void SetAbsolutePath() {
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

    mock_device_->SetPath(link_from);
  }

  base::ScopedTempDir temp_dir;
};

TEST_P(ProximityTestWithParam, TypeCheck) {
  SetSingleSensor(kBaseSensorLocation);
  EXPECT_EQ(GetConfiguration()->Configure(), std::get<2>(GetParam()));
}

INSTANTIATE_TEST_SUITE_P(
    ProximityTestWithParamRun,
    ProximityTestWithParam,
    ::testing::Values(std::make_tuple("lte-wifi", "wifi_cellular", true),
                      std::make_tuple("lte-wifi", "wifi_lte", true),
                      std::make_tuple("lte-wifi", "cellular_wifi", true),
                      std::make_tuple("cellular-wifi", "lte_wifi", true),
                      std::make_tuple("lte", "cellular", true),
                      std::make_tuple("cellular", "lte", true),
                      std::make_tuple("wifi", "wifi", true),
                      std::make_tuple("cellula-wif", "lte_wifi", false),
                      std::make_tuple("lte-wifi", "lte", false),
                      std::make_tuple("lte-wifi", "cellular", false),
                      std::make_tuple("lte-wifi", "wifi", false),
                      std::make_tuple("wifi", "lte", false),
                      std::make_tuple("lte", "wifi", false)));

}  // namespace

}  // namespace mems_setup
