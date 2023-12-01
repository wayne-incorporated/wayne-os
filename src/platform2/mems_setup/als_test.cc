// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <map>
#include <memory>
#include <string>

#include <base/strings/stringprintf.h>
#include <gtest/gtest.h>

#include <libmems/common_types.h>
#include <libmems/iio_context.h>
#include <libmems/iio_device.h>
#include <libmems/test_fakes.h>
#include "mems_setup/configuration.h"
#include "mems_setup/delegate.h"
#include "mems_setup/sensor_location.h"
#include "mems_setup/test_fakes.h"
#include "mems_setup/test_helper.h"

using mems_setup::testing::SensorTestBase;

namespace mems_setup {

namespace {

constexpr int kDeviceId = 5;
static gid_t kIioserviceGroupId = 777;

class AlsTest : public SensorTestBase, public ::testing::Test {
 public:
  AlsTest() : SensorTestBase("acpi-als", kDeviceId) {
    mock_delegate_->AddGroup(GetConfiguration()->GetGroupNameForSysfs(),
                             kIioserviceGroupId);
    mock_delegate_->SetMockContext(mock_context_.get());
  }
};

TEST_F(AlsTest, TriggerSet) {
  SetSingleSensor(kBaseSensorLocation);
  ConfigureVpd({{"als_cal_intercept", "100"}});

  EXPECT_TRUE(GetConfiguration()->Configure());

  EXPECT_FALSE(mock_device_->GetTrigger());
  EXPECT_EQ(mock_context_
                ->GetTriggersByName(base::StringPrintf(
                    libmems::kHrtimerNameFormatString, kDeviceId))
                .size(),
            1);
}

TEST_F(AlsTest, PartialVpd) {
  SetSingleSensor(kBaseSensorLocation);
  ConfigureVpd({{"als_cal_intercept", "100"}});

  EXPECT_TRUE(GetConfiguration()->Configure());

  EXPECT_TRUE(mock_device_->GetChannel("illuminance")
                  ->ReadDoubleAttribute("calibbias")
                  .has_value());
  EXPECT_EQ(100, mock_device_->GetChannel("illuminance")
                     ->ReadDoubleAttribute("calibbias")
                     .value());
  EXPECT_FALSE(mock_device_->GetChannel("illuminance")
                   ->ReadDoubleAttribute("calibscale")
                   .has_value());
}

TEST_F(AlsTest, VpdFormatError) {
  SetSingleSensor(kBaseSensorLocation);
  ConfigureVpd({{"als_cal_slope", "abc"}});

  EXPECT_TRUE(GetConfiguration()->Configure());

  EXPECT_FALSE(mock_device_->GetChannel("illuminance")
                   ->ReadDoubleAttribute("calibbias")
                   .has_value());
  EXPECT_FALSE(mock_device_->GetChannel("illuminance")
                   ->ReadDoubleAttribute("calibscale")
                   .has_value());
}

TEST_F(AlsTest, ValidVpd) {
  SetSingleSensor(kBaseSensorLocation);
  ConfigureVpd({{"als_cal_intercept", "1.25"}, {"als_cal_slope", "12.5"}});

  EXPECT_TRUE(GetConfiguration()->Configure());

  EXPECT_TRUE(mock_device_->GetChannel("illuminance")
                  ->ReadDoubleAttribute("calibbias")
                  .has_value());
  EXPECT_EQ(1.25, mock_device_->GetChannel("illuminance")
                      ->ReadDoubleAttribute("calibbias")
                      .value());
  EXPECT_TRUE(mock_device_->GetChannel("illuminance")
                  ->ReadDoubleAttribute("calibscale")
                  .has_value());
  EXPECT_EQ(12.5, mock_device_->GetChannel("illuminance")
                      ->ReadDoubleAttribute("calibscale")
                      .value());
}

TEST_F(AlsTest, VpdCalSlopeColorGood) {
  SetColorLightSensor();
  ConfigureVpd({{"als_cal_slope_color", "1.1 1.2 1.3"}});

  EXPECT_TRUE(GetConfiguration()->Configure());

  EXPECT_TRUE(mock_device_->GetChannel("illuminance_red")
                  ->ReadDoubleAttribute("calibscale")
                  .has_value());
  EXPECT_EQ(1.1, mock_device_->GetChannel("illuminance_red")
                     ->ReadDoubleAttribute("calibscale")
                     .value());

  EXPECT_TRUE(mock_device_->GetChannel("illuminance_green")
                  ->ReadDoubleAttribute("calibscale")
                  .has_value());
  EXPECT_EQ(1.2, mock_device_->GetChannel("illuminance_green")
                     ->ReadDoubleAttribute("calibscale")
                     .value());

  EXPECT_TRUE(mock_device_->GetChannel("illuminance_blue")
                  ->ReadDoubleAttribute("calibscale")
                  .has_value());
  EXPECT_EQ(1.3, mock_device_->GetChannel("illuminance_blue")
                     ->ReadDoubleAttribute("calibscale")
                     .value());
}

TEST_F(AlsTest, VpdCalSlopeColorCorrupted) {
  SetColorLightSensor();
  ConfigureVpd({{"als_cal_slope_color", "1.1 no 1.3"}});

  EXPECT_TRUE(GetConfiguration()->Configure());

  EXPECT_TRUE(mock_device_->GetChannel("illuminance_red")
                  ->ReadDoubleAttribute("calibscale")
                  .has_value());
  EXPECT_EQ(1.1, mock_device_->GetChannel("illuminance_red")
                     ->ReadDoubleAttribute("calibscale")
                     .value());

  EXPECT_FALSE(mock_device_->GetChannel("illuminance_green")
                   ->ReadDoubleAttribute("calibscale")
                   .has_value());

  EXPECT_FALSE(mock_device_->GetChannel("illuminance_blue")
                   ->ReadDoubleAttribute("calibscale")
                   .has_value());
}

TEST_F(AlsTest, VpdCalSlopeColorIncomplete) {
  SetColorLightSensor();
  ConfigureVpd({{"als_cal_slope_color", "1.1"}});

  EXPECT_TRUE(GetConfiguration()->Configure());

  EXPECT_FALSE(mock_device_->GetChannel("illuminance_red")
                   ->ReadDoubleAttribute("calibscale")
                   .has_value());

  EXPECT_FALSE(mock_device_->GetChannel("illuminance_green")
                   ->ReadDoubleAttribute("calibscale")
                   .has_value());

  EXPECT_FALSE(mock_device_->GetChannel("illuminance_blue")
                   ->ReadDoubleAttribute("calibscale")
                   .has_value());
}

}  // namespace

}  // namespace mems_setup
