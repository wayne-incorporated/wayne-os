// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <base/files/file_util.h>

#include <gtest/gtest.h>

#include <libmems/common_types.h>
#include <libmems/iio_context.h>
#include <libmems/iio_device.h>
#include <libmems/iio_device_impl.h>
#include <libmems/test_fakes.h>
#include "mems_setup/configuration.h"
#include "mems_setup/delegate.h"
#include "mems_setup/sensor_location.h"
#include "mems_setup/test_fakes.h"
#include "mems_setup/test_helper.h"

using libmems::fakes::FakeIioChannel;
using libmems::fakes::FakeIioDevice;
using mems_setup::testing::SensorTestBase;

namespace mems_setup {

namespace {

static gid_t kChronosGroupId = 666;
static gid_t kIioserviceGroupId = 777;
static gid_t kPowerGroupId = 999;

constexpr int kDeviceId = 1;
constexpr char kTriggerString[] = "trigger";
constexpr char kHwfifoTimeoutString[] = "buffer/hwfifo_timeout";
constexpr char kFlushString[] = "flush";

class AccelerometerTest : public SensorTestBase, public ::testing::Test {
 public:
  AccelerometerTest() : SensorTestBase("cros-ec-accel", kDeviceId) {
    mock_delegate_->AddGroup("chronos", kChronosGroupId);
    mock_delegate_->AddGroup(GetConfiguration()->GetGroupNameForSysfs(),
                             kIioserviceGroupId);

    std::string dev_name = libmems::IioDeviceImpl::GetStringFromId(kDeviceId);
    // /sys/bus/iio/devices/iio:device1
    base::FilePath sys_dev_path = mock_device_->GetPath();

    // Create the file to set the trigger in |AddSysfsTrigger|.
    mock_delegate_->CreateFile(sys_dev_path.Append(kTriggerString));

    // Create the files to set permissions and ownership for test.
    mock_delegate_->CreateFile(sys_dev_path.Append(kHwfifoTimeoutString));
    mock_delegate_->CreateFile(sys_dev_path.Append(kFlushString));
  }

  void CheckPermissionsAndOwnershipForFile(const base::FilePath& path,
                                           int permission) {
    uid_t user;
    gid_t group;

    EXPECT_TRUE(mock_delegate_->GetOwnership(path, &user, &group));
    EXPECT_EQ(group, kIioserviceGroupId);
    EXPECT_EQ(permission, mock_delegate_->GetPermissions(path));
  }
};

TEST_F(AccelerometerTest, CheckPermissionsAndOwnership) {
  SetSingleSensor(kBaseSensorLocation);
  ConfigureVpd({{"in_accel_x_base_calibbias", "100"}});

  EXPECT_TRUE(GetConfiguration()->Configure());

  std::string dev_name = libmems::IioDeviceImpl::GetStringFromId(kDeviceId);

  // /sys/bus/iio/devices/iio:device1
  base::FilePath sys_dev_path = mock_device_->GetPath();

  CheckPermissionsAndOwnershipForFile(sys_dev_path.Append(kHwfifoTimeoutString),
                                      base::FILE_PERMISSION_WRITE_BY_GROUP |
                                          base::FILE_PERMISSION_READ_BY_GROUP);
  CheckPermissionsAndOwnershipForFile(sys_dev_path.Append(kFlushString),
                                      base::FILE_PERMISSION_WRITE_BY_GROUP |
                                          base::FILE_PERMISSION_READ_BY_GROUP);

  // /dev/iio:deviceX
  base::FilePath dev_path =
      base::FilePath(libmems::kDevString).Append(dev_name.c_str());

  CheckPermissionsAndOwnershipForFile(dev_path,
                                      base::FILE_PERMISSION_WRITE_BY_GROUP |
                                          base::FILE_PERMISSION_READ_BY_GROUP);
}

TEST_F(AccelerometerTest, FrequencyReset) {
  SetSingleSensor(kBaseSensorLocation);
  ConfigureVpd({{"in_accel_x_base_calibbias", "100"}});

  EXPECT_TRUE(GetConfiguration()->Configure());

  auto frequency_opt =
      mock_device_->ReadDoubleAttribute(libmems::kSamplingFrequencyAttr);
  EXPECT_TRUE(frequency_opt.has_value());
  EXPECT_EQ(frequency_opt.value(), 0.0);
}

TEST_F(AccelerometerTest, CheckClock) {
  SetSingleSensor(kBaseSensorLocation);
  ConfigureVpd({{"in_accel_x_base_calibbias", "100"}});

  EXPECT_TRUE(GetConfiguration()->Configure());
  auto attr_opt = mock_device_->ReadStringAttribute("current_timestamp_clock");
  EXPECT_TRUE(attr_opt.has_value());
  EXPECT_EQ(attr_opt.value(), "boottime");
}

TEST_F(AccelerometerTest, MissingVpd) {
  SetSingleSensor(kBaseSensorLocation);
  ConfigureVpd({{"in_accel_x_base_calibbias", "100"}});

  EXPECT_TRUE(GetConfiguration()->Configure());

  EXPECT_TRUE(mock_device_->GetChannel("accel_x")
                  ->ReadNumberAttribute("calibbias")
                  .has_value());
  EXPECT_EQ(100, mock_device_->GetChannel("accel_x")
                     ->ReadNumberAttribute("calibbias")
                     .value());
  EXPECT_FALSE(mock_device_->GetChannel("accel_y")
                   ->ReadNumberAttribute("calibbias")
                   .has_value());
  EXPECT_FALSE(mock_device_->GetChannel("accel_z")
                   ->ReadNumberAttribute("calibbias")
                   .has_value());
}

TEST_F(AccelerometerTest, NotNumericVpd) {
  SetSingleSensor(kBaseSensorLocation);
  ConfigureVpd({{"in_accel_x_base_calibbias", "blah"},
                {"in_accel_y_base_calibbias", "104"}});

  EXPECT_TRUE(GetConfiguration()->Configure());

  EXPECT_FALSE(mock_device_->GetChannel("accel_x")
                   ->ReadNumberAttribute("calibbias")
                   .has_value());
  EXPECT_TRUE(mock_device_->GetChannel("accel_y")
                  ->ReadNumberAttribute("calibbias")
                  .has_value());
  EXPECT_EQ(104, mock_device_->GetChannel("accel_y")
                     ->ReadNumberAttribute("calibbias")
                     .value());
  EXPECT_FALSE(mock_device_->GetChannel("accel_z")
                   ->ReadNumberAttribute("calibbias")
                   .has_value());
}

TEST_F(AccelerometerTest, VpdOutOfRange) {
  SetSingleSensor(kBaseSensorLocation);
  ConfigureVpd({{"in_accel_x_base_calibbias", "400"},  // Above .250g
                {"in_accel_y_base_calibbias", "104"},
                {"in_accel_z_base_calibbias", "85"}});

  EXPECT_TRUE(GetConfiguration()->Configure());

  EXPECT_FALSE(mock_device_->GetChannel("accel_x")
                   ->ReadNumberAttribute("calibbias")
                   .has_value());
  EXPECT_FALSE(mock_device_->GetChannel("accel_y")
                   ->ReadNumberAttribute("calibbias")
                   .has_value());
  EXPECT_FALSE(mock_device_->GetChannel("accel_z")
                   ->ReadNumberAttribute("calibbias")
                   .has_value());
}

TEST_F(AccelerometerTest, CalibscaleData) {
  SetSingleSensor(kBaseSensorLocation);
  ConfigureVpd({{"in_accel_x_base_calibscale", "5"},
                {"in_accel_y_base_calibscale", "6"},
                {"in_accel_z_base_calibscale", "7"}});

  EXPECT_TRUE(GetConfiguration()->Configure());

  EXPECT_TRUE(mock_device_->GetChannel("accel_x")
                  ->ReadNumberAttribute("calibscale")
                  .has_value());
  EXPECT_TRUE(mock_device_->GetChannel("accel_y")
                  ->ReadNumberAttribute("calibscale")
                  .has_value());
  EXPECT_TRUE(mock_device_->GetChannel("accel_z")
                  ->ReadNumberAttribute("calibscale")
                  .has_value());

  EXPECT_EQ(5, mock_device_->GetChannel("accel_x")
                   ->ReadNumberAttribute("calibscale")
                   .value());
  EXPECT_EQ(6, mock_device_->GetChannel("accel_y")
                   ->ReadNumberAttribute("calibscale")
                   .value());
  EXPECT_EQ(7, mock_device_->GetChannel("accel_z")
                   ->ReadNumberAttribute("calibscale")
                   .value());
}

TEST_F(AccelerometerTest, CalibscaleZeroData) {
  SetSingleSensor(kBaseSensorLocation);
  ConfigureVpd({{"in_accel_x_base_calibscale", "5"},
                {"in_accel_y_base_calibscale", "6"},
                {"in_accel_z_base_calibscale", "0"}});

  EXPECT_TRUE(GetConfiguration()->Configure());

  EXPECT_TRUE(mock_device_->GetChannel("accel_x")
                  ->ReadNumberAttribute("calibscale")
                  .has_value());
  EXPECT_TRUE(mock_device_->GetChannel("accel_y")
                  ->ReadNumberAttribute("calibscale")
                  .has_value());
  EXPECT_TRUE(mock_device_->GetChannel("accel_z")
                  ->ReadNumberAttribute("calibscale")
                  .has_value());

  EXPECT_EQ(5, mock_device_->GetChannel("accel_x")
                   ->ReadNumberAttribute("calibscale")
                   .value());
  EXPECT_EQ(6, mock_device_->GetChannel("accel_y")
                   ->ReadNumberAttribute("calibscale")
                   .value());
  EXPECT_EQ(0, mock_device_->GetChannel("accel_z")
                   ->ReadNumberAttribute("calibscale")
                   .value());
}

TEST_F(AccelerometerTest, NotLoadingTriggerModule) {
  SetSingleSensor(kBaseSensorLocation);
  ConfigureVpd({{"in_accel_x_base_calibbias", "50"},
                {"in_accel_y_base_calibbias", "104"},
                {"in_accel_z_base_calibbias", "85"}});

  EXPECT_TRUE(GetConfiguration()->Configure());

  EXPECT_EQ(0, mock_delegate_->GetNumModulesProbed());
}

TEST_F(AccelerometerTest, MultipleSensorDevice) {
  SetSharedSensor();
  ConfigureVpd({{"in_accel_x_base_calibbias", "50"},
                {"in_accel_y_base_calibbias", "104"},
                {"in_accel_z_base_calibbias", "85"},
                {"in_accel_y_lid_calibbias", "27"}});

  EXPECT_TRUE(GetConfiguration()->Configure());

  EXPECT_TRUE(mock_device_->GetChannel("accel_x_base")
                  ->ReadNumberAttribute("calibbias")
                  .has_value());
  EXPECT_TRUE(mock_device_->GetChannel("accel_y_base")
                  ->ReadNumberAttribute("calibbias")
                  .has_value());
  EXPECT_TRUE(mock_device_->GetChannel("accel_z_base")
                  ->ReadNumberAttribute("calibbias")
                  .has_value());

  EXPECT_EQ(50, mock_device_->GetChannel("accel_x_base")
                    ->ReadNumberAttribute("calibbias")
                    .value());
  EXPECT_EQ(104, mock_device_->GetChannel("accel_y_base")
                     ->ReadNumberAttribute("calibbias")
                     .value());
  EXPECT_EQ(85, mock_device_->GetChannel("accel_z_base")
                    ->ReadNumberAttribute("calibbias")
                    .value());

  EXPECT_FALSE(mock_device_->GetChannel("accel_x_lid")
                   ->ReadNumberAttribute("calibbias")
                   .has_value());
  EXPECT_TRUE(mock_device_->GetChannel("accel_y_lid")
                  ->ReadNumberAttribute("calibbias")
                  .has_value());
  EXPECT_EQ(27, mock_device_->GetChannel("accel_y_lid")
                    ->ReadNumberAttribute("calibbias")
                    .value());
  EXPECT_FALSE(mock_device_->GetChannel("accel_z_lid")
                   ->ReadNumberAttribute("calibbias")
                   .has_value());
}

TEST_F(AccelerometerTest, TriggerPermissions) {
  SetSingleSensor(kLidSensorLocation);
  EXPECT_TRUE(GetConfiguration()->Configure());

  base::FilePath trigger_now = mock_trigger1_->GetPath().Append("trigger_now");
  EXPECT_NE(0, mock_delegate_->GetPermissions(trigger_now) &
                   base::FILE_PERMISSION_WRITE_BY_GROUP);
  gid_t gid = 0;
  mock_delegate_->GetOwnership(trigger_now, nullptr, &gid);
  EXPECT_EQ(kChronosGroupId, gid);
}

TEST_F(AccelerometerTest, SingleSensorKbWakeAnglePermissions) {
  base::FilePath kb_path("/sys/class/chromeos/cros_ec/kb_wake_angle");

  SetSingleSensor(kLidSensorLocation);
  mock_delegate_->CreateFile(kb_path);
  mock_delegate_->AddGroup("power", kPowerGroupId);
  EXPECT_TRUE(GetConfiguration()->Configure());

  EXPECT_NE(0, mock_delegate_->GetPermissions(kb_path) &
                   base::FILE_PERMISSION_WRITE_BY_GROUP);
  gid_t gid = 0;
  mock_delegate_->GetOwnership(kb_path, nullptr, &gid);
  EXPECT_EQ(kPowerGroupId, gid);
}

TEST_F(AccelerometerTest, OkWithSysfstrigDefined) {
  SetSingleSensor(kLidSensorLocation);

  mock_sysfs_trigger_->AddMockTrigger();

  EXPECT_TRUE(GetConfiguration()->Configure());
}

TEST_F(AccelerometerTest, SetSingleAccelRangeNoGyroLid) {
  SetSingleSensor(kLidSensorLocation);
  EXPECT_TRUE(GetConfiguration()->Configure());
  EXPECT_EQ(4, mock_device_->ReadNumberAttribute("scale").value());
}

TEST_F(AccelerometerTest, SetSingleAccelRangeNoGyroBase) {
  SetSingleSensor(kLidSensorLocation);
  EXPECT_TRUE(GetConfiguration()->Configure());
  EXPECT_EQ(4, mock_device_->ReadNumberAttribute("scale").value());
}

TEST_F(AccelerometerTest, SetPairAccelRangeNoGyroBase) {
  SetSingleSensor(kBaseSensorLocation);
  auto mock_lid_accel =
      std::make_unique<FakeIioDevice>(mock_context_.get(), "cros-ec-accel", 2);
  mock_lid_accel->WriteStringAttribute("location", kLidSensorLocation);
  mock_context_->AddDevice(std::move(mock_lid_accel));

  EXPECT_TRUE(GetConfiguration()->Configure());
  EXPECT_EQ(2, mock_device_->ReadNumberAttribute("scale").value());
}

TEST_F(AccelerometerTest, SetPairAccelRangeNoGyroLid) {
  SetSingleSensor(kLidSensorLocation);
  auto mock_base_accel =
      std::make_unique<FakeIioDevice>(mock_context_.get(), "cros-ec-accel", 2);
  mock_base_accel->WriteStringAttribute("location", kBaseSensorLocation);
  mock_context_->AddDevice(std::move(mock_base_accel));

  EXPECT_TRUE(GetConfiguration()->Configure());
  EXPECT_EQ(4, mock_device_->ReadNumberAttribute("scale").value());
}

TEST_F(AccelerometerTest, SetRangeNoGyroLidOld) {
  SetSharedSensor();
  SetSingleSensor(kBaseSensorLocation);
  EXPECT_TRUE(GetConfiguration()->Configure());
  EXPECT_EQ(4, mock_device_->ReadNumberAttribute("scale").value());
}

TEST_F(AccelerometerTest, SetRangeGyroBaseBase) {
  auto mock_gyro =
      std::make_unique<FakeIioDevice>(mock_context_.get(), "cros-ec-gyro", 2);
  mock_gyro->WriteStringAttribute("location", kBaseSensorLocation);
  mock_context_->AddDevice(std::move(mock_gyro));

  SetSingleSensor(kBaseSensorLocation);
  EXPECT_TRUE(GetConfiguration()->Configure());
  EXPECT_EQ(4, mock_device_->ReadNumberAttribute("scale").value());
}

TEST_F(AccelerometerTest, SetRangeGyroBaseLid) {
  auto mock_gyro =
      std::make_unique<FakeIioDevice>(mock_context_.get(), "cros-ec-gyro", 2);
  mock_gyro->WriteStringAttribute("location", kBaseSensorLocation);
  mock_context_->AddDevice(std::move(mock_gyro));

  SetSingleSensor(kLidSensorLocation);
  EXPECT_TRUE(GetConfiguration()->Configure());
  EXPECT_EQ(2, mock_device_->ReadNumberAttribute("scale").value());
}

TEST_F(AccelerometerTest, SetRangeMultipleGyroLid) {
  auto mock_gyro1 =
      std::make_unique<FakeIioDevice>(mock_context_.get(), "cros-ec-gyro", 2);
  mock_gyro1->WriteStringAttribute("location", kBaseSensorLocation);
  mock_context_->AddDevice(std::move(mock_gyro1));

  auto mock_gyro2 =
      std::make_unique<FakeIioDevice>(mock_context_.get(), "cros-ec-gyro", 3);
  mock_gyro2->WriteStringAttribute("location", kLidSensorLocation);
  mock_context_->AddDevice(std::move(mock_gyro2));

  SetSingleSensor(kLidSensorLocation);
  EXPECT_TRUE(GetConfiguration()->Configure());
  EXPECT_EQ(4, mock_device_->ReadNumberAttribute("scale").value());
}
TEST_F(AccelerometerTest, SetRangeMultipleGyroBase) {
  auto mock_gyro1 =
      std::make_unique<FakeIioDevice>(mock_context_.get(), "cros-ec-gyro", 2);
  mock_gyro1->WriteStringAttribute("location", kBaseSensorLocation);
  mock_context_->AddDevice(std::move(mock_gyro1));

  auto mock_gyro2 =
      std::make_unique<FakeIioDevice>(mock_context_.get(), "cros-ec-gyro", 3);
  mock_gyro2->WriteStringAttribute("location", kLidSensorLocation);
  mock_context_->AddDevice(std::move(mock_gyro2));

  SetSingleSensor(kBaseSensorLocation);
  EXPECT_TRUE(GetConfiguration()->Configure());
  EXPECT_EQ(4, mock_device_->ReadNumberAttribute("scale").value());
}

TEST_F(AccelerometerTest, SetRangeSingleAccelBase) {
  SetSingleSensor(kBaseSensorLocation);
  EXPECT_TRUE(GetConfiguration()->Configure());
  EXPECT_EQ(4, mock_device_->ReadNumberAttribute("scale").value());
}

}  // namespace

}  // namespace mems_setup
