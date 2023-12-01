// Copyright 2021 The ChromiumOS Authors
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

namespace mems_setup {

namespace {

using mems_setup::testing::SensorTestBase;

static gid_t kIioserviceGroupId = 777;

constexpr int kDeviceId = 1;
constexpr char kAccelSamplingFrequency[] = "in_accel_sampling_frequency";
constexpr char kInvalidSamplingFrequency[] = "accel_sampling_frequency";

constexpr char kScanElementsString[] = "scan_elements";

constexpr char kFakeChannel[] = "in_accel_a_en";
constexpr char kInvalidChannel[] = "in_accel_a_enn";

class HidAccelerometerTest : public SensorTestBase, public ::testing::Test {
 public:
  HidAccelerometerTest() : SensorTestBase("accel_3d", kDeviceId) {
    mock_delegate_->AddGroup(GetConfiguration()->GetGroupNameForSysfs(),
                             kIioserviceGroupId);
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

TEST_F(HidAccelerometerTest, CheckPermissionsAndOwnership) {
  // /sys/bus/iio/devices/iio:device1
  base::FilePath sys_dev_path = mock_device_->GetPath();

  // Create the files to set permissions and ownership for test.
  mock_delegate_->CreateFile(sys_dev_path.Append(kAccelSamplingFrequency));
  mock_delegate_->CreateFile(sys_dev_path.Append(kInvalidSamplingFrequency));
  mock_delegate_->CreateFile(
      sys_dev_path.Append(kScanElementsString).Append(kFakeChannel));
  mock_delegate_->CreateFile(
      sys_dev_path.Append(kScanElementsString).Append(kInvalidChannel));

  EXPECT_TRUE(GetConfiguration()->Configure());

  std::string dev_name = libmems::IioDeviceImpl::GetStringFromId(kDeviceId);

  CheckPermissionsAndOwnershipForFile(
      sys_dev_path.Append(kAccelSamplingFrequency),
      base::FILE_PERMISSION_WRITE_BY_GROUP |
          base::FILE_PERMISSION_READ_BY_GROUP);

  // The file name doesn't match the regex to be set the write permission.
  CheckPermissionsAndOwnershipForFile(
      sys_dev_path.Append(kInvalidSamplingFrequency),
      base::FILE_PERMISSION_READ_BY_GROUP);

  CheckPermissionsAndOwnershipForFile(
      sys_dev_path.Append(kScanElementsString).Append(kFakeChannel),
      base::FILE_PERMISSION_WRITE_BY_GROUP |
          base::FILE_PERMISSION_READ_BY_GROUP);

  // The file name doesn't match the regex to be set the write permission.
  CheckPermissionsAndOwnershipForFile(
      sys_dev_path.Append(kScanElementsString).Append(kInvalidChannel),
      base::FILE_PERMISSION_READ_BY_GROUP);

  // /dev/iio:deviceX
  base::FilePath dev_path =
      base::FilePath(libmems::kDevString).Append(dev_name.c_str());

  CheckPermissionsAndOwnershipForFile(dev_path,
                                      base::FILE_PERMISSION_WRITE_BY_GROUP |
                                          base::FILE_PERMISSION_READ_BY_GROUP);
}

}  // namespace

}  // namespace mems_setup
