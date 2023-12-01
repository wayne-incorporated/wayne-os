// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cros-disks/disk_monitor.h"

#include <base/files/file_path.h>
#include <base/logging.h>
#include <base/stl_util.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "cros-disks/device_ejector.h"

namespace cros_disks {

class DiskMonitorTest : public ::testing::Test {
 public:
  DiskMonitorTest() = default;

 protected:
  DiskMonitor monitor_;
};

TEST_F(DiskMonitorTest, EnumerateDisks) {
  std::vector<Disk> disks = monitor_.EnumerateDisks();
}

// TODO(crbug.com/1002570): Disabled due to flakiness. This test relies on the
// disk enumeration being stable for the life of the tests. However, if another
// process on the system is modifying disks (i.e. adding/removing loopback
// devices), this test might fail because a device found by EnumerateDisks() may
// no longer exist when GetDiskByDevicePath() is called.
TEST_F(DiskMonitorTest, DISABLED_GetDiskByDevicePath) {
  std::vector<Disk> disks = monitor_.EnumerateDisks();
  if (disks.empty()) {
    LOG(WARNING) << "No disks found to test.";
  }

  for (const auto& found_disk : disks) {
    std::string device_path = found_disk.device_file;
    LOG(INFO) << "Using device_path: " << device_path << "\n";

    Disk disk;
    EXPECT_TRUE(
        monitor_.GetDiskByDevicePath(base::FilePath(device_path), &disk));
    EXPECT_EQ(device_path, disk.device_file);
  }
}

TEST_F(DiskMonitorTest, GetDiskByNonexistentDevicePath) {
  Disk disk;
  base::FilePath device_path("/dev/nonexistent-path");
  EXPECT_FALSE(monitor_.GetDiskByDevicePath(device_path, &disk));
}

}  // namespace cros_disks
