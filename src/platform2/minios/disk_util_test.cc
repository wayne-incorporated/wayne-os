// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <gtest/gtest.h>

#include "minios/disk_util.h"

namespace minios {

class DiskUtilTest : public ::testing::Test {
 public:
  void SetUp() override {
    ASSERT_TRUE(tmp_device_.CreateUniqueTempDir());
    disk_util_.SetDevicePathForTest(tmp_device_.GetPath());
    ASSERT_TRUE(tmp_storage_.CreateUniqueTempDir());
    disk_util_.SetStoragePathForTest(tmp_storage_.GetPath());
  }

 protected:
  base::ScopedTempDir tmp_device_;
  base::ScopedTempDir tmp_storage_;
  DiskUtil disk_util_;
};

TEST_F(DiskUtilTest, GetFixedDriveEmptyStorage) {
  EXPECT_TRUE(disk_util_.GetFixedDrive().empty());
}

TEST_F(DiskUtilTest, GetFixedDriveOnlyLoopbackAndDmVerityDevices) {
  ASSERT_TRUE(base::CreateDirectory(tmp_storage_.GetPath().Append("loop0")));
  ASSERT_TRUE(base::CreateDirectory(tmp_storage_.GetPath().Append("dm-0")));
  EXPECT_TRUE(disk_util_.GetFixedDrive().empty());
}

TEST_F(DiskUtilTest, GetFixedDriveOnlyRemovableDevice) {
  const auto path = tmp_storage_.GetPath().Append("sda0");
  ASSERT_TRUE(base::CreateDirectory(path));
  ASSERT_TRUE(base::WriteFile(path.Append("removable"), "1"));
  EXPECT_TRUE(disk_util_.GetFixedDrive().empty());
}

TEST_F(DiskUtilTest, GetFixedDriveSuccess) {
  const auto device_name = base::FilePath("sda0");
  const auto device_path = tmp_device_.GetPath().Append(device_name);
  const auto device_storage_path = tmp_storage_.GetPath().Append(device_name);
  ASSERT_TRUE(base::CreateDirectory(device_path));
  ASSERT_TRUE(base::CreateDirectory(device_storage_path));
  ASSERT_TRUE(base::WriteFile(device_storage_path.Append("removable"), "0"));
  EXPECT_EQ(disk_util_.GetFixedDrive(), device_path);
}

TEST_F(DiskUtilTest, GetStatefulPartition) {
  base::ScopedTempDir tmp_dir;
  // Treat this as the device drive.
  ASSERT_TRUE(tmp_dir.CreateUniqueTempDir());
  const base::FilePath drive = tmp_dir.GetPath();

  // No stateful partitions path created yet.
  EXPECT_TRUE(disk_util_.GetStatefulPartition(drive).empty());

  // Create a fake stateful partition (e.g. /dev/sda1).
  const auto drive_partition_1 = base::FilePath(drive.value() + "1");
  ASSERT_TRUE(base::CreateDirectory(drive_partition_1));
  EXPECT_FALSE(disk_util_.GetStatefulPartition(drive).empty());
  ASSERT_TRUE(base::DeleteFile(drive_partition_1));

  // Create a fake stateful partition (e.g. /dev/nvme0n1p1).
  const auto drive_partition_p1 = base::FilePath(drive.value() + "p1");
  ASSERT_TRUE(base::CreateDirectory(drive_partition_p1));
  EXPECT_FALSE(disk_util_.GetStatefulPartition(drive).empty());
  ASSERT_TRUE(base::DeleteFile(drive_partition_p1));
}

}  // namespace minios
