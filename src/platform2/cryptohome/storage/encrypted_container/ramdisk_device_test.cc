// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/storage/encrypted_container/ramdisk_device.h"

#include <memory>

#include <brillo/blkdev_utils/loop_device_fake.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "cryptohome/mock_platform.h"
#include "cryptohome/storage/encrypted_container/backing_device.h"
#include "cryptohome/storage/mount_constants.h"

namespace cryptohome {

using ::testing::_;
using ::testing::DoAll;
using ::testing::NiceMock;
using ::testing::Return;
using ::testing::SetArgPointee;

namespace {
constexpr char kBackingFile[] = "file";
constexpr int kEphemeralVFSFragmentSize = 1 << 10;
constexpr int kEphemeralVFSSize = 1 << 12;
}  // namespace

class RamdiskDeviceTest : public ::testing::Test {
 public:
  RamdiskDeviceTest() { SetupVFSMock(); }

 protected:
  void SetupVFSMock() {
    ephemeral_statvfs_ = {0};
    ephemeral_statvfs_.f_frsize = kEphemeralVFSFragmentSize;
    ephemeral_statvfs_.f_blocks = kEphemeralVFSSize / kEphemeralVFSFragmentSize;

    ON_CALL(platform_, StatVFS(base::FilePath(kEphemeralCryptohomeDir), _))
        .WillByDefault(
            DoAll(SetArgPointee<1>(ephemeral_statvfs_), Return(true)));
  }

  NiceMock<MockPlatform> platform_;
  struct statvfs ephemeral_statvfs_;
};

namespace {

TEST_F(RamdiskDeviceTest, Create_Success) {
  const base::FilePath ephemeral_root(kEphemeralCryptohomeDir);
  const base::FilePath ephemeral_sparse_file =
      ephemeral_root.Append(kSparseFileDir).Append(kBackingFile);

  ASSERT_TRUE(platform_.CreateDirectory(ephemeral_root));
  auto ramdisk = RamdiskDevice::Generate(kBackingFile, &platform_);

  ASSERT_TRUE(ramdisk->Create());
  ASSERT_TRUE(platform_.FileExists(ephemeral_sparse_file));
  ASSERT_TRUE(ramdisk->Setup());
  ASSERT_TRUE(ramdisk->Teardown());
  ASSERT_FALSE(platform_.FileExists(ephemeral_sparse_file));
  ASSERT_TRUE(ramdisk->Purge());
  ASSERT_FALSE(platform_.FileExists(ephemeral_sparse_file));
}

TEST_F(RamdiskDeviceTest, Create_FailVFS) {
  EXPECT_CALL(platform_, StatVFS(base::FilePath(kEphemeralCryptohomeDir), _))
      .WillOnce(Return(false));
  EXPECT_FALSE(RamdiskDevice::Generate(kBackingFile, &platform_));
}

TEST_F(RamdiskDeviceTest, Create_FailDirCreation) {
  const base::FilePath ephemeral_root(kEphemeralCryptohomeDir);
  const base::FilePath ephemeral_sparse_file =
      ephemeral_root.Append(kSparseFileDir).Append(kBackingFile);

  ASSERT_TRUE(platform_.CreateDirectory(ephemeral_root));
  auto ramdisk = RamdiskDevice::Generate(kBackingFile, &platform_);

  EXPECT_CALL(platform_, CreateDirectory(_)).WillOnce(Return(false));
  ASSERT_FALSE(ramdisk->Create());
  ASSERT_FALSE(platform_.FileExists(ephemeral_sparse_file));
}

}  // namespace

}  // namespace cryptohome
