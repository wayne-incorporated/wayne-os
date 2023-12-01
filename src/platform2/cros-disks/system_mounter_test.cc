// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cros-disks/system_mounter.h"

#include <sys/mount.h>

#include <base/files/scoped_temp_dir.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "cros-disks/mock_platform.h"
#include "cros-disks/mount_options.h"
#include "cros-disks/mount_point.h"
#include "cros-disks/platform.h"

namespace cros_disks {
namespace {

using testing::_;
using testing::Return;

constexpr uint64_t kDefaultMountFlags =
    MS_NODEV | MS_NOEXEC | MS_NOSUID | MS_DIRSYNC | MS_NOSYMFOLLOW;

class PlatformForTest : public Platform {
 public:
  // Tests are being run on devices that don't support nosymfollow. Strip it.
  MountError Mount(const std::string& source,
                   const std::string& target,
                   const std::string& filesystem_type,
                   uint64_t flags,
                   const std::string& options) const override {
    EXPECT_TRUE((flags & MS_NOSYMFOLLOW) == MS_NOSYMFOLLOW);
    return Platform::Mount(source, target, filesystem_type,
                           flags & ~MS_NOSYMFOLLOW, options);
  }
};
}  // namespace

TEST(SystemMounterTest, RunAsRootMount) {
  PlatformForTest platform;
  SystemMounter mounter(&platform, "tmpfs", /* read_only= */ false, {});

  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());

  MountError error = MountError::kSuccess;
  auto mountpoint = mounter.Mount("/dev/null", temp_dir.GetPath(), {}, &error);
  EXPECT_TRUE(mountpoint);
  EXPECT_EQ(MountError::kSuccess, error);
  error = mountpoint->Unmount();
  EXPECT_EQ(MountError::kSuccess, error);
}

TEST(SystemMounterTest, RunAsRootMountWithNonexistentSourcePath) {
  PlatformForTest platform;
  SystemMounter mounter(&platform, "ext2", /* read_only= */ false, {});

  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());

  // To test mounting a nonexistent source path, use ext2 as the
  // filesystem type instead of tmpfs since tmpfs does not care
  // about source path.
  MountError error = MountError::kSuccess;
  auto mountpoint =
      mounter.Mount("/nonexistent", temp_dir.GetPath(), {}, &error);
  EXPECT_FALSE(mountpoint);
  EXPECT_EQ(MountError::kInvalidPath, error);
}

TEST(SystemMounterTest, RunAsRootMountWithNonexistentTargetPath) {
  PlatformForTest platform;
  SystemMounter mounter(&platform, "tmpfs", /* read_only= */ false, {});

  MountError error = MountError::kSuccess;
  auto mountpoint =
      mounter.Mount("/dev/null", base::FilePath("/nonexistent"), {}, &error);
  EXPECT_FALSE(mountpoint);
  EXPECT_EQ(MountError::kInvalidPath, error);
}

TEST(SystemMounterTest, RunAsRootMountWithNonexistentFilesystemType) {
  PlatformForTest platform;
  SystemMounter mounter(&platform, "nonexistentfs", /* read_only= */ false, {});

  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());
  MountError error = MountError::kSuccess;
  auto mountpoint = mounter.Mount("/dev/null", temp_dir.GetPath(), {}, &error);
  EXPECT_FALSE(mountpoint);
  EXPECT_EQ(MountError::kUnsupportedFilesystem, error);
}

TEST(SystemMounterTest, MountFilesystem) {
  MockPlatform platform;
  SystemMounter mounter(&platform, "fstype", /* read_only= */ false, {});

  EXPECT_CALL(platform, Mount("/dev/block", "/mnt/dir", "fstype", _, _))
      .WillOnce(Return(MountError::kSuccess));
  MountError error = MountError::kUnknownError;
  auto mountpoint =
      mounter.Mount("/dev/block", base::FilePath("/mnt/dir"), {}, &error);
  ASSERT_TRUE(mountpoint);
  EXPECT_EQ(MountError::kSuccess, error);

  EXPECT_CALL(platform, Unmount(base::FilePath("/mnt/dir"), "fstype"))
      .WillOnce(Return(MountError::kSuccess));
  mountpoint.reset();
}

TEST(SystemMounterTest, MountFailed) {
  MockPlatform platform;
  SystemMounter mounter(&platform, "fstype", /* read_only= */ false, {});

  EXPECT_CALL(platform, Mount("/dev/block", "/mnt/dir", "fstype", _, _))
      .WillOnce(Return(MountError::kPathNotMounted));
  EXPECT_CALL(platform, Unmount).Times(0);

  MountError error = MountError::kUnknownError;
  auto mountpoint =
      mounter.Mount("/dev/block", base::FilePath("/mnt/dir"), {}, &error);
  ASSERT_FALSE(mountpoint);
  EXPECT_EQ(MountError::kPathNotMounted, error);
}

TEST(SystemMounterTest, UnmountFailedNoRetry) {
  MockPlatform platform;
  SystemMounter mounter(&platform, "fstype", /* read_only= */ false, {});

  EXPECT_CALL(platform, Mount(_, "/mnt/dir", "fstype", _, _))
      .WillOnce(Return(MountError::kSuccess));
  MountError error = MountError::kUnknownError;
  auto mountpoint =
      mounter.Mount("/dev/block", base::FilePath("/mnt/dir"), {}, &error);

  EXPECT_CALL(platform, Unmount(base::FilePath("/mnt/dir"), "fstype"))
      .WillOnce(Return(MountError::kInvalidArgument))
      .WillOnce(Return(MountError::kSuccess));
  EXPECT_EQ(MountError::kInvalidArgument, mountpoint->Unmount());
  mountpoint.reset();
}

TEST(SystemMounterTest, MountFlags) {
  MockPlatform platform;
  SystemMounter mounter(&platform, "fstype", /* read_only= */ false, {});

  EXPECT_CALL(platform, Mount(_, "/mnt/dir", "fstype", kDefaultMountFlags, _))
      .WillOnce(Return(MountError::kSuccess));
  MountError error = MountError::kUnknownError;
  auto mountpoint =
      mounter.Mount("/dev/block", base::FilePath("/mnt/dir"), {}, &error);
}

TEST(SystemMounterTest, ReadOnlyForced) {
  MockPlatform platform;
  SystemMounter mounter(&platform, "fstype", /* read_only= */ true, {});

  EXPECT_CALL(platform,
              Mount(_, "/mnt/dir", "fstype", kDefaultMountFlags | MS_RDONLY, _))
      .WillOnce(Return(MountError::kSuccess));
  MountError error = MountError::kUnknownError;
  auto mountpoint =
      mounter.Mount("/dev/block", base::FilePath("/mnt/dir"), {}, &error);
}

TEST(SystemMounterTest, ReadOnlyRequested) {
  MockPlatform platform;
  SystemMounter mounter(&platform, "fstype", /* read_only= */ false, {});

  EXPECT_CALL(platform,
              Mount(_, "/mnt/dir", "fstype", kDefaultMountFlags | MS_RDONLY, _))
      .WillOnce(Return(MountError::kSuccess));
  MountError error = MountError::kUnknownError;
  auto mountpoint =
      mounter.Mount("/dev/block", base::FilePath("/mnt/dir"), {"ro"}, &error);
}

TEST(SystemMounterTest, MountOptionsPassedButParamsIgnored) {
  MockPlatform platform;
  SystemMounter mounter(&platform, "fstype", /* read_only= */ false,
                        {"foo", "bar=baz"});

  EXPECT_CALL(platform, Mount(_, "/mnt/dir", "fstype", _, "foo,bar=baz"))
      .WillOnce(Return(MountError::kSuccess));
  MountError error = MountError::kUnknownError;
  auto mountpoint = mounter.Mount("/dev/block", base::FilePath("/mnt/dir"),
                                  {"abc=def", "xyz"}, &error);
}

}  // namespace cros_disks
