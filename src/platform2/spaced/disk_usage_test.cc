// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <spaced/disk_usage_impl.h>

#include <sys/statvfs.h>

#include <optional>
#include <string>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <base/strings/stringprintf.h>
#include <brillo/blkdev_utils/mock_lvm.h>

using testing::_;
using testing::DoAll;
using testing::Return;
using testing::SetArgPointee;

namespace spaced {
namespace {
// ~3% of blocks are allocated.
constexpr const char kSampleReport[] =
    "0 32768 thin-pool 3 1/24 8/256 - rw discard_passdown "
    "queue_if_no_space - 1024";
}  // namespace

class DiskUsageUtilMock : public DiskUsageUtilImpl {
 public:
  DiskUsageUtilMock(struct statvfs st, std::optional<brillo::Thinpool> thinpool)
      : DiskUsageUtilImpl(base::FilePath("/dev/foo"), thinpool), st_(st) {}

 protected:
  int StatVFS(const base::FilePath& path, struct statvfs* st) override {
    memcpy(st, &st_, sizeof(struct statvfs));
    return !st_.f_fsid;
  }

 private:
  struct statvfs st_;
};

TEST(DiskUsageUtilTest, FailedVfsCall) {
  struct statvfs st = {};

  DiskUsageUtilMock disk_usage_mock(st, std::nullopt);
  base::FilePath path("/foo/bar");

  EXPECT_EQ(disk_usage_mock.GetFreeDiskSpace(path), -1);
  EXPECT_EQ(disk_usage_mock.GetTotalDiskSpace(path), -1);
}

TEST(DiskUsageUtilTest, FilesystemData) {
  struct statvfs st = {};
  st.f_fsid = 1;
  st.f_bavail = 1024;
  st.f_blocks = 2048;
  st.f_frsize = 4096;

  DiskUsageUtilMock disk_usage_mock(st, std::nullopt);
  base::FilePath path("/foo/bar");

  EXPECT_EQ(disk_usage_mock.GetFreeDiskSpace(path), 4194304);
  EXPECT_EQ(disk_usage_mock.GetTotalDiskSpace(path), 8388608);
}

TEST(DiskUsageUtilTest, ThinProvisionedVolume) {
  struct statvfs st = {};
  st.f_fsid = 1;
  st.f_bavail = 1024;
  st.f_blocks = 2048;
  st.f_frsize = 4096;

  auto lvm_command_runner = std::make_shared<brillo::MockLvmCommandRunner>();
  brillo::Thinpool thinpool("thinpool", "STATEFUL", lvm_command_runner);

  DiskUsageUtilMock disk_usage_mock(st, thinpool);
  base::FilePath path("/foo/bar");

  std::vector<std::string> cmd = {"/sbin/dmsetup", "status", "--noflush",
                                  "STATEFUL-thinpool-tpool"};

  std::string report = kSampleReport;
  EXPECT_CALL(*lvm_command_runner.get(), RunProcess(cmd, _))
      .WillRepeatedly(DoAll(SetArgPointee<1>(report), Return(true)));

  // With only 3% of the thinpool occupied, disk usage should use the
  // filesystem data for free space.
  EXPECT_EQ(disk_usage_mock.GetFreeDiskSpace(path), 4194304);
  EXPECT_EQ(disk_usage_mock.GetTotalDiskSpace(path), 8388608);
}

TEST(DiskUsageUtilTest, ThinProvisionedVolumeLowDiskSpace) {
  struct statvfs st = {};
  st.f_fsid = 1;
  st.f_bavail = 1024;
  st.f_blocks = 2048;
  st.f_frsize = 4096;

  auto lvm_command_runner = std::make_shared<brillo::MockLvmCommandRunner>();
  brillo::Thinpool thinpool("thinpool", "STATEFUL", lvm_command_runner);

  DiskUsageUtilMock disk_usage_mock(st, thinpool);
  base::FilePath path("/foo/bar");

  std::vector<std::string> cmd = {"/sbin/dmsetup", "status", "--noflush",
                                  "STATEFUL-thinpool-tpool"};

  std::string report = kSampleReport;
  EXPECT_CALL(*lvm_command_runner.get(), RunProcess(cmd, _))
      .WillRepeatedly(DoAll(SetArgPointee<1>(report), Return(true)));

  EXPECT_EQ(disk_usage_mock.GetFreeDiskSpace(path), 4194304);
  EXPECT_EQ(disk_usage_mock.GetTotalDiskSpace(path), 8388608);
}

TEST(DiskUsageUtilTest, OverprovisionedVolumeSpace) {
  struct statvfs st = {};
  st.f_fsid = 1;
  st.f_bavail = 1024;
  st.f_blocks = 9192;
  st.f_frsize = 4096;

  auto lvm_command_runner = std::make_shared<brillo::MockLvmCommandRunner>();
  brillo::Thinpool thinpool("thinpool", "STATEFUL", lvm_command_runner);

  DiskUsageUtilMock disk_usage_mock(st, thinpool);
  base::FilePath path("/foo/bar");

  std::vector<std::string> cmd = {"/sbin/dmsetup", "status", "--noflush",
                                  "STATEFUL-thinpool-tpool"};

  std::string report = kSampleReport;
  EXPECT_CALL(*lvm_command_runner.get(), RunProcess(cmd, _))
      .WillRepeatedly(DoAll(SetArgPointee<1>(report), Return(true)));

  EXPECT_EQ(disk_usage_mock.GetFreeDiskSpace(path), 4194304);
  EXPECT_EQ(disk_usage_mock.GetTotalDiskSpace(path), 16777216);
}

class DiskUsageRootdevMock : public DiskUsageUtilImpl {
 public:
  DiskUsageRootdevMock(int64_t size, const base::FilePath& path)
      : DiskUsageUtilImpl(path, std::nullopt),
        rootdev_size_(size),
        rootdev_path_(path) {}

 protected:
  int64_t GetBlockDeviceSize(const base::FilePath& device) override {
    // At the moment, only the root device size is queried from spaced.
    // Once more block devices are queried, move this into a map.
    if (device == rootdev_path_)
      return rootdev_size_;

    return -1;
  }

 private:
  int64_t rootdev_size_;
  base::FilePath rootdev_path_;
};

TEST(DiskUsageUtilTest, InvalidRootDeviceTest) {
  DiskUsageRootdevMock disk_usage_mock(0, base::FilePath("/dev/foo"));

  EXPECT_EQ(disk_usage_mock.GetRootDeviceSize(), 0);
}

TEST(DiskUsageUtilTest, RootDeviceSizeTest) {
  DiskUsageRootdevMock disk_usage_mock(500, base::FilePath("/dev/foo"));

  EXPECT_EQ(disk_usage_mock.GetRootDeviceSize(), 500);
}

}  // namespace spaced
