// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "rmad/executor/mount.h"

#include <fcntl.h>
#include <linux/loop.h>
#include <sys/ioctl.h>

#include <utility>

#include <base/files/file.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_file.h>
#include <base/files/scoped_temp_dir.h>
#include <base/logging.h>
#include <base/process/launch.h>
#include <base/strings/stringprintf.h>
#include <brillo/file_utils.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "rmad/udev/mock_udev_device.h"
#include "rmad/udev/mock_udev_utils.h"

using testing::_;
using testing::NiceMock;
using testing::Return;

namespace {

constexpr char kLoopControlPath[] = "/dev/loop-control";
constexpr char kVfatImagePath[] = "executor/testdata/vfat.bin";
constexpr char kDefaultMountPoint[] = "mount_point";

}  // namespace

namespace rmad {

class MountTest : public testing::Test {
 public:
  MountTest() {
    // Set up a loop device with VFAT file system.
    CreateTempDir();
    SetUpImage();
    SetUpLoopDevice();
  }
  ~MountTest() override {
    // Release the loop device.
    if (loop_fd_.is_valid()) {
      EXPECT_EQ(0, ioctl(loop_fd_.get(), LOOP_CLR_FD, 0));
    }
  }

 private:
  void CreateTempDir() { EXPECT_TRUE(temp_dir_.CreateUniqueTempDir()); }

  void SetUpImage() {
    image_path_ = base::FilePath(kVfatImagePath);
    image_fd_ = base::ScopedFD(open(image_path_.value().c_str(), O_RDONLY));
    if (!image_fd_.is_valid()) {
      FAIL() << "Failed to open " << image_path_.value();
    }
  }

  void SetUpLoopDevice() {
    constexpr int kMaxRetry = 5;
    for (int i = 0; i < kMaxRetry; ++i) {
      bool retry = false;
      if (SetUpLoopDeviceInternal(&retry)) {
        return;
      }
      if (!retry) {
        break;
      }
      DLOG(INFO) << "LoopMountInternal failed with EBUSY. Try again.";
    }
    FAIL() << "LoopMountInternal failed " << kMaxRetry << " tries";
  }

  bool SetUpLoopDeviceInternal(bool* retry) {
    *retry = false;

    // There's a race condition in resource query (LOOP_CTL_GET_FREE) and
    // resource allocation (LOOP_SET_FD) when multiple tests are running in
    // parallel. A possible solution might be using loopfs to create private
    // loop devices per test, but that's not supported in chroot yet. Hence we
    // set |retry| to true if we failed to set up the loop device with EBUSY
    // error, meaning the loop device is already taken by another process.
    base::ScopedFD loopctl_fd(open(kLoopControlPath, O_RDONLY));
    if (!loopctl_fd.is_valid()) {
      PLOG(ERROR) << "Failed to open " << kLoopControlPath;
      return false;
    }

    int dev_num = ioctl(loopctl_fd.get(), LOOP_CTL_GET_FREE);
    if (dev_num < 0) {
      PLOG(ERROR) << "Failed to allocate loop device";
      return false;
    }

    auto loop_path = base::FilePath(base::StringPrintf("/dev/loop%d", dev_num));
    auto loop_fd = base::ScopedFD(open(loop_path.value().c_str(), O_RDONLY));
    if (!loop_fd.is_valid()) {
      PLOG(ERROR) << "Failed to open " << loop_path.value();
      return false;
    }

    if (ioctl(loop_fd.get(), LOOP_SET_FD, image_fd_.get()) < 0) {
      PLOG(ERROR) << "Failed to associate " << image_path_.value() << " with "
                  << loop_path.value();
      *retry = (errno == EBUSY);
      return false;
    }

    loop_path_ = std::move(loop_path);
    loop_fd_ = std::move(loop_fd);
    return true;
  }

 protected:
  std::unique_ptr<UdevUtils> CreateMockUdevUtils(const std::string& fs_type,
                                                 bool is_removable) {
    auto udev_utils = std::make_unique<NiceMock<MockUdevUtils>>();
    ON_CALL(*udev_utils, GetBlockDeviceFromDevicePath(_, _))
        .WillByDefault([fs_type, is_removable](
                           const std::string&,
                           std::unique_ptr<UdevDevice>* dev) {
          auto mock_dev = std::make_unique<NiceMock<MockUdevDevice>>();
          ON_CALL(*mock_dev, GetFileSystemType())
              .WillByDefault(Return(fs_type));
          ON_CALL(*mock_dev, IsRemovable()).WillByDefault(Return(is_removable));
          dev->reset(mock_dev.release());
          return true;
        });
    return udev_utils;
  }

  base::ScopedTempDir temp_dir_;
  base::FilePath image_path_;
  base::ScopedFD image_fd_;
  base::FilePath loop_path_;
  base::ScopedFD loop_fd_;
};

TEST_F(MountTest, RunAsRoot_Success) {
  const base::FilePath mount_point =
      temp_dir_.GetPath().Append(kDefaultMountPoint);
  EXPECT_TRUE(base::CreateDirectory(mount_point));

  Mount mount(loop_path_, mount_point, "vfat", true,
              CreateMockUdevUtils("vfat", true));
  EXPECT_TRUE(mount.IsValid());
}

TEST_F(MountTest, RunAsRoot_NotRemovable) {
  const base::FilePath mount_point =
      temp_dir_.GetPath().Append(kDefaultMountPoint);
  EXPECT_TRUE(base::CreateDirectory(mount_point));

  Mount mount(loop_path_, mount_point, "vfat", true,
              CreateMockUdevUtils("vfat", false));
  EXPECT_FALSE(mount.IsValid());
}

TEST_F(MountTest, RunAsRoot_UnsupportedFileSystem) {
  const base::FilePath mount_point =
      temp_dir_.GetPath().Append(kDefaultMountPoint);
  EXPECT_TRUE(base::CreateDirectory(mount_point));

  Mount mount(loop_path_, mount_point, "vfat", true,
              CreateMockUdevUtils("abc", true));
  EXPECT_FALSE(mount.IsValid());
}

TEST_F(MountTest, RunAsRoot_MountPointNotDirectory) {
  const base::FilePath mount_point =
      temp_dir_.GetPath().Append(kDefaultMountPoint);
  EXPECT_TRUE(brillo::TouchFile(mount_point));

  Mount mount(loop_path_, mount_point, "vfat", true,
              CreateMockUdevUtils("vfat", true));
  EXPECT_FALSE(mount.IsValid());
}

TEST_F(MountTest, RunAsRoot_MountPointAlreadyMounted) {
  const base::FilePath mount_point =
      temp_dir_.GetPath().Append(kDefaultMountPoint);
  EXPECT_TRUE(base::CreateDirectory(mount_point));

  // First mount succeeds.
  Mount mount(loop_path_, mount_point, "vfat", true,
              CreateMockUdevUtils("vfat", true));
  EXPECT_TRUE(mount.IsValid());

  // Second mount on the same mount point fails.
  Mount mount2(loop_path_, mount_point, "vfat", true,
               CreateMockUdevUtils("vfat", true));
  EXPECT_FALSE(mount2.IsValid());
}

}  // namespace rmad
