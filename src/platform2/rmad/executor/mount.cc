// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "rmad/executor/mount.h"

#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/vfs.h>

#include <algorithm>
#include <array>
#include <memory>
#include <utility>

#include <base/files/file_path.h>
#include <base/logging.h>

#include "rmad/udev/udev_device.h"
#include "rmad/udev/udev_utils.h"

namespace {

constexpr uint32_t kDefaultMountFlags =
    MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_NOSYMFOLLOW;

bool IsSupportedFileSystemType(const std::string& fs_type) {
  // Currently only FAT32 and ext* are supported.
  static constexpr std::array<const char*, 4> kSupportedFileSystems = {
      "vfat", "ext2", "ext3", "ext4"};

  return std::find(kSupportedFileSystems.begin(), kSupportedFileSystems.end(),
                   fs_type) != kSupportedFileSystems.end();
}

}  // namespace

namespace rmad {

Mount::Mount() : valid_(false) {}

Mount::Mount(const base::FilePath& device_path,
             const base::FilePath& mount_point,
             const std::string& fs_type,
             bool read_only)
    : mount_point_(mount_point) {
  udev_utils_ = std::make_unique<UdevUtilsImpl>();
  valid_ = AttemptMount(device_path, mount_point, fs_type, read_only);
}

Mount::Mount(const base::FilePath& device_path,
             const base::FilePath& mount_point,
             const std::string& fs_type,
             bool read_only,
             std::unique_ptr<UdevUtils> udev_utils)
    : mount_point_(mount_point), udev_utils_(std::move(udev_utils)) {
  valid_ = AttemptMount(device_path, mount_point, fs_type, read_only);
}

Mount::Mount(Mount&& mount)
    : mount_point_(mount.mount_point_),
      valid_(mount.valid_),
      udev_utils_(std::move(mount.udev_utils_)) {
  mount.valid_ = false;
}

Mount& Mount::operator=(Mount&& mount) {
  mount_point_ = mount.mount_point_;
  udev_utils_ = std::move(mount.udev_utils_);
  valid_ = mount.valid_;
  mount.valid_ = false;
  return *this;
}

bool Mount::AttemptMount(const base::FilePath& device_path,
                         const base::FilePath& mount_point,
                         const std::string& fs_type,
                         bool read_only) {
  if (!IsSupportedFileSystemType(fs_type)) {
    return false;
  }

  // |device_path| is restricted to device paths for block devices with
  // supported filesystems.
  std::unique_ptr<UdevDevice> dev;
  if (!udev_utils_->GetBlockDeviceFromDevicePath(device_path.value(), &dev) ||
      !dev->IsRemovable() ||
      !IsSupportedFileSystemType(dev->GetFileSystemType())) {
    return false;
  }

  if (!VerifyMountPoint(mount_point)) {
    return false;
  }

  uint32_t mount_flags = kDefaultMountFlags;
  if (read_only) {
    mount_flags |= MS_RDONLY;
  }

  if (mount(device_path.value().c_str(), mount_point.value().c_str(),
            fs_type.c_str(), mount_flags, "") != 0) {
    PLOG(ERROR) << "Failed to mount " << device_path.value() << " to "
                << mount_point.value();
    return false;
  }

  return true;
}

Mount::~Mount() {
  if (IsValid() && umount(mount_point_.value().c_str()) != 0) {
    PLOG(ERROR) << "Failed to unmount " << mount_point_.value();
  }
}

bool Mount::VerifyMountPoint(const base::FilePath& mount_point) {
  struct stat st, st_parent;
  if (lstat(mount_point.value().c_str(), &st) != 0) {
    PLOG(ERROR) << "Could not lstat the mount point " << mount_point.value();
    return false;
  }
  if (!S_ISDIR(st.st_mode)) {
    LOG(ERROR) << "Mount point " << mount_point.value()
               << " exists but is not a directory";
    return false;
  }

  base::FilePath mount_parent = mount_point.DirName();
  if (stat(mount_parent.value().c_str(), &st_parent) != 0) {
    PLOG(ERROR) << "Could not stat the mount point parent "
                << mount_parent.value();
    return false;
  }
  return st.st_dev == st_parent.st_dev;
}

}  // namespace rmad
