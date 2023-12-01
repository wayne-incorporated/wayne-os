// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "spaced/disk_usage_impl.h"

#include <algorithm>
#include <memory>
#include <optional>
#include <string>

#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/statvfs.h>

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/posix/eintr_wrapper.h>
#include <base/strings/string_util.h>
#include <rootdev/rootdev.h>

namespace spaced {
DiskUsageUtilImpl::DiskUsageUtilImpl(const base::FilePath& rootdev,
                                     std::optional<brillo::Thinpool> thinpool)
    : rootdev_(rootdev), thinpool_(thinpool) {}

int DiskUsageUtilImpl::StatVFS(const base::FilePath& path, struct statvfs* st) {
  return HANDLE_EINTR(statvfs(path.value().c_str(), st));
}

int64_t DiskUsageUtilImpl::GetFreeDiskSpace(const base::FilePath& path) {
  // Use statvfs() to get the free space for the given path.
  struct statvfs stat;

  if (StatVFS(path, &stat) != 0) {
    PLOG(ERROR) << "Failed to run statvfs() on " << path;
    return -1;
  }

  int64_t free_disk_space = static_cast<int64_t>(stat.f_bavail) * stat.f_frsize;

  return free_disk_space;
}

int64_t DiskUsageUtilImpl::GetTotalDiskSpace(const base::FilePath& path) {
  // Use statvfs() to get the total space for the given path.
  struct statvfs stat;

  if (StatVFS(path, &stat) != 0) {
    PLOG(ERROR) << "Failed to run statvfs() on " << path;
    return -1;
  }

  int64_t total_disk_space =
      static_cast<int64_t>(stat.f_blocks) * stat.f_frsize;

  int64_t thinpool_total_space;
  if (thinpool_ && thinpool_->IsValid() &&
      thinpool_->GetTotalSpace(&thinpool_total_space)) {
    total_disk_space = std::min(total_disk_space, thinpool_total_space);
  }

  return total_disk_space;
}

int64_t DiskUsageUtilImpl::GetBlockDeviceSize(const base::FilePath& device) {
  base::ScopedFD fd(HANDLE_EINTR(
      open(device.value().c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC)));
  if (!fd.is_valid()) {
    PLOG(ERROR) << "open " << device.value();
    return -1;
  }

  int64_t size;
  if (ioctl(fd.get(), BLKGETSIZE64, &size)) {
    PLOG(ERROR) << "ioctl(BLKGETSIZE): " << device.value();
    return -1;
  }
  return size;
}

int64_t DiskUsageUtilImpl::GetRootDeviceSize() {
  if (rootdev_.empty()) {
    LOG(WARNING) << "Failed to get root device";
    return -1;
  }

  return GetBlockDeviceSize(rootdev_);
}

}  // namespace spaced
