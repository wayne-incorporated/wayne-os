// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "secure_erase_file/secure_erase_file.h"

#include <fcntl.h>
#include <linux/fiemap.h>
#include <linux/fs.h>
#include <linux/major.h>
#include <linux/mmc/ioctl.h>
#include <mntent.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>

#include <algorithm>
#include <limits>
#include <memory>
#include <string>
#include <vector>

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_file.h>
#include <base/logging.h>
#include <base/memory/free_deleter.h>
#include <base/process/launch.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <brillo/blkdev_utils/get_backing_block_device.h>

namespace secure_erase_file {
namespace {

// A container for fiemap that handles cleaning up allocated memory.
// base::FreeDeleter must be used here because the underlying struct fiemap is
// allocated with malloc().
typedef std::unique_ptr<struct fiemap, base::FreeDeleter> ScopedFiemap;

// For simplicity, we only support files with up to 32 extents, and fail
// otherwise.
//
// This is somewhat arbitrary and could be increased in the future if there is a
// need to securely erase larger files.
constexpr int kMaxExtents = 32;

// When verifying that the original data can not be read back, we read in 1M
// chunks instead of reading the whole file at once.
constexpr size_t kVerifyReadSizeBytes = 1024 * 1024;

// Verifies that the data for an extent has been erased by seeking within the
// partition and confirming that the original file data is erased.
//
// Returns true only if the read succeeds and all bytes are 0x00 or 0xFF.
bool VerifyExtentErased(int partition_fd,
                        uint64_t start,
                        uint64_t len,
                        bool zero_only) {
  // NOTE: This verification scheme assumes that blocks can be read after being
  // trimmed. According to gwendal@, this is not true for NVMe 1.3 devices with
  // NSFEAT bit 2 set to 1. If that is something we need to support, we could
  // confirm that the blocks cannot be read on those devices.
  if (lseek(partition_fd, start, SEEK_SET) < 0) {
    PLOG(ERROR) << "Failed to seek in partition fd";
    return false;
  }

  std::unique_ptr<char[]> buf(new char[kVerifyReadSizeBytes]);
  uint64_t to_read = len;
  do {
    // Limit file reads to 1M regions to keep our memory footprint reasonable.
    size_t bytes_to_read = std::min<size_t>(to_read, kVerifyReadSizeBytes);
    int rc = HANDLE_EINTR(read(partition_fd, buf.get(), bytes_to_read));
    if (rc < 0) {
      PLOG(ERROR) << "Failed to read LBAs to verify erase";
      return false;
    }
    for (int i = 0; i < rc; i++) {
      unsigned char ch = buf.get()[i];
      if (ch != 0x00 && (zero_only || ch != 0xFF)) {
        LOG(ERROR) << "Found uncleared data at partition byte: "
                   << start + (len - to_read) + i;
        return false;
      }
    }
    to_read -= rc;
  } while (to_read > 0);
  return true;
}

// Fetches extent data for the requested file path.
ScopedFiemap GetExtentsForFile(const base::FilePath& path) {
  size_t alloc_size = offsetof(struct fiemap, fm_extents[kMaxExtents]);
  ScopedFiemap fm(static_cast<struct fiemap*>(malloc(alloc_size)));
  memset(fm.get(), 0, alloc_size);
  fm->fm_length = std::numeric_limits<uint64_t>::max();
  fm->fm_flags |= FIEMAP_FLAG_SYNC;
  fm->fm_extent_count = kMaxExtents;

  base::ScopedFD fd(open(path.value().c_str(), O_RDONLY | O_CLOEXEC));
  if (fd.get() < 0) {
    PLOG(ERROR) << "Unable to open file: " << path.value();
    return nullptr;
  }

  // There's no need to sync() before getting the extents with the ioctl() here;
  // the kernel takes care of that with FIEMAP_FLAG_SYNC set above. See
  // fs/ioctl.c in the kernel for details.
  if (HANDLE_EINTR(ioctl(fd.get(), FS_IOC_FIEMAP, fm.get())) < -1) {
    PLOG(ERROR) << "Unable to get FIEMAP for file: " << path.value();
    return nullptr;
  }

  // We require that the target file has at least 1 extent.
  // This means that we don't support inlined files in ext4, but don't have to
  // handle the case where sensitive data is stored inside the inode.
  if (fm->fm_mapped_extents < 1 || fm->fm_mapped_extents > kMaxExtents) {
    LOG(ERROR) << "Bad number of mapped extents (" << fm->fm_mapped_extents
               << ") for path: " << path.value();
    return nullptr;
  }

  // We don't want to erase data for any files that have shared extents. Doing
  // so may destroy data for other files.
  for (uint32_t i = 0; i < fm->fm_mapped_extents; i++) {
    if (fm->fm_extents[i].fe_flags & FIEMAP_EXTENT_SHARED) {
      LOG(ERROR) << "Shared extent found for path: " << path.value();
      return nullptr;
    }
    if (fm->fm_extents[i].fe_flags & FIEMAP_EXTENT_DATA_INLINE) {
      LOG(ERROR) << "Data mixed with metadata in extent found for path: "
                 << path.value();
      return nullptr;
    }
    if (fm->fm_extents[i].fe_flags & FIEMAP_EXTENT_DATA_TAIL) {
      LOG(ERROR) << "Multiple files in block for extent found for path: "
                 << path.value();
      return nullptr;
    }
  }

  return fm;
}

// Trims extents specified in |fm| on the partition specified in |partition_fd|.
bool TrimExtents(int partition_fd, const struct fiemap* fm) {
  for (uint32_t i = 0; i < fm->fm_mapped_extents; i++) {
    uint64_t range[2];
    range[0] = fm->fm_extents[i].fe_physical;
    range[1] = fm->fm_extents[i].fe_length;

    // TODO(crbug.com/724169): Explicitly send TRIM+SANITIZE from userspace.
    //
    // BLKDISCARD can't be used as it may send DISCARD instead of a TRIM, which
    // isn't guaranteed to completely remove data with SANITIZE.
    //
    // Similarly, we cannot use FITRIM here because it will skip requests that
    // are smaller than the discard granularity.
    //
    // Sending a TRIM will require either explicitly crafting eMMC commands from
    // userspace, or modifying the kernel to force a TRIM from some other
    // interface.
    //
    // BLKSECDISCARD (Secure Erase) is eMMC-only and is deprecated in favor of
    // TRIM+SANITIZE as of eMMC 4.51.
    if (HANDLE_EINTR(ioctl(partition_fd, BLKSECDISCARD, &range)) < 0) {
      PLOG(ERROR) << "Unable to BLKSECDISCARD target range";
      return false;
    }
  }
  return true;
}

// Zero extents specified in |fm| on the partition specified in |partition_fd|.
bool ZeroExtents(int partition_fd, const struct fiemap* fm) {
  for (uint32_t i = 0; i < fm->fm_mapped_extents; i++) {
    uint64_t range[2];
    range[0] = fm->fm_extents[i].fe_physical;
    range[1] = fm->fm_extents[i].fe_length;

    if (HANDLE_EINTR(ioctl(partition_fd, BLKZEROOUT, &range)) < 0) {
      PLOG(ERROR) << "Unable to BLKZEROOUT target range";
      return false;
    }
  }
  return true;
}

// Verifies that the data in given extents cannot be recovered.
bool VerifyExtentsErased(int partition_fd,
                         const struct fiemap* fm,
                         bool zero_only) {
  for (uint32_t i = 0; i < fm->fm_mapped_extents; i++) {
    if (!VerifyExtentErased(partition_fd, fm->fm_extents[i].fe_physical,
                            fm->fm_extents[i].fe_length, zero_only)) {
      return false;
    }
  }
  return true;
}

bool IsDevMmc(const base::FilePath& path) {
  struct stat stat_buf;
  if (stat(path.value().c_str(), &stat_buf) < 0) {
    PLOG(WARNING) << "Could not stat: " << path.value();
    return false;
  }

  if (major(stat_buf.st_rdev) == MMC_BLOCK_MAJOR) {
    return true;
  }

  return false;
}

}  // namespace

bool IsSupported(const base::FilePath& path) {
  struct stat stat_buf;
  if (stat(path.value().c_str(), &stat_buf) < 0) {
    PLOG(WARNING) << "Could not stat: " << path.value();
    return false;
  }
  if (!S_ISREG(stat_buf.st_mode)) {
    LOG(WARNING) << "File is not a regular file: " << path.value();
    return false;
  }

  // Note that this prevents us from supporting files on mount points like /var.
  if (IsDevMmc(brillo::GetBackingLogicalDeviceForFile(path))) {
    return true;
  }

  LOG(WARNING) << "secure_erase_file only supports eMMC devices. "
               << "Ineligible file: " << path.value();
  return false;
}

bool SecureErase(const base::FilePath& path) {
  if (!IsSupported(path)) {
    LOG(ERROR) << "Could not erase file, device unsupported for path: "
               << path.value();
    return false;
  }

  ScopedFiemap fm = GetExtentsForFile(path);
  if (!fm) {
    LOG(ERROR) << "Failed to get extents for file: " << path.value();
    return false;
  }

  std::string partition = brillo::GetBackingLogicalDeviceForFile(path).value();
  if (partition.empty()) {
    LOG(ERROR) << "Partition could not be found for file: " << path.value();
    return false;
  }

  base::ScopedFD partition_fd(
      open(partition.c_str(), O_RDWR | O_LARGEFILE | O_CLOEXEC));
  if (partition_fd.get() < 0) {
    PLOG(ERROR) << "Unable to open partition: " << partition;
  }

  if (!TrimExtents(partition_fd.get(), fm.get())) {
    return false;
  }

  if (!VerifyExtentsErased(partition_fd.get(), fm.get(), /*zero_only=*/false)) {
    return false;
  }

  if (unlink(path.value().c_str()) < 0) {
    PLOG(ERROR) << "Failed to unlink() file: " << path.value();
    return false;
  }
  sync();

  return true;
}

bool ZeroFile(const base::FilePath& path) {
  struct stat stat_buf;
  if (stat(path.value().c_str(), &stat_buf) < 0) {
    PLOG(WARNING) << "Could not stat: " << path.value();
    return false;
  }
  if (!S_ISREG(stat_buf.st_mode)) {
    LOG(WARNING) << "File is not a regular file: " << path.value();
    return false;
  }

  ScopedFiemap fm = GetExtentsForFile(path);
  if (!fm) {
    LOG(ERROR) << "Failed to get extents for file: " << path.value();
    return false;
  }

  base::FilePath dev_node = brillo::GetBackingLogicalDeviceForFile(path);
  if (dev_node.empty()) {
    PLOG(ERROR) << "Can not find backing logical device for a file: " << path;
    return false;
  }

  base::ScopedFD dev_fd(
      open(dev_node.value().c_str(), O_RDWR | O_LARGEFILE | O_CLOEXEC));
  if (dev_fd.get() < 0) {
    PLOG(ERROR) << "Unable to open partition: " << dev_node;
    return false;
  }

  if (!ZeroExtents(dev_fd.get(), fm.get())) {
    return false;
  }

  if (!VerifyExtentsErased(dev_fd.get(), fm.get(), /*zero_only=*/true)) {
    return false;
  }

  if (unlink(path.value().c_str()) < 0) {
    PLOG(ERROR) << "Failed to unlink() file: " << path.value();
    return false;
  }
  sync();

  return true;
}

bool DropCaches() {
  // Drop all clean cache data to ensure that erased data does not stay visible.
  // This clears the page cache and slab objects (maybe unnecessary).
  // https://www.kernel.org/doc/Documentation/sysctl/vm.txt
  constexpr char kData = '3';
  if (!base::WriteFile(base::FilePath("/proc/sys/vm/drop_caches"), &kData,
                       sizeof(kData))) {
    PLOG(ERROR) << "Failed to drop cache.";
    return false;
  }
  return true;
}

}  // namespace secure_erase_file
