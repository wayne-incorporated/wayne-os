// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This is a base class that provides basic operations, such as wiping, on a
// block device.

#ifndef LIBBRILLO_BRILLO_BLKDEV_UTILS_STORAGE_DEVICE_H_
#define LIBBRILLO_BRILLO_BLKDEV_UTILS_STORAGE_DEVICE_H_

#include <string>

#include <base/files/file.h>
#include <base/files/file_path.h>
#include <brillo/brillo_export.h>

namespace brillo {
// Defines the ioctl used to logically erase the block device.
enum BRILLO_EXPORT LogicalErasureIoctl {
  blkdiscard,
  blkzeroout,
  blksecdiscard,
};

// Maps the LogicalErasureIoctl enum to a string.
BRILLO_EXPORT std::string LogicalErasureIoctlToString(
    LogicalErasureIoctl ioctl_type);

// Provides an interface to wipe the given block device.
class BRILLO_EXPORT StorageDevice {
 public:
  StorageDevice() = default;
  virtual ~StorageDevice() = default;

  // Wipes a range of bytes on the block device.
  // Wiping consists of two operations: LogicalErasure and PhysicalErasure.
  // LogicalErasure invokes `LogicalErasureIoctl` on a range of bytes on the
  // block device. PhysicalErasure physically erases the region that has been
  // logically erased.
  // Returns false on failure.
  // Parameters
  //   device_path - Path to the block device.
  //   device_offset - The starting byte offset to wipe.
  //   device_length - The number of bytes to wipe.
  //   run_physical_erasure - If set to true, PhysicalErasure will be invoked.
  //   discard - Set to true to discard the blocks after a wipe.
  bool WipeBlkDev(const base::FilePath& device_path,
                  const uint64_t device_offset,
                  const uint64_t device_length,
                  bool run_physical_erasure,
                  bool discard) const;

  // Zeros a range of bytes on the block device.
  bool ZeroBlockDevice(const base::FilePath& device_path,
                       const uint64_t device_offset,
                       const uint64_t device_length) const;

  // Discards a range of bytes on the block device.
  bool DiscardBlockDevice(const base::FilePath& device_path,
                          const uint64_t device_offset,
                          const uint64_t device_length) const;

  // Secure discards a range of bytes on the block device.
  bool SecureDiscardBlockDevice(const base::FilePath& device_path,
                                const uint64_t device_offset,
                                const uint64_t device_length) const;

  // Whether the device supports physical erasure or not.
  virtual bool SupportPhysicalErasure() const;

 private:
  // Logically erases a range of bytes on the block device.
  // Returns false on failure.
  // Parameters
  //   device_path - Path to the block device.
  //   device_offset - The starting byte offset to wipe.
  //   device_length - The number of bytes to wipe.
  //   ioctl_type - The ioctl used to logically erase the block device.
  bool LogicalErasure(const base::FilePath& device_path,
                      const uint64_t device_offset,
                      const uint64_t device_length,
                      LogicalErasureIoctl ioctl_type) const;

  // Get the device specific ioctl to logically erase the block device.
  // By default, the operation is `BLKZEROOUT` since it is significantly faster
  // if supported by the device. It is not supported on kernels before 4.4.
  virtual LogicalErasureIoctl GetLogicalErasureIoctlType() const;

  // Physically erases the region that has been logically erased. Currently,
  // only UFS and eMMC support physical erasure.
  // Parameters
  //   device_path - Path to the block device.
  //   device_length - The number of bytes to wipe.
  // Returns
  //   true on success.
  //   false on failure or unsupported.
  virtual bool PhysicalErasure(const base::FilePath& device_path,
                               const uint64_t device_length) const;
};

}  // namespace brillo

#endif  // LIBBRILLO_BRILLO_BLKDEV_UTILS_STORAGE_DEVICE_H_
