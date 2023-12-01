// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Supports storage related utilities, such as getting the storage type.

#ifndef LIBBRILLO_BRILLO_BLKDEV_UTILS_STORAGE_UTILS_H_
#define LIBBRILLO_BRILLO_BLKDEV_UTILS_STORAGE_UTILS_H_

#include <memory>
#include <string>

#include <base/files/file_path.h>
#include <brillo/brillo_export.h>
#include <brillo/blkdev_utils/storage_device.h>

namespace brillo {
enum StorageType { ata, emmc, nvme, ufs, usb, others };

// Provides an interface to get the storage information.
class BRILLO_EXPORT StorageUtils {
 public:
  StorageUtils() = default;
  virtual ~StorageUtils() = default;

  // Gets the storage type.
  // This function re-implements the logic of `get_device_type` from
  // `src/platform2/chromeos-common-script/share/chromeos-common.sh`.
  // Returns StorageType enum.
  // Parameters
  //   root - Path to the root.
  //   root_disk - Path to the main storage.
  StorageType GetStorageType(const base::FilePath& root,
                             const base::FilePath& root_disk);

 protected:
  // Gets the absolute path.
  // Marks as protected so that it can be overridden by the unit tests.
  // Returns
  //   The absolute file path. Will be empty on failure.
  virtual base::FilePath GetAbsPath(const base::FilePath& path);
};

// Gets the StorageDevice object derived from the StorageType.
BRILLO_EXPORT std::unique_ptr<StorageDevice> GetStorageDevice(
    const base::FilePath& root_disk);

// Maps the StorageType enum to a string.
BRILLO_EXPORT std::string StorageTypeToString(StorageType type);

// Get the path of a device's partition. This handles prefixing the
// partition number with a 'p' when needed.
//
// The device path cannot be empty, and the partition must be >= 1.
BRILLO_EXPORT base::FilePath AppendPartition(const base::FilePath& device,
                                             int partition);

}  // namespace brillo

#endif  // LIBBRILLO_BRILLO_BLKDEV_UTILS_STORAGE_UTILS_H_
