// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBBRILLO_BRILLO_BLKDEV_UTILS_EMMC_H_
#define LIBBRILLO_BRILLO_BLKDEV_UTILS_EMMC_H_

#include <base/files/file_path.h>
#include <brillo/blkdev_utils/storage_device.h>
#include <brillo/brillo_export.h>

namespace brillo {

// Implements eMMC's wiping function, which logically erases the storage using
// `BLKSECDISCARD`, then physically erases the BLKSECDISCARD'ed region.
class BRILLO_EXPORT Emmc : public StorageDevice {
 public:
  bool SupportPhysicalErasure() const override;

 private:
  LogicalErasureIoctl GetLogicalErasureIoctlType() const override;
  // Physically erases the regions that has been BLKSECDISCARD'ed.
  // Dependencies
  //   mmc binary
  bool PhysicalErasure(const base::FilePath& device_path,
                       const uint64_t device_length) const override;
};

}  // namespace brillo

#endif  // LIBBRILLO_BRILLO_BLKDEV_UTILS_EMMC_H_
