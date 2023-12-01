// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBBRILLO_BRILLO_BLKDEV_UTILS_UFS_H_
#define LIBBRILLO_BRILLO_BLKDEV_UTILS_UFS_H_

#include <base/files/file_path.h>
#include <brillo/blkdev_utils/storage_device.h>
#include <brillo/brillo_export.h>

namespace brillo {

BRILLO_EXPORT base::FilePath UfsSysfsToControllerNode(
    const base::FilePath& dev_node);
BRILLO_EXPORT bool IsUfs(const base::FilePath& dev_node);

// Implements UFS's wiping function, which logically erases the storage using
// `BLKDISCARD`, then physically erases the BLKDISCARD'ed region.
class BRILLO_EXPORT Ufs : public StorageDevice {
 public:
  bool SupportPhysicalErasure() const override;

 private:
  LogicalErasureIoctl GetLogicalErasureIoctlType() const override;
  // Physically erases the regions that has been BLKDISCARD'ed.
  // Dependencies
  //   factory_ufs binary
  bool PhysicalErasure(const base::FilePath& device_path,
                       const uint64_t device_length) const override;
};

}  // namespace brillo

#endif  // LIBBRILLO_BRILLO_BLKDEV_UTILS_UFS_H_
