// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_FETCHERS_STORAGE_DEVICE_INFO_H_
#define DIAGNOSTICS_CROS_HEALTHD_FETCHERS_STORAGE_DEVICE_INFO_H_

#include <cstdint>
#include <memory>
#include <string>

#include <base/files/file_path.h>
#include <brillo/blkdev_utils/disk_iostat.h>

#include "diagnostics/cros_healthd/fetchers/storage/platform.h"
#include "diagnostics/mojom/public/cros_healthd_probe.mojom.h"

namespace diagnostics {

// StorageDeviceInfo encapsulates the logic for retrieving info about an
// individual storage device. Should not leave longer than its parent
// StorageDeviceManager.
class StorageDeviceInfo {
 public:
  static std::unique_ptr<StorageDeviceInfo> Create(
      const base::FilePath& dev_sys_path,
      const base::FilePath& dev_node_path,
      const std::string& subsystem,
      ash::cros_healthd::mojom::StorageDevicePurpose purpose,
      const Platform* platform);

  // FetchDeviceInfo fills the mutable fields of Mojo's data structure
  // representing a block device.
  base::expected<ash::cros_healthd::mojom::NonRemovableBlockDeviceInfoPtr,
                 ash::cros_healthd::mojom::ProbeErrorPtr>
  FetchDeviceInfo();

 private:
  const base::FilePath dev_sys_path_;
  const base::FilePath dev_node_path_;
  const Platform* const platform_;

  brillo::DiskIoStat iostat_;
  ash::cros_healthd::mojom::NonRemovableBlockDeviceInfoPtr
      immutable_block_device_info_;

  StorageDeviceInfo(const base::FilePath& dev_sys_path,
                    const base::FilePath& dev_node_path,
                    ash::cros_healthd::mojom::NonRemovableBlockDeviceInfoPtr
                        immutable_block_device_info,
                    const Platform* platform);
  StorageDeviceInfo(const StorageDeviceInfo&) = delete;
  StorageDeviceInfo(StorageDeviceInfo&&) = delete;
  StorageDeviceInfo& operator=(const StorageDeviceInfo&) = delete;
  StorageDeviceInfo& operator=(StorageDeviceInfo&&) = delete;
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_FETCHERS_STORAGE_DEVICE_INFO_H_
