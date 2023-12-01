// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_STORAGE_ENCRYPTED_CONTAINER_LOGICAL_VOLUME_BACKING_DEVICE_H_
#define CRYPTOHOME_STORAGE_ENCRYPTED_CONTAINER_LOGICAL_VOLUME_BACKING_DEVICE_H_

#include "cryptohome/storage/encrypted_container/backing_device.h"

#include <memory>
#include <optional>
#include <string>

#include <base/files/file_path.h>
#include <base/values.h>
#include <brillo/blkdev_utils/lvm.h>

namespace cryptohome {

// `LogicalVolumeBackingDevice` represents a thin volume backing device.
class LogicalVolumeBackingDevice : public BackingDevice {
 public:
  // `LogicalVolumeBackingDevice` are defined by the following config values:
  // - `name`: Name of the logical volume.
  // - `vg`: Object of volume group on which the logical volume resides.
  // - `thinpool`: Object of thinpool which backs the logical volume.
  // - `size`: Size of thin logical volume.
  LogicalVolumeBackingDevice(const BackingDeviceConfig& config,
                             brillo::LogicalVolumeManager* lvm);
  ~LogicalVolumeBackingDevice() = default;

  // Creates the thin logical volume.
  bool Create() override;

  // Removed the thin logical volume. The volume should not be in-use before
  // calling this function.
  bool Purge() override;

  // Activates the logical volume.
  bool Setup() override;

  // Deactivates the logical volume.
  bool Teardown() override;

  // Checks if the logical volume exists.
  bool Exists() override;

  // Gets the device type for reporting.
  BackingDeviceType GetType() override {
    return BackingDeviceType::kLogicalVolumeBackingDevice;
  }

  // Gets path to the logical volume's block device.
  std::optional<base::FilePath> GetPath() override;

 private:
  std::optional<brillo::LogicalVolume> GetLogicalVolume();

  const std::string name_;
  const int64_t size_;

  const std::shared_ptr<brillo::VolumeGroup> vg_;
  const std::shared_ptr<brillo::Thinpool> thinpool_;

  std::optional<brillo::LogicalVolume> lv_;

  brillo::LogicalVolumeManager* lvm_;
};

}  // namespace cryptohome

#endif  // CRYPTOHOME_STORAGE_ENCRYPTED_CONTAINER_LOGICAL_VOLUME_BACKING_DEVICE_H_
