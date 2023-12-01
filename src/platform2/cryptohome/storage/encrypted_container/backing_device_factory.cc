// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/storage/encrypted_container/backing_device_factory.h"

#include <memory>

#include "cryptohome/platform.h"
#include "cryptohome/storage/encrypted_container/backing_device.h"
#include "cryptohome/storage/encrypted_container/logical_volume_backing_device.h"
#include "cryptohome/storage/encrypted_container/ramdisk_device.h"

namespace cryptohome {

BackingDeviceFactory::BackingDeviceFactory(Platform* platform)
    : platform_(platform) {}

std::unique_ptr<BackingDevice> BackingDeviceFactory::Generate(
    const BackingDeviceConfig& config) {
  switch (config.type) {
    case BackingDeviceType::kLoopbackDevice:
      return std::make_unique<LoopbackDevice>(config, platform_);
    case BackingDeviceType::kRamdiskDevice:
      return RamdiskDevice::Generate(config.ramdisk.backing_file_name,
                                     platform_);
    case BackingDeviceType::kLogicalVolumeBackingDevice:
      return std::make_unique<LogicalVolumeBackingDevice>(
          config, platform_->GetLogicalVolumeManager());
    default:
      return nullptr;
  }
}

}  // namespace cryptohome
