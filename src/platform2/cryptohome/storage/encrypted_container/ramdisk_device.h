// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_STORAGE_ENCRYPTED_CONTAINER_RAMDISK_DEVICE_H_
#define CRYPTOHOME_STORAGE_ENCRYPTED_CONTAINER_RAMDISK_DEVICE_H_

#include <memory>
#include <string>

#include <base/files/file_path.h>

#include "cryptohome/platform.h"

#include "cryptohome/storage/encrypted_container/backing_device.h"
#include "cryptohome/storage/encrypted_container/loopback_device.h"

namespace cryptohome {

class RamdiskDevice final : public LoopbackDevice {
 public:
  ~RamdiskDevice() override = default;

  bool Create() override;
  bool Purge() override;
  bool Teardown() override;
  BackingDeviceType GetType() override { return LoopbackDevice::GetType(); }

  static std::unique_ptr<RamdiskDevice> Generate(
      const std::string& backing_file_name, Platform* platform);

 private:
  RamdiskDevice(const BackingDeviceConfig& config, Platform* platform);

  Platform* platform_;
};

}  // namespace cryptohome

#endif  // CRYPTOHOME_STORAGE_ENCRYPTED_CONTAINER_RAMDISK_DEVICE_H_
