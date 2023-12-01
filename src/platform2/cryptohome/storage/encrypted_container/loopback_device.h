// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_STORAGE_ENCRYPTED_CONTAINER_LOOPBACK_DEVICE_H_
#define CRYPTOHOME_STORAGE_ENCRYPTED_CONTAINER_LOOPBACK_DEVICE_H_

#include "cryptohome/storage/encrypted_container/backing_device.h"

#include <memory>
#include <optional>
#include <string>

#include <base/files/file_path.h>
#include <base/values.h>
#include <brillo/blkdev_utils/loop_device.h>

#include "cryptohome/platform.h"

namespace cryptohome {

// `LoopbackDevice` represents a loop device over a sparse backing file.
class LoopbackDevice : public BackingDevice {
 public:
  // LoopbackDevices are defined by the following config values:
  // - `name`: Name of the loopback device. This should be unique across
  //         loop devices. For all operations, loopback devices are queried
  //         by name.
  // - `size`: Size of the underlying sparse file.
  // - `backing_file_path`: Path of the backing sparse file.
  LoopbackDevice(const BackingDeviceConfig& config, Platform* platform);

  ~LoopbackDevice() = default;

  // Creates the sparse backing file.
  bool Create() override;

  // Removes the sparse backing file. This function should only be called when
  // the loopback device is not active.
  bool Purge() override;

  // Sets up the loopback device and sets the loopback device name.
  bool Setup() override;

  // Detaches the loopback device by name.
  bool Teardown() override;

  // Checks if the backing device exists.
  bool Exists() override;

  // Gets the device type for reporting.
  BackingDeviceType GetType() override {
    return BackingDeviceType::kLoopbackDevice;
  }

  // Gets the device path for the loop device.
  std::optional<base::FilePath> GetPath() override;

 protected:
  const base::FilePath backing_file_path_;

 private:
  friend class LoopbackDevicePeer;

  const std::string name_;
  const int64_t size_;
  const bool fixed_backing_;

  Platform* platform_;
};

}  // namespace cryptohome

#endif  // CRYPTOHOME_STORAGE_ENCRYPTED_CONTAINER_LOOPBACK_DEVICE_H_
