// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_STORAGE_ENCRYPTED_CONTAINER_BACKING_DEVICE_H_
#define CRYPTOHOME_STORAGE_ENCRYPTED_CONTAINER_BACKING_DEVICE_H_

#include <memory>
#include <optional>
#include <string>

#include <base/files/file_path.h>
#include <base/values.h>
#include <brillo/blkdev_utils/lvm.h>

#include "cryptohome/platform.h"

namespace cryptohome {

// `BackingDeviceType` represents the types of backing devices currently
// supported.
enum class BackingDeviceType {
  kUnknown = 0,
  kLoopbackDevice,
  kRamdiskDevice,
  kLogicalVolumeBackingDevice,
};

// Configuration for backing devices.
struct BackingDeviceConfig {
  BackingDeviceType type;
  std::string name;
  int64_t size;
  struct {
    base::FilePath backing_file_path;
    bool fixed_backing;
  } loopback;
  struct {
    std::string backing_file_name;
  } ramdisk;
  struct {
    std::shared_ptr<brillo::VolumeGroup> vg;
    std::shared_ptr<brillo::Thinpool> thinpool;
  } logical_volume;
};

// `BackingDevice` represents a backing block device that can be used as a
// building block for storage containers.
class BackingDevice {
 public:
  virtual ~BackingDevice() {}

  virtual bool Create() = 0;
  virtual bool Purge() = 0;
  virtual bool Setup() = 0;
  virtual bool Teardown() = 0;
  virtual bool Exists() = 0;
  virtual BackingDeviceType GetType() = 0;
  virtual std::optional<base::FilePath> GetPath() = 0;
};

}  // namespace cryptohome

#endif  // CRYPTOHOME_STORAGE_ENCRYPTED_CONTAINER_BACKING_DEVICE_H_
