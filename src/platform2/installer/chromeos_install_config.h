// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef INSTALLER_CHROMEOS_INSTALL_CONFIG_H_
#define INSTALLER_CHROMEOS_INSTALL_CONFIG_H_

#include <string>

#include <base/files/file_path.h>

#include "installer/inst_util.h"

// These values are persisted to logs. Entries should not be renumbered and
// numeric values should never be reused.
enum class BiosType {
  kUnknown = 0,
  kSecure = 1,
  kUBoot = 2,
  kLegacy = 3,
  kEFI = 4,
  kMaxValue = kEFI
};

bool StrToBiosType(std::string name, BiosType* bios_type);

enum DeferUpdateAction {
  kAuto,
  kHold,
  kApply,
};

bool StrToDeferUpdateAction(std::string name, DeferUpdateAction* defer_updates);

// We commonly need to have the same data about devices in multiple formats
// during the install process. This class allows us to have a partition
// device in whichever format is currently most useful.
//
// Partition device name "/dev/sda3"
// Base device and number "/dev/sda" 3
// Mount point (optional) "/tmp/root.mnt"
class Partition {
 public:
  Partition() {}
  explicit Partition(base::FilePath device) : device_(device) {}
  Partition(base::FilePath device, base::FilePath mount)
      : device_(device), mount_(mount) {}

  // Get/Set the partition device, usually of form: /dev/sda3
  base::FilePath device() const { return device_; }
  void set_device(const base::FilePath& device) { device_ = device; }

  // If the device is /dev/sda3 the base_device is /dev/sda
  base::FilePath base_device() const {
    return GetBlockDevFromPartitionDev(device());
  }

  // If the device is /dev/sda3 the number is 3
  PartitionNum number() const { return GetPartitionFromPartitionDev(device()); }

  virtual std::string uuid() const;

  // The mount point for this device or "" if unmounted/unknown
  base::FilePath mount() const { return mount_; }
  void set_mount(const base::FilePath& mount) { mount_ = mount; }

 private:
  base::FilePath device_;
  base::FilePath mount_;
};

// This class contains all of the information commonly passed around
// during a post install.
struct InstallConfig {
  // "A" or "B" in a standard install
  std::string slot;

  Partition root;
  Partition kernel;
  Partition boot;

  BiosType bios_type;
  DeferUpdateAction defer_update_action;
  bool force_update_firmware{false};
};

#endif  // INSTALLER_CHROMEOS_INSTALL_CONFIG_H_
