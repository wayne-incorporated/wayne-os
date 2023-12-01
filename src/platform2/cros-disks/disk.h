// Copyright 2011 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CROS_DISKS_DISK_H_
#define CROS_DISKS_DISK_H_

#include <stdint.h>

#include <string>
#include <vector>

#include <chromeos/dbus/service_constants.h>

namespace cros_disks {

// A simple type that describes a storage device attached to our system.
//
// This class was designed to run in a single threaded context and should not
// be considered thread safe.
struct Disk {
  // Returns a presentation name of the disk, which can be used to name
  // the mount directory of the disk. The naming scheme is as follows:
  // (1) Use a non-empty label if the disk has one.
  // (2) Otherwise, use one of the following names based on the device
  //     media type:
  //     - USB drive
  //     - SD card
  //     - Optical disc
  //     - Mobile device
  //     - External drive (if the device media type is unknown)
  // Any forward slash '/' in the presentation name is replaced with an
  // underscore '_'.
  std::string GetPresentationName() const;

  bool IsMounted() const { return !mount_paths.empty(); }

  bool IsOpticalDisk() const {
    return (media_type == DeviceType::kOpticalDisc ||
            media_type == DeviceType::kDVD);
  }

  bool is_drive = false;
  bool is_hidden = false;
  bool is_auto_mountable = false;
  bool is_media_available = false;
  bool is_on_boot_device = true;
  bool is_on_removable_device = false;
  bool is_rotational = false;
  bool is_read_only = false;
  bool is_virtual = true;
  std::vector<std::string> mount_paths;
  std::string native_path;
  std::string device_file;
  std::string storage_device_path;
  std::string filesystem_type;
  std::string uuid;
  std::string label;
  std::string vendor_id;
  std::string vendor_name;
  std::string product_id;
  std::string product_name;
  std::string drive_model;
  DeviceType media_type = DeviceType::kUnknown;
  int bus_number = -1;
  int device_number = -1;
  uint64_t device_capacity = 0;
  uint64_t bytes_remaining = 0;
};

}  // namespace cros_disks

#endif  // CROS_DISKS_DISK_H_
