// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBBRILLO_BRILLO_BLKDEV_UTILS_GET_BACKING_BLOCK_DEVICE_H_
#define LIBBRILLO_BRILLO_BLKDEV_UTILS_GET_BACKING_BLOCK_DEVICE_H_

#include <memory>
#include <string>

#include <base/files/file_path.h>
#include <brillo/brillo_export.h>
#include <brillo/udev/udev.h>

namespace brillo {

// Finds physical backing device for a block device. Traverses DM indirection.
//
// dev_node - path to the device in devfs.
// search_path - alternative /sys/block location for testing.
BRILLO_EXPORT base::FilePath GetBackingPhysicalDeviceForBlock(
    const base::FilePath& dev_node, const std::string& search_path = "");

// Finds physical backing device for a block device. Traverses DM indirection.
//
// devnum - device number.
// search_path - alternative /sys/block location for testing.
// udev - udev dependency injection for testing.
BRILLO_EXPORT base::FilePath GetBackingPhysicalDeviceForBlock(
    dev_t devnum,
    const std::string& search_path = "",
    std::unique_ptr<Udev> udev = Udev::Create());

// Finds physical backing device for a file. Traverses DM indirection.
//
// path - path to the file.
BRILLO_EXPORT base::FilePath GetBackingPhysicalDeviceForFile(
    const base::FilePath& path);

// Finds logical backing device for a file. Logical backing device can be a
// partition or a logical volume.
BRILLO_EXPORT base::FilePath GetBackingLogicalDeviceForFile(
    const base::FilePath& path);

}  // namespace brillo

#endif  // LIBBRILLO_BRILLO_BLKDEV_UTILS_GET_BACKING_BLOCK_DEVICE_H_
