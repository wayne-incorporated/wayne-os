// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "dlcservice/boot/boot_slot.h"

#include <climits>
#include <utility>

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>

#include "dlcservice/boot/boot_device.h"
#include "dlcservice/utils.h"

using std::string;
using std::unique_ptr;

namespace dlcservice {

BootSlot::BootSlot(unique_ptr<BootDeviceInterface> boot_device)
    : boot_device_(std::move(boot_device)) {}

bool BootSlot::Init() {
  device_path_ = boot_device_->GetBootDevice();
  if (device_path_.empty()) {
    LOG(ERROR) << "Failed to get boot device path.";
    return false;
  }
  if (!SplitPartitionName(device_path_.value(), &device_name_,
                          &partition_num_)) {
    LOG(ERROR) << "Failed to split boot device into name and partition num.";
    return false;
  }
  is_removable_ = boot_device_->IsRemovableDevice(device_name_);

  // Search through the slots to see which slot has the `partition_num_` we
  // booted from.
  // In Chrome OS, the ROOT partitions are hard coded to 3 (A) or 5 (B).
  // See http://www.chromium.org/chromium-os/chromiumos-design-docs/disk-format
  switch (partition_num_) {
    case 3:  // ROOT-A
      slot_ = Slot::A;
      return true;
    case 5:  // ROOT-B
      slot_ = Slot::B;
      return true;
    default:
      LOG(ERROR) << "Couldn't find the slot number corresponding to the "
                    "partition "
                 << device_path_.value();
      return false;
  }
}

bool BootSlot::IsDeviceRemovable() {
  return is_removable_;
}

std::string BootSlot::GetDeviceName() {
  return device_name_;
}

BootSlot::Slot BootSlot::GetSlot() {
  return slot_;
}

base::FilePath BootSlot::GetStatefulPartitionPath() {
  // Stateful is always partition number 1 in CrOS.
  return base::FilePath{JoinPartitionName(device_name_, 1)};
}

// static
string BootSlot::ToString(BootSlot::Slot slot) {
  return slot == BootSlot::Slot::A ? kDlcDirAName : kDlcDirBName;
}

}  // namespace dlcservice
