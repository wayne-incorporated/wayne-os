// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DLCSERVICE_LVM_LVM_UTILS_H_
#define DLCSERVICE_LVM_LVM_UTILS_H_

#include <string>

#include "dlcservice/boot/boot_slot.h"
#include "dlcservice/types.h"

namespace dlcservice {

// Takes a DLC ID and returns the logical volume name based on slot.
std::string LogicalVolumeName(const DlcId& id, BootSlotInterface::Slot slot);

}  // namespace dlcservice

#endif  // DLCSERVICE_LVM_LVM_UTILS_H_
