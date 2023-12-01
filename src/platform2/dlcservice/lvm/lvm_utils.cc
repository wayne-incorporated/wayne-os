// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "dlcservice/lvm/lvm_utils.h"

namespace dlcservice {

constexpr char kDlcLogicalVolumePrefix[] = "dlc_";
constexpr char kDlcSlotA[] = "_a";
constexpr char kDlcSlotB[] = "_b";

std::string LogicalVolumeName(const DlcId& id, BootSlotInterface::Slot slot) {
  static const std::string& kPrefix(kDlcLogicalVolumePrefix);
  switch (slot) {
    case BootSlotInterface::Slot::A:
      return kPrefix + id + kDlcSlotA;
    case BootSlotInterface::Slot::B:
      return kPrefix + id + kDlcSlotB;
  }
}

}  // namespace dlcservice
