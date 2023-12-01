// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libec/flash_protect_command_factory.h"

namespace ec {

std::unique_ptr<FlashProtectCommand> FlashProtectCommandFactory::Create(
    CrosFpDeviceInterface* cros_fp,
    flash_protect::Flags flags,
    flash_protect::Flags mask) {
  uint32_t version = 1;
  if (cros_fp->EcCmdVersionSupported(EC_CMD_FLASH_PROTECT, 2) ==
      EcCmdVersionSupportStatus::SUPPORTED) {
    version = 2;
  }
  return std::make_unique<ec::FlashProtectCommand>(flags, mask, version);
}

}  // namespace ec
