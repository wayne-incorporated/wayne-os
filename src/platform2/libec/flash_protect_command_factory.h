// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBEC_FLASH_PROTECT_COMMAND_FACTORY_H_
#define LIBEC_FLASH_PROTECT_COMMAND_FACTORY_H_

#include <memory>
#include <string>

#include "libec/fingerprint/cros_fp_device_interface.h"
#include "libec/flash_protect_command.h"

namespace ec {

class BRILLO_EXPORT FlashProtectCommandFactory {
 public:
  static std::unique_ptr<FlashProtectCommand> Create(
      CrosFpDeviceInterface* cros_fp,
      flash_protect::Flags flags,
      flash_protect::Flags mask);
};

}  // namespace ec

#endif  // LIBEC_FLASH_PROTECT_COMMAND_FACTORY_H_
