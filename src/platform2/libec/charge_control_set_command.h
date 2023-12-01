// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBEC_CHARGE_CONTROL_SET_COMMAND_H_
#define LIBEC_CHARGE_CONTROL_SET_COMMAND_H_

#include <brillo/brillo_export.h>
#include "libec/ec_command.h"

namespace ec {

class BRILLO_EXPORT ChargeControlSetCommand
    : public EcCommand<struct ec_params_charge_control, EmptyParam> {
 public:
  // Default args create a basic set command for default charging state.
  explicit ChargeControlSetCommand(uint32_t mode = CHARGE_CONTROL_NORMAL,
                                   uint8_t lower = -1,
                                   uint8_t upper = -1)
      : EcCommand(EC_CMD_CHARGE_CONTROL, 2) {
    Req()->cmd = EC_CHARGE_CONTROL_CMD_SET;
    Req()->mode = mode;
    Req()->sustain_soc.lower = lower;
    Req()->sustain_soc.upper = upper;
  }
  ~ChargeControlSetCommand() override = default;
};

static_assert(!std::is_copy_constructible<ChargeControlSetCommand>::value,
              "EcCommands are not copyable by default");
static_assert(!std::is_copy_assignable<ChargeControlSetCommand>::value,
              "EcCommands are not copy-assignable by default");

}  // namespace ec

#endif  // LIBEC_CHARGE_CONTROL_SET_COMMAND_H_
