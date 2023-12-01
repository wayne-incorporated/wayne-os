// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBEC_CHARGE_CURRENT_LIMIT_SET_COMMAND_H_
#define LIBEC_CHARGE_CURRENT_LIMIT_SET_COMMAND_H_

#include <brillo/brillo_export.h>

#include "libec/ec_command.h"

namespace ec {

class BRILLO_EXPORT ChargeCurrentLimitSetCommand
    : public EcCommand<struct ec_params_current_limit, EmptyParam> {
 public:
  // Request the EC apply a maximum charge limit, measured in milliamps.
  // A value of UINT32_MAX indicates "no limit".
  explicit ChargeCurrentLimitSetCommand(uint32_t limit_mA);
  ~ChargeCurrentLimitSetCommand() override = default;
};

static_assert(!std::is_copy_constructible<ChargeCurrentLimitSetCommand>::value,
              "EcCommands are not copyable by default");
static_assert(!std::is_copy_assignable<ChargeCurrentLimitSetCommand>::value,
              "EcCommands are not copy-assignable by default");

}  // namespace ec

#endif  // LIBEC_CHARGE_CURRENT_LIMIT_SET_COMMAND_H_
