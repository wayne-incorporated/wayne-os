// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libec/charge_current_limit_set_command.h"

namespace ec {

ChargeCurrentLimitSetCommand::ChargeCurrentLimitSetCommand(uint32_t limit_mA)
    : EcCommand(EC_CMD_CHARGE_CURRENT_LIMIT) {
  Req()->limit = limit_mA;
}

}  // namespace ec
