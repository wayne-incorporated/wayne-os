// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libec/set_mkbp_wake_mask_command.h"

namespace ec {

SetMkbpWakeMaskCommand::SetMkbpWakeMaskCommand(enum ec_mkbp_mask_type mask_type,
                                               uint32_t new_wake_mask)
    : EcCommand(EC_CMD_MKBP_WAKE_MASK) {
  Req()->action = SET_WAKE_MASK;
  Req()->mask_type = mask_type;
  Req()->new_wake_mask = new_wake_mask;
}

SetMkbpWakeMaskHostEventCommand::SetMkbpWakeMaskHostEventCommand(
    uint32_t new_wake_mask)
    : SetMkbpWakeMaskCommand(EC_MKBP_HOST_EVENT_WAKE_MASK, new_wake_mask) {}

SetMkbpWakeMaskEventCommand::SetMkbpWakeMaskEventCommand(uint32_t new_wake_mask)
    : SetMkbpWakeMaskCommand(EC_MKBP_EVENT_WAKE_MASK, new_wake_mask) {}

}  // namespace ec
