// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libec/get_mkbp_wake_mask_command.h"

namespace ec {

GetMkbpWakeMaskCommand::GetMkbpWakeMaskCommand(enum ec_mkbp_mask_type mask_type)
    : EcCommand(EC_CMD_MKBP_WAKE_MASK) {
  Req()->action = GET_WAKE_MASK;
  Req()->mask_type = mask_type;
}

uint32_t GetMkbpWakeMaskCommand::GetWakeMask() const {
  return Resp()->wake_mask;
}

GetMkbpWakeMaskHostEventCommand::GetMkbpWakeMaskHostEventCommand()
    : GetMkbpWakeMaskCommand(EC_MKBP_HOST_EVENT_WAKE_MASK) {}

bool GetMkbpWakeMaskHostEventCommand::IsEnabled(
    enum host_event_code event) const {
  return EC_HOST_EVENT_MASK(event) & Resp()->wake_mask;
}

GetMkbpWakeMaskEventCommand::GetMkbpWakeMaskEventCommand()
    : GetMkbpWakeMaskCommand(EC_MKBP_EVENT_WAKE_MASK) {}

bool GetMkbpWakeMaskEventCommand::IsEnabled(enum ec_mkbp_event event) const {
  // TODO(http://b/210128922): There should be a separate macro for
  //  "EC_MKBP_EVENT_MASK".
  return EC_HOST_EVENT_MASK(event) & Resp()->wake_mask;
}

}  // namespace ec
