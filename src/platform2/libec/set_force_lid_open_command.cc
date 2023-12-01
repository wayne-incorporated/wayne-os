// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libec/set_force_lid_open_command.h"

namespace ec {

SetForceLidOpenCommand::SetForceLidOpenCommand(uint8_t force_lid_open)
    : EcCommand(EC_CMD_FORCE_LID_OPEN) {
  Req()->enabled = force_lid_open;
}

}  // namespace ec
