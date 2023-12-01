// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libec/reboot_ec_command.h"

namespace ec {

RebootEcCommand::RebootEcCommand(enum ec_reboot_cmd cmd,
                                 enum reboot_ec::flags flags)
    : EcCommand(EC_CMD_REBOOT_EC) {
  Req()->cmd = cmd;
  Req()->flags = flags;
}

}  // namespace ec
