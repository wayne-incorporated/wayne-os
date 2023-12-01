// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libec/get_comms_status_command.h"

namespace ec {

GetCommsStatusCommand::GetCommsStatusCommand()
    : EcCommand(EC_CMD_GET_COMMS_STATUS) {}

bool GetCommsStatusCommand::IsProcessing() const {
  return Resp()->flags & ec_comms_status::EC_COMMS_STATUS_PROCESSING;
}

}  // namespace ec
