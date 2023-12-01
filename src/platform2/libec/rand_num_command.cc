// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <chromeos/ec/ec_commands.h>

#include "libec/ec_command.h"
#include "libec/rand_num_command.h"

namespace ec {

RandNumCommand::RandNumCommand(uint16_t num_rand_bytes)
    : EcCommand(EC_CMD_RAND_NUM, EC_VER_RAND_NUM) {
  Req()->num_rand_bytes = num_rand_bytes;
}

rand::RandNumData RandNumCommand::GetRandNumData() const {
  return Resp()->rand_num_data;
}

}  // namespace ec
