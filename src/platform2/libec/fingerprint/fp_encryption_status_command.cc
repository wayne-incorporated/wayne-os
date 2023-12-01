// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <chromeos/ec/ec_commands.h>
#include <string>

#include "libec/ec_command.h"
#include "libec/fingerprint/fp_encryption_status_command.h"

namespace ec {

FpEncryptionStatusCommand::FpEncryptionStatusCommand()
    : EcCommand(EC_CMD_FP_ENC_STATUS) {}

std::string FpEncryptionStatusCommand::ParseFlags(uint32_t flags) {
  std::string output;
  if (flags & FP_ENC_STATUS_SEED_SET) {
    output += " FPTPM_seed_set";
  }
  return output;
}

uint32_t FpEncryptionStatusCommand::GetValidFlags() const {
  return Resp()->valid_flags;
}

uint32_t FpEncryptionStatusCommand::GetStatus() const {
  return Resp()->status;
}

}  // namespace ec
