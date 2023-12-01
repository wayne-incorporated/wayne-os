// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libec/fingerprint/fp_seed_command.h"

namespace ec {

FpSeedCommand::~FpSeedCommand() {
  ClearSeedBuffer();
}

bool FpSeedCommand::Run(int fd) {
  bool ret = EcCommandRun(fd);

  // Clear intermediate buffers throughout the stack. We expect running the
  // command to fail since the SBP will reject the new seed.
  ClearSeedBuffer();
  EcCommandRun(fd);

  return ret;
}

void FpSeedCommand::ClearSeedBuffer() {
  brillo::SecureClearContainer(Req()->seed);
}

bool FpSeedCommand::EcCommandRun(int fd) {
  return EcCommand::Run(fd);
}

}  // namespace ec
