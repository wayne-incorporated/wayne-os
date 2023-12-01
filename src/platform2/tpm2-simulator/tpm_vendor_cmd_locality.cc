// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <string>

#include "tpm2-simulator/tpm_command_utils.h"
#include "tpm2-simulator/tpm_vendor_cmd_locality.h"

namespace {
const uint32_t kTpmCcSetLocality = 0x20001000;
}  // namespace

namespace tpm2_simulator {

bool TpmVendorCommandLocality::Init() {
  return true;
}

bool TpmVendorCommandLocality::IsVendorCommand(const std::string& command) {
  CommandHeader header;
  if (!ExtractCommandHeader(command, &header)) {
    return false;
  }
  return header.code == kTpmCcSetLocality;
}

std::string TpmVendorCommandLocality::RunCommand(const std::string& command) {
  // Do nothing.
  return CreateCommandWithCode(0);
}

}  // namespace tpm2_simulator
