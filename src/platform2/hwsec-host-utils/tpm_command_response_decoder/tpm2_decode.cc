// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "hwsec-host-utils/tpm_command_response_decoder/tpm2_decode.h"

#include <cstdint>
#include <string>

#include <absl/strings/str_format.h>
#include <trunks/command_codes.h>
#include <trunks/error_codes.h>

namespace hwsec_host_utils {

std::string DecodeTpm2CommandResponse(uint32_t cc, uint32_t rc) {
  std::string command = trunks::GetCommandString(cc);
  std::string response = trunks::GetErrorString(rc);
  return command + ": " + response;
}

}  // namespace hwsec_host_utils
