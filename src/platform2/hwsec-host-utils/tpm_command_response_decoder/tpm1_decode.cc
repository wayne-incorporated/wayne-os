// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "hwsec-host-utils/tpm_command_response_decoder/tpm1_decode.h"

#include <cstdint>
#include <string>

#include <absl/strings/str_format.h>
#include <trousers/trousers.h>

namespace hwsec_host_utils {

std::string DecodeTpm1CommandResponse(uint32_t cc, uint32_t rc) {
  std::string command;
  const char* command_ptr = Trspi_Ordinal_String(cc);
  if (command_ptr) {
    command = std::string(command_ptr);
  } else {
    command = absl::StrFormat("Unknown TCSD_ORD 0x%04x", cc);
  }
  std::string response;
  const char* response_ptr = Trspi_Error_Code_String(rc);
  if (response_ptr) {
    std::string layer = Trspi_Error_Layer(rc);
    response = layer + ": " + response_ptr;
  } else {
    response = absl::StrFormat("Unknown TSS_RESULT 0x%04x", rc);
  }

  return command + ": " + response;
}

}  // namespace hwsec_host_utils
