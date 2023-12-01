// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TPM2_SIMULATOR_TPM_COMMAND_UTILS_H_
#define TPM2_SIMULATOR_TPM_COMMAND_UTILS_H_

#include <string>

namespace tpm2_simulator {

struct CommandHeader {
  uint16_t tag;
  uint32_t size;
  uint32_t code;
} __attribute__((packed));

bool ExtractCommandSize(const std::string& command, uint32_t* size);

bool ExtractCommandHeader(const std::string& command, CommandHeader* header);

std::string CreateCommandWithCode(uint32_t code);

}  // namespace tpm2_simulator

#endif  // TPM2_SIMULATOR_TPM_COMMAND_UTILS_H_
