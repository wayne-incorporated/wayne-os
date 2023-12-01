// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <string>

#include <base/logging.h>
#include <base/sys_byteorder.h>

#include "tpm2-simulator/tpm_command_utils.h"

namespace {

constexpr size_t kHeaderSize = 10;
static_assert(kHeaderSize == sizeof(tpm2_simulator::CommandHeader));

struct CommandPartialHeader {
  uint16_t tag;
  uint32_t size;
} __attribute__((packed));

constexpr size_t kPartialHeaderSize = 6;
static_assert(kPartialHeaderSize == sizeof(CommandPartialHeader));

constexpr uint32_t kTpmNoSessionTag = 0x8001;

}  // namespace

namespace tpm2_simulator {

bool ExtractCommandSize(const std::string& command, uint32_t* size) {
  if (command.size() < kPartialHeaderSize) {
    return false;
  }

  const CommandPartialHeader* input_header =
      reinterpret_cast<const CommandPartialHeader*>(command.data());

  *size = base::NetToHost32(input_header->size);
  return true;
}

bool ExtractCommandHeader(const std::string& command, CommandHeader* header) {
  if (command.size() < kHeaderSize) {
    LOG(ERROR) << "Command too small.";
    return false;
  }

  const CommandHeader* input_header =
      reinterpret_cast<const CommandHeader*>(command.data());

  header->tag = base::NetToHost16(input_header->tag);
  header->size = base::NetToHost32(input_header->size);
  header->code = base::NetToHost32(input_header->code);
  return true;
}

std::string CreateCommandWithCode(uint32_t code) {
  std::string response;
  response.resize(kHeaderSize);

  CommandHeader* header = reinterpret_cast<CommandHeader*>(response.data());
  header->tag = base::HostToNet16(kTpmNoSessionTag);
  header->size = base::HostToNet32(kHeaderSize);
  header->code = base::HostToNet32(code);
  return response;
}

}  // namespace tpm2_simulator
