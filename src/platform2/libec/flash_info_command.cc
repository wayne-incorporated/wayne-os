// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libec/ec_command.h"
#include "libec/flash_info_command.h"

namespace ec {

ec::FlashInfoCommand_v0::FlashInfoCommand_v0()
    : EcCommand(EC_CMD_FLASH_INFO, 0) {}

uint32_t FlashInfoCommand_v0::GetFlashSize() const {
  return Resp()->flash_size;
}

uint32_t FlashInfoCommand_v0::GetWriteBlockSize() const {
  return Resp()->write_block_size;
}

uint32_t FlashInfoCommand_v0::GetEraseBlockSize() const {
  return Resp()->erase_block_size;
}

uint32_t FlashInfoCommand_v0::GetProtectBlockSize() const {
  return Resp()->protect_block_size;
}

FlashInfoCommand_v1::FlashInfoCommand_v1() : EcCommand(EC_CMD_FLASH_INFO, 1) {}

uint32_t FlashInfoCommand_v1::GetFlashSize() const {
  return Resp()->flash_size;
}

uint32_t FlashInfoCommand_v1::GetWriteBlockSize() const {
  return Resp()->write_block_size;
}

uint32_t FlashInfoCommand_v1::GetEraseBlockSize() const {
  return Resp()->erase_block_size;
}

uint32_t FlashInfoCommand_v1::GetProtectBlockSize() const {
  return Resp()->protect_block_size;
}

uint32_t FlashInfoCommand_v1::GetIdealWriteSize() const {
  return Resp()->write_ideal_size;
}

bool FlashInfoCommand_v1::FlashErasesToZero() const {
  return Resp()->flags & EC_FLASH_INFO_ERASE_TO_0;
}

bool FlashInfoCommand_v1::FlashSelectRequired() const {
  return Resp()->flags & EC_FLASH_INFO_SELECT_REQUIRED;
}

FlashInfoCommand_v2::FlashInfoCommand_v2() : EcCommand(EC_CMD_FLASH_INFO, 2) {
  Req()->num_banks_desc = 0;
  SetRespSize(sizeof(struct ec_response_flash_info_2));
}

uint32_t FlashInfoCommand_v2::GetFlashSize() const {
  return Resp()->info.flash_size;
}

uint32_t FlashInfoCommand_v2::GetIdealWriteSize() const {
  return Resp()->info.write_ideal_size;
}

uint32_t FlashInfoCommand_v2::GetTotalNumBanks() const {
  return Resp()->info.num_banks_total;
}

std::optional<struct ec_flash_bank> FlashInfoCommand_v2::GetBankDescription(
    unsigned int bank) const {
  if (bank >= Resp()->info.num_banks_desc) {
    return std::nullopt;
  }
  return Resp()->banks[bank];
}

bool FlashInfoCommand_v2::FlashErasesToZero() const {
  return Resp()->info.flags & EC_FLASH_INFO_ERASE_TO_0;
}

bool FlashInfoCommand_v2::FlashSelectRequired() const {
  return Resp()->info.flags & EC_FLASH_INFO_SELECT_REQUIRED;
}

bool FlashInfoCommand_v2::Run(int fd) {
  // Run once to get the total number of banks, but no descriptions.
  if (!EcCommandRun(fd)) {
    return false;
  }

  // We now know the number of banks, so we can request descriptions for them.
  Req()->num_banks_desc = Resp()->info.num_banks_total;
  SetRespSize(sizeof(struct ec_response_flash_info_2) +
              sizeof(struct ec_flash_bank) * Req()->num_banks_desc);

  if (!EcCommandRun(fd)) {
    return false;
  }

  return true;
}

bool FlashInfoCommand_v2::EcCommandRun(int fd) {
  return EcCommand::Run(fd);
}

}  // namespace ec
