// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libec/flash_spi_info_command.h"

namespace ec {

FlashSpiInfoCommand::FlashSpiInfoCommand() : EcCommand(EC_CMD_FLASH_SPI_INFO) {}

uint8_t FlashSpiInfoCommand::GetJedecManufacturer() const {
  return Resp()->jedec[0];
}

uint16_t FlashSpiInfoCommand::GetJedecDeviceId() const {
  return Resp()->jedec[1] << 8 | Resp()->jedec[2];
}

uint32_t FlashSpiInfoCommand::GetJedecCapacity() const {
  return BIT(Resp()->jedec[2]);
}

uint8_t FlashSpiInfoCommand::GetManufacturerId() const {
  return Resp()->mfr_dev_id[0];
}

uint8_t FlashSpiInfoCommand::GetDeviceId() const {
  return Resp()->mfr_dev_id[1];
}

uint8_t FlashSpiInfoCommand::GetStatusRegister1() const {
  return Resp()->sr1;
}

uint8_t FlashSpiInfoCommand::GetStatusRegister2() const {
  return Resp()->sr2;
}

}  // namespace ec
