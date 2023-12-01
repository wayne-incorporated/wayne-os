// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBEC_FLASH_SPI_INFO_COMMAND_H_
#define LIBEC_FLASH_SPI_INFO_COMMAND_H_

#include <brillo/brillo_export.h>
#include "libec/ec_command.h"

namespace ec {

class BRILLO_EXPORT FlashSpiInfoCommand
    : public EcCommand<EmptyParam, struct ec_response_flash_spi_info> {
 public:
  FlashSpiInfoCommand();
  ~FlashSpiInfoCommand() override = default;

  uint8_t GetJedecManufacturer() const;
  uint16_t GetJedecDeviceId() const;
  uint32_t GetJedecCapacity() const;
  uint8_t GetManufacturerId() const;
  uint8_t GetDeviceId() const;
  uint8_t GetStatusRegister1() const;
  uint8_t GetStatusRegister2() const;
};

static_assert(!std::is_copy_constructible<FlashSpiInfoCommand>::value,
              "EcCommands are not copyable by default");
static_assert(!std::is_copy_assignable<FlashSpiInfoCommand>::value,
              "EcCommands are not copy-assignable by default");

}  // namespace ec

#endif  // LIBEC_FLASH_SPI_INFO_COMMAND_H_
