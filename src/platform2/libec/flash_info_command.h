// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBEC_FLASH_INFO_COMMAND_H_
#define LIBEC_FLASH_INFO_COMMAND_H_

#include <optional>

#include <brillo/brillo_export.h>

#include "libec/ec_command.h"
#include "libec/flash_info_params.h"

namespace ec {

class BRILLO_EXPORT FlashInfoCommand_v0
    : public EcCommand<EmptyParam, struct ec_response_flash_info> {
 public:
  FlashInfoCommand_v0();
  ~FlashInfoCommand_v0() override = default;

  uint32_t GetFlashSize() const;
  uint32_t GetWriteBlockSize() const;
  uint32_t GetEraseBlockSize() const;
  uint32_t GetProtectBlockSize() const;
};

class BRILLO_EXPORT FlashInfoCommand_v1
    : public EcCommand<EmptyParam, struct ec_response_flash_info_1> {
 public:
  FlashInfoCommand_v1();
  ~FlashInfoCommand_v1() override = default;

  uint32_t GetFlashSize() const;
  uint32_t GetWriteBlockSize() const;
  uint32_t GetEraseBlockSize() const;
  uint32_t GetProtectBlockSize() const;
  uint32_t GetIdealWriteSize() const;

  bool FlashErasesToZero() const;
  bool FlashSelectRequired() const;
};

class BRILLO_EXPORT FlashInfoCommand_v2
    : public EcCommand<struct ec_params_flash_info_2, flash_info::Params_v2> {
 public:
  FlashInfoCommand_v2();
  ~FlashInfoCommand_v2() override = default;

  bool Run(int fd) override;

  uint32_t GetFlashSize() const;
  uint32_t GetIdealWriteSize() const;
  uint32_t GetTotalNumBanks() const;
  std::optional<struct ec_flash_bank> GetBankDescription(
      unsigned int bank) const;

  bool FlashErasesToZero() const;
  bool FlashSelectRequired() const;

 protected:
  virtual bool EcCommandRun(int fd);
};

}  // namespace ec

#endif  // LIBEC_FLASH_INFO_COMMAND_H_
