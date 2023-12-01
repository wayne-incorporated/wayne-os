// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBEC_FLASH_PROTECT_COMMAND_H_
#define LIBEC_FLASH_PROTECT_COMMAND_H_

#include <memory>
#include <string>

#include <brillo/brillo_export.h>
#include <brillo/enum_flags.h>
#include "libec/ec_command.h"
#include "libec/ec_command_async.h"

namespace ec {

namespace flash_protect {
enum class BRILLO_EXPORT Flags : uint32_t {
  kNone = 0,
  kRoAtBoot = EC_FLASH_PROTECT_RO_AT_BOOT,
  kRoNow = EC_FLASH_PROTECT_RO_NOW,
  kAllNow = EC_FLASH_PROTECT_ALL_NOW,
  kGpioAsserted = EC_FLASH_PROTECT_GPIO_ASSERTED,
  kErrorStuck = EC_FLASH_PROTECT_ERROR_STUCK,
  kErrorInconsistent = EC_FLASH_PROTECT_ERROR_INCONSISTENT,
  kAllAtBoot = EC_FLASH_PROTECT_ALL_AT_BOOT,
  kRwAtBoot = EC_FLASH_PROTECT_RW_AT_BOOT,
  kRwNow = EC_FLASH_PROTECT_RW_NOW,
  kRollbackAtBoot = EC_FLASH_PROTECT_ROLLBACK_AT_BOOT,
  kRollbackNow = EC_FLASH_PROTECT_ROLLBACK_NOW,
  kErrorUnknown = EC_FLASH_PROTECT_ERROR_UNKNOWN
};
DECLARE_FLAGS_ENUM(Flags);
BRILLO_EXPORT std::ostream& operator<<(std::ostream& os,
                                       flash_protect::Flags r);
}  // namespace flash_protect

class BRILLO_EXPORT FlashProtectCommand_v1
    : public EcCommand<struct ec_params_flash_protect,
                       struct ec_response_flash_protect> {
 public:
  FlashProtectCommand_v1(flash_protect::Flags flags, flash_protect::Flags mask);
  ~FlashProtectCommand_v1() override = default;

  flash_protect::Flags GetFlags() const;
  flash_protect::Flags GetValidFlags() const;
  flash_protect::Flags GetWritableFlags() const;
};

class BRILLO_EXPORT FlashProtectCommand_v2
    : public EcCommandAsync<struct ec_params_flash_protect_v2,
                            struct ec_response_flash_protect> {
 public:
  FlashProtectCommand_v2(flash_protect::Flags flags, flash_protect::Flags mask);
  ~FlashProtectCommand_v2() override = default;

  flash_protect::Flags GetFlags() const;
  flash_protect::Flags GetValidFlags() const;
  flash_protect::Flags GetWritableFlags() const;
};

class BRILLO_EXPORT FlashProtectCommand : public EcCommandInterface {
 public:
  FlashProtectCommand(flash_protect::Flags flags,
                      flash_protect::Flags mask,
                      uint32_t version)
      : command_version(version) {
    CHECK_GT(version, 0);
    CHECK_LE(version, 2);
    if (version == 2) {
      flash_protect_command_v2_ =
          std::make_unique<FlashProtectCommand_v2>(flags, mask);
    } else {
      flash_protect_command_v1_ =
          std::make_unique<FlashProtectCommand_v1>(flags, mask);
    }
  }

  bool Run(int ec_fd) override;
  bool Run(ec::EcUsbEndpointInterface& uep) override;
  bool RunWithMultipleAttempts(int fd, int num_attempts) override;
  uint32_t Version() const override;
  uint32_t Command() const override;

  uint32_t GetVersion() const;

  static std::string ParseFlags(flash_protect::Flags flags);

  flash_protect::Flags GetFlags() const;
  flash_protect::Flags GetValidFlags() const;
  flash_protect::Flags GetWritableFlags() const;

 private:
  std::unique_ptr<FlashProtectCommand_v1> flash_protect_command_v1_ = nullptr;
  std::unique_ptr<FlashProtectCommand_v2> flash_protect_command_v2_ = nullptr;
  uint32_t command_version;
};

}  // namespace ec

#endif  // LIBEC_FLASH_PROTECT_COMMAND_H_
