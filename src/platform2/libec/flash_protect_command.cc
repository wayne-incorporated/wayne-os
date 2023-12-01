// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <base/stl_util.h>
#include <chromeos/ec/ec_commands.h>

#include "libec/ec_command.h"
#include "libec/flash_protect_command.h"

namespace ec {

namespace flash_protect {
std::ostream& operator<<(std::ostream& os, flash_protect::Flags r) {
  os << base::to_underlying(r);
  return os;
}
}  // namespace flash_protect

FlashProtectCommand_v1::FlashProtectCommand_v1(flash_protect::Flags flags,
                                               flash_protect::Flags mask)
    : EcCommand(EC_CMD_FLASH_PROTECT, EC_VER_FLASH_PROTECT) {
  Req()->flags = base::to_underlying(flags);
  Req()->mask = base::to_underlying(mask);
}

/**
 * @return string names of set flags
 */
std::string FlashProtectCommand::ParseFlags(flash_protect::Flags flags) {
  std::string output;
  if ((flags & flash_protect::Flags::kGpioAsserted) !=
      flash_protect::Flags::kNone) {
    output += " wp_gpio_asserted";
  }
  if ((flags & flash_protect::Flags::kRoAtBoot) !=
      flash_protect::Flags::kNone) {
    output += " ro_at_boot";
  }
  if ((flags & flash_protect::Flags::kRwAtBoot) !=
      flash_protect::Flags::kNone) {
    output += " rw_at_boot";
  }
  if ((flags & flash_protect::Flags::kRollbackAtBoot) !=
      flash_protect::Flags::kNone) {
    output += " rollback_at_boot";
  }
  if ((flags & flash_protect::Flags::kAllAtBoot) !=
      flash_protect::Flags::kNone) {
    output += " all_at_boot";
  }
  if ((flags & flash_protect::Flags::kRoNow) != flash_protect::Flags::kNone) {
    output += " ro_now";
  }
  if ((flags & flash_protect::Flags::kRwNow) != flash_protect::Flags::kNone) {
    output += " rw_now";
  }
  if ((flags & flash_protect::Flags::kRollbackNow) !=
      flash_protect::Flags::kNone) {
    output += " rollback_now";
  }
  if ((flags & flash_protect::Flags::kAllNow) != flash_protect::Flags::kNone) {
    output += " all_now";
  }
  if ((flags & flash_protect::Flags::kErrorStuck) !=
      flash_protect::Flags::kNone) {
    output += " STUCK";
  }
  if ((flags & flash_protect::Flags::kErrorInconsistent) !=
      flash_protect::Flags::kNone) {
    output += " INCONSISTENT";
  }
  if ((flags & flash_protect::Flags::kErrorUnknown) !=
      flash_protect::Flags::kNone) {
    output += " UNKNOWN_ERROR";
  }
  return output;
}

flash_protect::Flags FlashProtectCommand_v1::GetFlags() const {
  return static_cast<flash_protect::Flags>(Resp()->flags);
}

flash_protect::Flags FlashProtectCommand_v1::GetValidFlags() const {
  return static_cast<flash_protect::Flags>(Resp()->valid_flags);
}

flash_protect::Flags FlashProtectCommand_v1::GetWritableFlags() const {
  return static_cast<flash_protect::Flags>(Resp()->writable_flags);
}

flash_protect::Flags FlashProtectCommand_v2::GetFlags() const {
  return static_cast<flash_protect::Flags>(Resp()->flags);
}

FlashProtectCommand_v2::FlashProtectCommand_v2(flash_protect::Flags flags,
                                               flash_protect::Flags mask)
    : EcCommandAsync(EC_CMD_FLASH_PROTECT,
                     FLASH_PROTECT_GET_RESULT,
                     {.poll_for_result_num_attempts = 20,
                      .poll_interval = base::Milliseconds(100),
                      // The EC temporarily stops responding to EC commands
                      // when this command is run, so we will keep trying until
                      // we get success (or time out).
                      .validate_poll_result = false},
                     2) {
  Req()->action = FLASH_PROTECT_ASYNC;
  Req()->flags = base::to_underlying(flags);
  Req()->mask = base::to_underlying(mask);
}

flash_protect::Flags FlashProtectCommand_v2::GetValidFlags() const {
  return static_cast<flash_protect::Flags>(Resp()->valid_flags);
}

flash_protect::Flags FlashProtectCommand_v2::GetWritableFlags() const {
  return static_cast<flash_protect::Flags>(Resp()->writable_flags);
}

uint32_t FlashProtectCommand::GetVersion() const {
  return command_version;
}

flash_protect::Flags FlashProtectCommand::GetFlags() const {
  if (GetVersion() == 2)
    return flash_protect_command_v2_->GetFlags();
  return flash_protect_command_v1_->GetFlags();
}

flash_protect::Flags FlashProtectCommand::GetValidFlags() const {
  if (GetVersion() == 2)
    return flash_protect_command_v2_->GetValidFlags();
  return flash_protect_command_v1_->GetValidFlags();
}

flash_protect::Flags FlashProtectCommand::GetWritableFlags() const {
  if (GetVersion() == 2)
    return flash_protect_command_v2_->GetWritableFlags();
  return flash_protect_command_v1_->GetWritableFlags();
}

bool FlashProtectCommand::Run(int ec_fd) {
  if (GetVersion() == 2)
    return flash_protect_command_v2_->Run(ec_fd);
  return flash_protect_command_v1_->Run(ec_fd);
}

bool FlashProtectCommand::Run(ec::EcUsbEndpointInterface& uep) {
  if (GetVersion() == 2)
    // TODO(b/286262144): Create an implementation for
    // Run(ec::EcUsbEndpointInterface& uep) in EcCommandAsync.h.
    return false;
  return flash_protect_command_v1_->Run(uep);
}

bool FlashProtectCommand::RunWithMultipleAttempts(int fd, int num_attempts) {
  if (GetVersion() == 2)
    return flash_protect_command_v2_->RunWithMultipleAttempts(fd, num_attempts);
  return flash_protect_command_v1_->RunWithMultipleAttempts(fd, num_attempts);
}

uint32_t FlashProtectCommand::Version() const {
  if (GetVersion() == 2)
    return flash_protect_command_v2_->Version();
  return flash_protect_command_v1_->Version();
}

uint32_t FlashProtectCommand::Command() const {
  if (GetVersion() == 2)
    return flash_protect_command_v2_->Command();
  return flash_protect_command_v1_->Command();
}

}  // namespace ec
