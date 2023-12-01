// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBEC_REBOOT_EC_COMMAND_H_
#define LIBEC_REBOOT_EC_COMMAND_H_

#include <brillo/brillo_export.h>
#include <brillo/enum_flags.h>

#include "libec/ec_command.h"

namespace ec {

namespace reboot_ec {
enum BRILLO_EXPORT flags {
  kReserved0 = EC_REBOOT_FLAG_RESERVED0,
  kOnApShutdown = EC_REBOOT_FLAG_ON_AP_SHUTDOWN,
  kSwitchRwSlot = EC_REBOOT_FLAG_SWITCH_RW_SLOT,
  kClearApIdle = EC_REBOOT_FLAG_CLEAR_AP_IDLE
};
DECLARE_FLAGS_ENUM(flags);
}  // namespace reboot_ec

// TODO(b/35528173): Rename this command when underlying EC_CMD_REBOOT_EC
// command is renamed.
class BRILLO_EXPORT RebootEcCommand
    : public EcCommand<struct ec_params_reboot_ec, EmptyParam> {
 public:
  RebootEcCommand(enum ec_reboot_cmd cmd, enum reboot_ec::flags flags);
  ~RebootEcCommand() override = default;
};

static_assert(!std::is_copy_constructible<RebootEcCommand>::value,
              "EcCommands are not copyable by default");
static_assert(!std::is_copy_assignable<RebootEcCommand>::value,
              "EcCommands are not copy-assignable by default");

}  // namespace ec

#endif  // LIBEC_REBOOT_EC_COMMAND_H_
