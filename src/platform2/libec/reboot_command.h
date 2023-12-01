// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBEC_REBOOT_COMMAND_H_
#define LIBEC_REBOOT_COMMAND_H_

#include <brillo/brillo_export.h>
#include "libec/ec_command.h"

namespace ec {

class BRILLO_EXPORT RebootCommand : public EcCommand<EmptyParam, EmptyParam> {
 public:
  RebootCommand() : EcCommand(EC_CMD_REBOOT) {}
  ~RebootCommand() override = default;
};

static_assert(!std::is_copy_constructible<RebootCommand>::value,
              "EcCommands are not copyable by default");
static_assert(!std::is_copy_assignable<RebootCommand>::value,
              "EcCommands are not copy-assignable by default");

}  // namespace ec

#endif  // LIBEC_REBOOT_COMMAND_H_
