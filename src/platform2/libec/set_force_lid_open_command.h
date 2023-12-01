// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBEC_SET_FORCE_LID_OPEN_COMMAND_H_
#define LIBEC_SET_FORCE_LID_OPEN_COMMAND_H_

#include <brillo/brillo_export.h>
#include "libec/ec_command.h"

namespace ec {

class BRILLO_EXPORT SetForceLidOpenCommand
    : public EcCommand<struct ec_params_force_lid_open, EmptyParam> {
 public:
  explicit SetForceLidOpenCommand(uint8_t force_lid_open);
  ~SetForceLidOpenCommand() override = default;
};

static_assert(!std::is_copy_constructible<SetForceLidOpenCommand>::value,
              "EcCommands are not copyable by default");
static_assert(!std::is_copy_assignable<SetForceLidOpenCommand>::value,
              "EcCommands are not copy-assignable by default");

}  // namespace ec

#endif  // LIBEC_SET_FORCE_LID_OPEN_COMMAND_H_
