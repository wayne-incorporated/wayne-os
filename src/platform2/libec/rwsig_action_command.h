// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBEC_RWSIG_ACTION_COMMAND_H_
#define LIBEC_RWSIG_ACTION_COMMAND_H_

#include <brillo/brillo_export.h>
#include "libec/ec_command.h"

namespace ec {

class BRILLO_EXPORT RWSigActionCommand
    : public EcCommand<struct ec_params_rwsig_action, EmptyParam> {
 public:
  explicit RWSigActionCommand(enum rwsig_action action)
      : EcCommand(EC_CMD_RWSIG_ACTION) {
    Req()->action = action;
  }
  ~RWSigActionCommand() override = default;
};

static_assert(!std::is_copy_constructible<RWSigActionCommand>::value,
              "EcCommands are not copyable by default");
static_assert(!std::is_copy_assignable<RWSigActionCommand>::value,
              "EcCommands are not copy-assignable by default");

}  // namespace ec

#endif  // LIBEC_RWSIG_ACTION_COMMAND_H_
