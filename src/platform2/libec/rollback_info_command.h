// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBEC_ROLLBACK_INFO_COMMAND_H_
#define LIBEC_ROLLBACK_INFO_COMMAND_H_

#include <brillo/brillo_export.h>
#include "libec/ec_command.h"

namespace ec {

class BRILLO_EXPORT RollbackInfoCommand
    : public EcCommand<EmptyParam, struct ec_response_rollback_info> {
 public:
  RollbackInfoCommand() : EcCommand(EC_CMD_ROLLBACK_INFO) {}
  ~RollbackInfoCommand() override = default;

  int32_t ID() const;
  int32_t MinVersion() const;
  int32_t RWVersion() const;
};

static_assert(!std::is_copy_constructible<RollbackInfoCommand>::value,
              "EcCommands are not copyable by default");
static_assert(!std::is_copy_assignable<RollbackInfoCommand>::value,
              "EcCommands are not copy-assignable by default");

}  // namespace ec

#endif  // LIBEC_ROLLBACK_INFO_COMMAND_H_
