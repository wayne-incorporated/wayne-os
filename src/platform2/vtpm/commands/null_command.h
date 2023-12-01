// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VTPM_COMMANDS_NULL_COMMAND_H_
#define VTPM_COMMANDS_NULL_COMMAND_H_

#include "vtpm/commands/command.h"

#include <string>

#include <base/functional/callback.h>

namespace vtpm {

// A null implementation of `Command`. it does nothing but always use an empty
// string as the TPM response.
// Used for testing purpose as a placeholder.
class NullCommand : public Command {
 public:
  // Calls `callback` with empty TPM response, no matter what is in `command`.
  void Run(const std::string& command,
           CommandResponseCallback callback) override;
};

}  // namespace vtpm

#endif  // VTPM_COMMANDS_NULL_COMMAND_H_
