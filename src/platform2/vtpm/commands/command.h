// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VTPM_COMMANDS_COMMAND_H_
#define VTPM_COMMANDS_COMMAND_H_

#include <string>

#include <base/functional/callback.h>

namespace vtpm {

// The type of the callback a `Command` instance runs with the the virtual tpm
// response as its argument.
using CommandResponseCallback = base::OnceCallback<void(const std::string&)>;

// A generic interface that executes a virtual TPM command.
class Command {
 public:
  virtual ~Command() = default;
  // Executes a TPM `command`. Once done, calls `callback` w/ the TPM response.
  virtual void Run(const std::string& command,
                   CommandResponseCallback callback) = 0;
};

}  // namespace vtpm

#endif  // VTPM_COMMANDS_COMMAND_H_
