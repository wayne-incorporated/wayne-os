// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VTPM_COMMANDS_DIRECT_FORWARD_COMMAND_H_
#define VTPM_COMMANDS_DIRECT_FORWARD_COMMAND_H_

#include "vtpm/commands/command.h"

#include <string>

#include <base/functional/callback.h>
#include <trunks/trunks_factory.h>

namespace vtpm {

// This implementation forwards the coming request, as it is w/o any change, to
// the host TPM.
class DirectForwardCommand : public Command {
 public:
  explicit DirectForwardCommand(trunks::TrunksFactory* factory);

  // Sends `command` to the host TPM and invoke `callback` with the response.
  void Run(const std::string& command,
           CommandResponseCallback callback) override;

 private:
  trunks::TrunksFactory* const factory_;
};

}  // namespace vtpm

#endif  // VTPM_COMMANDS_DIRECT_FORWARD_COMMAND_H_
