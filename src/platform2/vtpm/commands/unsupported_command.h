// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VTPM_COMMANDS_UNSUPPORTED_COMMAND_H_
#define VTPM_COMMANDS_UNSUPPORTED_COMMAND_H_

#include "vtpm/commands/command.h"

#include <string>

#include <base/functional/callback.h>
#include <trunks/response_serializer.h>

namespace vtpm {

// An implementation of `Command`. It rejects any incoming request and returns
// `TPM_RC_COOMAND_CODE`.
class UnsupportedCommand : public Command {
 public:
  explicit UnsupportedCommand(trunks::ResponseSerializer* serializer);
  void Run(const std::string& command,
           CommandResponseCallback callback) override;

 protected:
  trunks::ResponseSerializer* const response_serializer_;
};

}  // namespace vtpm

#endif  // VTPM_COMMANDS_UNSUPPORTED_COMMAND_H_
