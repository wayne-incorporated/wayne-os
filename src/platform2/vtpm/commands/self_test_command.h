// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VTPM_COMMANDS_SELF_TEST_COMMAND_H_
#define VTPM_COMMANDS_SELF_TEST_COMMAND_H_

#include "vtpm/commands/command.h"

#include <string>

#include <base/functional/callback.h>
#include <trunks/response_serializer.h>

namespace vtpm {

// A no-op implementation for `TPM_CC_SelfTest` command. As long as the command
// is parsed successfully this class considers the self test is successful.
class SelfTestCommand : public Command {
 public:
  explicit SelfTestCommand(trunks::ResponseSerializer* response_serializer);

  virtual ~SelfTestCommand() = default;
  void Run(const std::string& command,
           CommandResponseCallback callback) override;

 private:
  trunks::TPM_RC RunInternal(const std::string& command);
  trunks::ResponseSerializer* const response_serializer_;
};

}  // namespace vtpm

#endif  // VTPM_COMMANDS_SELF_TEST_COMMAND_H_
