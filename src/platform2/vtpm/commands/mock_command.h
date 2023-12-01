// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VTPM_COMMANDS_MOCK_COMMAND_H_
#define VTPM_COMMANDS_MOCK_COMMAND_H_

#include "vtpm/commands/command.h"

#include <string>

#include <base/functional/callback.h>
#include <gmock/gmock.h>

namespace vtpm {

class MockCommand : public Command {
 public:
  virtual ~MockCommand() = default;

  MOCK_METHOD(void,
              Run,
              (const std::string& command, CommandResponseCallback callback),
              (override));
};

}  // namespace vtpm

#endif  // VTPM_COMMANDS_MOCK_COMMAND_H_
