// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VTPM_COMMANDS_NV_READ_COMMAND_H_
#define VTPM_COMMANDS_NV_READ_COMMAND_H_

#include "vtpm/commands/command.h"

#include <string>

#include <base/functional/callback.h>
#include <trunks/command_parser.h>
#include <trunks/response_serializer.h>

#include "vtpm/backends/nv_space_manager.h"

namespace vtpm {

class NvReadCommand : public Command {
 public:
  NvReadCommand(trunks::CommandParser* command_parser,
                trunks::ResponseSerializer* response_serializer,
                NvSpaceManager* nv_space_manager);
  ~NvReadCommand() override = default;
  void Run(const std::string& command,
           CommandResponseCallback callback) override;

 private:
  // Runs the command. if it is successful, sets `data` and returns
  // `TPM_RC_SUCCESS`. Otherwise, only returns a `TPM_RC`.
  trunks::TPM_RC RunInternal(const std::string& command, std::string& data);

  trunks::CommandParser* const command_parser_;
  trunks::ResponseSerializer* const response_serializer_;
  NvSpaceManager* const nv_space_manager_;
};

}  // namespace vtpm

#endif  // VTPM_COMMANDS_NV_READ_COMMAND_H_
