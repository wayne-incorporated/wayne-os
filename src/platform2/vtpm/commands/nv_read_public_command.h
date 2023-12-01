// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VTPM_COMMANDS_NV_READ_PUBLIC_COMMAND_H_
#define VTPM_COMMANDS_NV_READ_PUBLIC_COMMAND_H_

#include "vtpm/commands/command.h"

#include <string>

#include <base/functional/callback.h>
#include <trunks/command_parser.h>
#include <trunks/response_serializer.h>

#include "vtpm/backends/nv_space_manager.h"
#include "vtpm/backends/static_analyzer.h"

namespace vtpm {

class NvReadPublicCommand : public Command {
 public:
  NvReadPublicCommand(trunks::CommandParser* command_parser,
                      trunks::ResponseSerializer* response_serializer,
                      NvSpaceManager* nv_space_manager,
                      StaticAnalyzer* static_analyzer);
  ~NvReadPublicCommand() override = default;
  void Run(const std::string& command,
           CommandResponseCallback callback) override;

 private:
  // Runs the command. if it is successful, sets `nv_public` and `nv_name`, and
  // returns `TPM_RC_SUCCESS`. Otherwise, only returns a `TPM_RC`.
  trunks::TPM_RC RunInternal(const std::string& command,
                             trunks::TPMS_NV_PUBLIC& nv_public,
                             std::string& nv_name);

  trunks::CommandParser* const command_parser_;
  trunks::ResponseSerializer* const response_serializer_;
  NvSpaceManager* const nv_space_manager_;
  StaticAnalyzer* const static_analyzer_;
};

}  // namespace vtpm

#endif  // VTPM_COMMANDS_NV_READ_PUBLIC_COMMAND_H_
