// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VTPM_COMMANDS_GET_CAPABILITY_COMMAND_H_
#define VTPM_COMMANDS_GET_CAPABILITY_COMMAND_H_

#include "vtpm/commands/command.h"

#include <optional>
#include <string>

#include <base/functional/callback.h>
#include <trunks/command_parser.h>
#include <trunks/response_serializer.h>

#include "vtpm/backends/tpm_handle_manager.h"
#include "vtpm/backends/tpm_property_manager.h"

namespace vtpm {

class GetCapabilityCommand : public Command {
 public:
  GetCapabilityCommand(trunks::CommandParser* command_parser,
                       trunks::ResponseSerializer* response_serializer,
                       Command* direct_forwarder,
                       TpmHandleManager* tpm_handle_manager,
                       TpmPropertyManager* tpm_property_manager);
  void Run(const std::string& command,
           CommandResponseCallback callback) override;

 private:
  trunks::TPM_RC GetCapabilityTpmHandles(trunks::UINT32 property,
                                         trunks::UINT32 property_count,
                                         trunks::TPMI_YES_NO& has_more,
                                         trunks::TPML_HANDLE& handles);

  trunks::TPM_RC GetCapabilityCommands(trunks::UINT32 property,
                                       trunks::UINT32 property_count,
                                       trunks::TPMI_YES_NO& has_more,
                                       trunks::TPML_CCA& command);

  trunks::TPM_RC GetCapabilityPCRs(trunks::UINT32 property,
                                   trunks::UINT32 property_count,
                                   trunks::TPMI_YES_NO& has_more,
                                   trunks::TPML_PCR_SELECTION& assigned_pcr);

  trunks::TPM_RC GetCapabilityTpmProperties(
      trunks::UINT32 property,
      trunks::UINT32 property_count,
      trunks::TPMI_YES_NO& has_more,
      trunks::TPML_TAGGED_TPM_PROPERTY& tpm_properties);

  void ReturnWithError(trunks::TPM_RC rc, CommandResponseCallback callback);

  trunks::CommandParser* const command_parser_;
  trunks::ResponseSerializer* const response_serializer_;
  Command* const direct_forwarder_;
  TpmHandleManager* const tpm_handle_manager_;
  TpmPropertyManager* const tpm_property_manager_;
};

}  // namespace vtpm

#endif  // VTPM_COMMANDS_GET_CAPABILITY_COMMAND_H_
