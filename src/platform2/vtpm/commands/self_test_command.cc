// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "vtpm/commands/self_test_command.h"

#include <string>
#include <utility>

#include <base/check.h>
#include <base/functional/callback.h>
#include <trunks/tpm_generated.h>
#include <trunks/tpm_structure_parser.h>

namespace vtpm {

SelfTestCommand::SelfTestCommand(
    trunks::ResponseSerializer* response_serializer)
    : response_serializer_(response_serializer) {
  CHECK(response_serializer_);
}

void SelfTestCommand::Run(const std::string& command,
                          CommandResponseCallback callback) {
  std::string response;
  response_serializer_->SerializeHeaderOnlyResponse(RunInternal(command),
                                                    &response);
  std::move(callback).Run(response);
}

trunks::TPM_RC SelfTestCommand::RunInternal(const std::string& command) {
  trunks::TPMI_ST_COMMAND_TAG tag;
  trunks::UINT32 size;
  trunks::TPM_CC cc;
  trunks::TpmStructureParser parser(command);
  trunks::TPMI_YES_NO full_test;
  trunks::TPM_RC rc = parser.Parse(tag, size, cc, full_test);
  if (rc) {
    return rc;
  }
  if (cc != trunks::TPM_CC_SelfTest) {
    return trunks::TPM_RC_COMMAND_CODE;
  } else if (!parser.payload().empty()) {
    return trunks::TPM_RC_SIZE;
  }
  return trunks::TPM_RC_SUCCESS;
}

}  // namespace vtpm
