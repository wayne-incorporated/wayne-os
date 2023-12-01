// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "vtpm/commands/nv_read_public_command.h"

#include <utility>

#include <base/check.h>
#include <base/check_op.h>
#include <base/logging.h>
#include <trunks/error_codes.h>
#include <trunks/tpm_generated.h>

#include "vtpm/backends/nv_space_manager.h"
#include "vtpm/backends/static_analyzer.h"

namespace vtpm {

NvReadPublicCommand::NvReadPublicCommand(
    trunks::CommandParser* command_parser,
    trunks::ResponseSerializer* response_serializer,
    NvSpaceManager* nv_space_manager,
    StaticAnalyzer* static_analyzer)
    : command_parser_(command_parser),
      response_serializer_(response_serializer),
      nv_space_manager_(nv_space_manager),
      static_analyzer_(static_analyzer) {
  CHECK(command_parser_);
  CHECK(response_serializer_);
  CHECK(nv_space_manager_);
  CHECK(static_analyzer_);
}

void NvReadPublicCommand::Run(const std::string& command,
                              CommandResponseCallback callback) {
  trunks::TPMS_NV_PUBLIC nv_public = {};
  std::string nv_name;
  const trunks::TPM_RC rc = RunInternal(command, nv_public, nv_name);
  std::string response;
  LOG_IF(ERROR, rc) << __func__ << ": Returning " << trunks::GetErrorString(rc);
  if (rc) {
    response_serializer_->SerializeHeaderOnlyResponse(rc, &response);
  } else {
    CHECK_LE(nv_name.size(), sizeof(trunks::TPM2B_NAME::name));
    response_serializer_->SerializeResponseNvReadPublic(
        trunks::Make_TPM2B_NV_PUBLIC(nv_public),
        trunks::Make_TPM2B_NAME(nv_name), &response);
  }
  std::move(callback).Run(response);
}

trunks::TPM_RC NvReadPublicCommand::RunInternal(
    const std::string& command,
    trunks::TPMS_NV_PUBLIC& nv_public,
    std::string& nv_name) {
  std::string buffer = command;
  trunks::TPMI_RH_NV_INDEX nv_index;

  trunks::TPM_RC rc =
      command_parser_->ParseCommandNvReadPublic(&buffer, &nv_index);

  if (rc) {
    return rc;
  }

  nv_public.nv_index = nv_index;
  // Ideally this is supposed to come from `NvSpaceManager` as well, but there
  // is no demand for non-empty policy digest.
  nv_public.auth_policy = trunks::Make_TPM2B_DIGEST("");

  rc = nv_space_manager_->GetDataSize(nv_index, nv_public.data_size);
  if (rc) {
    return rc;
  }
  rc = nv_space_manager_->GetAttributes(nv_index, nv_public.attributes);
  if (rc) {
    return rc;
  }
  rc = nv_space_manager_->GetNameAlgorithm(nv_index, nv_public.name_alg);
  if (rc) {
    return rc;
  }

  rc = static_analyzer_->ComputeNvName(nv_public, nv_name);
  if (rc) {
    return rc;
  }

  return trunks::TPM_RC_SUCCESS;
}

}  // namespace vtpm
