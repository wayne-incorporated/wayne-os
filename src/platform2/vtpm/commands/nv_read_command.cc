// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "vtpm/commands/nv_read_command.h"

#include <utility>

#include <base/check.h>
#include <base/logging.h>
#include <trunks/error_codes.h>
#include <trunks/tpm_generated.h>

namespace vtpm {

NvReadCommand::NvReadCommand(trunks::CommandParser* command_parser,
                             trunks::ResponseSerializer* response_serializer,
                             NvSpaceManager* nv_space_manager)
    : command_parser_(command_parser),
      response_serializer_(response_serializer),
      nv_space_manager_(nv_space_manager) {
  CHECK(command_parser_);
  CHECK(response_serializer_);
  CHECK(nv_space_manager_);
}

void NvReadCommand::Run(const std::string& command,
                        CommandResponseCallback callback) {
  std::string data;
  const trunks::TPM_RC rc = RunInternal(command, data);
  std::string response;
  LOG_IF(ERROR, rc) << __func__ << ": Returning " << trunks::GetErrorString(rc);
  if (rc) {
    response_serializer_->SerializeHeaderOnlyResponse(rc, &response);
  } else {
    trunks::TPM2B_MAX_NV_BUFFER buffer = trunks::Make_TPM2B_MAX_NV_BUFFER(data);
    response_serializer_->SerializeResponseNvRead(buffer, &response);
  }
  std::move(callback).Run(response);
}

trunks::TPM_RC NvReadCommand::RunInternal(const std::string& command,
                                          std::string& data) {
  std::string buffer = command;
  trunks::TPMI_RH_NV_AUTH auth_handle;
  trunks::TPMI_RH_NV_INDEX nv_index;
  trunks::TPMS_AUTH_COMMAND auth;
  trunks::UINT16 size;
  trunks::UINT16 offset;

  trunks::TPM_RC rc = command_parser_->ParseCommandNvRead(
      &buffer, &auth_handle, &nv_index, &auth, &size, &offset);

  if (rc) {
    return rc;
  }

  // Only the password authorization is supported for nv read. Other handle
  // values are considered to be invalid.
  if (auth.session_handle != trunks::TPM_RS_PW) {
    return trunks::TPM_RC_HANDLE;
  }

  // Only support the case that the nv index itself as the auth handle.
  if (auth_handle != nv_index) {
    LOG(ERROR) << __func__ << ": Unsupported or wrong auth handle.";
    return trunks::TPM_RC_NV_AUTHORIZATION;
  }

  // If the size is even larger than the buffer size, i.e., this virtual TPM's
  // `MAX_NV_BUFFER_SIZE` defined in `tpm_generated.h`, return `TPM_RC_VALUE` as
  // what we learnt from some geenric TPMs.
  if (size > MAX_NV_BUFFER_SIZE) {
    return trunks::TPM_RC_VALUE;
  }

  // Get the password.
  std::string nv_data;
  const std::string password(auth.hmac.buffer,
                             auth.hmac.buffer + auth.hmac.size);
  rc = nv_space_manager_->Read(nv_index, password, nv_data);
  if (rc) {
    return rc;
  }

  if (nv_data.size() < size + offset) {
    return trunks::TPM_RC_NV_RANGE;
  }

  data = nv_data.substr(offset, size);
  return trunks::TPM_RC_SUCCESS;
}

}  // namespace vtpm
