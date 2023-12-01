// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "vtpm/backends/endorsement_password_changer.h"

#include <optional>
#include <string>
#include <utility>

#include <base/check.h>
#include <base/check_op.h>
#include <base/logging.h>
#include <tpm_manager/client/tpm_manager_utility.h>
#include <trunks/error_codes.h>
#include <trunks/tpm_generated.h>
#include <trunks/tpm_structure_parser.h>

namespace vtpm {

EndorsementPasswordChanger::EndorsementPasswordChanger(
    tpm_manager::TpmManagerUtility* tpm_manager_utility,
    const std::string virtual_password)
    : tpm_manager_utility_(tpm_manager_utility),
      virtual_password_(virtual_password) {
  CHECK(tpm_manager_utility_);
}

// TODO(b/230343588): Add fuzzing test.
trunks::TPM_RC EndorsementPasswordChanger::Change(std::string& command) {
  trunks::TpmStructureParser parser(command);
  trunks::TPMI_ST_COMMAND_TAG tag;
  trunks::UINT32 original_size;
  trunks::TPM_CC cc;
  trunks::TPM_RC rc = parser.Parse(tag, original_size, cc);
  if (rc) {
    LOG(ERROR) << __func__ << ": Error parsing command header: "
               << trunks::GetErrorString(rc);
    return rc;
  }

  // If the command doesn't need password translattion, just performs no-ops.
  if (cc != trunks::TPM_CC_PolicySecret) {
    return trunks::TPM_RC_SUCCESS;
  }
  trunks::TPMI_DH_ENTITY auth_handle = 0;
  trunks::TPMI_SH_POLICY policy_session = 0;
  rc = parser.Parse(auth_handle, policy_session);
  if (rc) {
    LOG(ERROR) << __func__
               << ": Error parsing handle area: " << trunks::GetErrorString(rc)
               << ".";
    return rc;
  }

  // The entity is not even endorsement, performs no-ops.
  if (auth_handle != trunks::TPM_RH_ENDORSEMENT) {
    return trunks::TPM_RC_SUCCESS;
  }
  const std::string before_session_bytes =
      command.substr(0, command.size() - parser.payload().size());

  trunks::UINT32 session_size;
  rc = parser.Parse(session_size);
  if (rc) {
    LOG(ERROR) << __func__ << ": Error parsing session section size: "
               << trunks::GetErrorString(rc) << ".";
    return rc;
  }

  std::string session_bytes = parser.payload().substr(0, session_size);
  session_bytes = session_bytes.substr(0, session_size);
  trunks::TPMS_AUTH_COMMAND auth_command = {};
  rc = trunks::Parse_TPMS_AUTH_COMMAND(&session_bytes, &auth_command, nullptr);
  if (rc) {
    return rc;
  }
  // Prepend the excessively long bytes and let host TPM do the error handling,
  if (!session_bytes.empty()) {
    LOG(WARNING) << __func__ << ": Session bytes too long.";
  }
  const std::string after_session_bytes =
      session_bytes + parser.payload().substr(session_size);

  // The Parser should ensure a valid struct once successful.
  CHECK_LE(auth_command.hmac.size, sizeof(auth_command.hmac.buffer));

  // Password mismatch; performs no-ops.
  if (auth_command.session_handle != trunks::TPM_RS_PW ||
      virtual_password_ !=
          std::string(auth_command.hmac.buffer,
                      auth_command.hmac.buffer + auth_command.hmac.size)) {
    return rc;
  }

  const std::optional<std::string> real_password = GetEndorsementPassword();
  if (!real_password.has_value()) {
    return trunks::TPM_RC_FAILURE;
  }

  CHECK_LE(real_password->size(), sizeof(auth_command.hmac.buffer));
  // Build the command with real password.
  // Replace the password.
  auth_command.hmac = trunks::Make_TPM2B_DIGEST(*real_password);
  std::string real_session_bytes;
  std::string real_session_size_bytes;
  trunks::Serialize_TPMS_AUTH_COMMAND(auth_command, &real_session_bytes);
  const trunks::UINT32 real_session_size = real_session_bytes.size();
  const int size_diff =
      static_cast<int>(real_session_size) - static_cast<int>(session_size);
  trunks::Serialize_UINT32(real_session_size, &real_session_size_bytes);

  std::string processed_command = before_session_bytes +
                                  real_session_size_bytes + real_session_bytes +
                                  after_session_bytes;

  const trunks::UINT32 new_size = static_cast<int>(original_size) + size_diff;
  std::string new_size_str;
  trunks::Serialize_UINT32(new_size, &new_size_str);
  command = std::move(processed_command.replace(
      sizeof(trunks::TPMI_ST_COMMAND_TAG), new_size_str.size(), new_size_str));
  return trunks::TPM_RC_SUCCESS;
}

std::optional<std::string>
EndorsementPasswordChanger::GetEndorsementPassword() {
  tpm_manager::LocalData local_data;
  bool is_enabled = false;
  bool is_owned = false;
  if (!tpm_manager_utility_->GetTpmStatus(&is_enabled, &is_owned,
                                          &local_data)) {
    LOG(ERROR) << __func__ << ": Failed to get tpm status from tpm_manager.";
    return std::nullopt;
  }
  if (!is_enabled || !is_owned) {
    LOG(ERROR) << __func__ << ": Tpm is not ready.";
    return std::nullopt;
  }
  // For those that have lost endorsement password, treat it as a system error.
  if (local_data.endorsement_password().empty()) {
    LOG(ERROR) << __func__ << ": tpm manager has lost endorsement password.";
  }
  return local_data.endorsement_password();
}

}  // namespace vtpm
