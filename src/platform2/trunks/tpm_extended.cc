// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "trunks/tpm_generated.h"

#include <iterator>

#include <base/check.h>
#include <base/functional/bind.h>
#include <base/functional/callback.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <crypto/secure_hash.h>

#include "trunks/authorization_delegate.h"
#include "trunks/command_transceiver.h"
#include "trunks/error_codes.h"

namespace trunks {
// static
TPM_RC Tpm::SerializeCommand_PolicyFidoSigned(
    const TPMI_DH_OBJECT& auth_object,
    const std::string& auth_object_name,
    const TPMI_SH_POLICY& policy_session,
    const std::string& policy_session_name,
    const std::string& auth_data,
    const std::vector<FIDO_DATA_RANGE>& auth_data_descr,
    const TPMT_SIGNATURE& auth,
    std::string* serialized_command,
    AuthorizationDelegate* authorization_delegate) {
  VLOG(3) << __func__;
  TPM_RC rc = TPM_RC_SUCCESS;
  TPMI_ST_COMMAND_TAG tag = TPM_ST_NO_SESSIONS;
  UINT32 command_size = 10;  // Header size.
  std::string handle_section_bytes;
  std::string parameter_section_bytes;
  TPM_CC command_code = TPM_CCE_PolicyFidoSigned;
  bool is_command_parameter_encryption_possible = true;
  bool is_response_parameter_encryption_possible = true;

  // Serialize header
  std::string command_code_bytes;

  rc = Serialize_TPM_CC(command_code, &command_code_bytes);
  if (rc != TPM_RC_SUCCESS)
    return rc;

  // Serialize handles
  std::string auth_object_bytes;

  rc = Serialize_TPMI_DH_OBJECT(auth_object, &auth_object_bytes);
  if (rc != TPM_RC_SUCCESS)
    return rc;

  std::string policy_session_bytes;

  rc = Serialize_TPMI_SH_POLICY(policy_session, &policy_session_bytes);
  if (rc != TPM_RC_SUCCESS)
    return rc;

  // Serialize Command parameters
  std::string auth_data_size_bytes;

  rc = Serialize_UINT16(auth_data.size(), &auth_data_size_bytes);
  if (rc != TPM_RC_SUCCESS)
    return rc;

  std::string auth_data_bytes;

  for (const char& ch : auth_data) {
    rc = Serialize_BYTE(ch, &auth_data_bytes);
    if (rc != TPM_RC_SUCCESS)
      return rc;
  }

  // auth_data_descr is an array of tuples of (UINT16, UINT16).
  // auth_data_descr_count is the number of tuples in this array.

  std::string auth_data_descr_count_bytes;
  UINT16 auth_data_descr_count = auth_data_descr.size();

  rc = Serialize_UINT16(auth_data_descr_count, &auth_data_descr_count_bytes);
  if (rc != TPM_RC_SUCCESS)
    return rc;

  std::string auth_data_descr_bytes;

  for (const auto& descr : auth_data_descr) {
    rc = Serialize_UINT16(descr.offset, &auth_data_descr_bytes);
    if (rc != TPM_RC_SUCCESS)
      return rc;

    rc = Serialize_UINT16(descr.size, &auth_data_descr_bytes);
    if (rc != TPM_RC_SUCCESS)
      return rc;
  }

  std::string auth_bytes;

  rc = Serialize_TPMT_SIGNATURE(auth, &auth_bytes);
  if (rc != TPM_RC_SUCCESS)
    return rc;

  if (authorization_delegate) {
    // Encrypt just the auth_data, not the auth_data_size.
    if (!authorization_delegate->EncryptCommandParameter(&auth_data_bytes))
      return TRUNKS_RC_ENCRYPTION_FAILED;
  }

  // Get a hash and construct a command by concatenation parts
  std::unique_ptr<crypto::SecureHash> hash(
      crypto::SecureHash::Create(crypto::SecureHash::SHA256));

  // Construct the handle section
  hash->Update(command_code_bytes.data(), command_code_bytes.size());
  hash->Update(auth_object_name.data(), auth_object_name.size());
  handle_section_bytes += auth_object_bytes;
  command_size += auth_object_bytes.size();

  hash->Update(policy_session_name.data(), policy_session_name.size());
  handle_section_bytes += policy_session_bytes;
  command_size += policy_session_bytes.size();

  // Construct the parameter section
  // Hash on authenticator data
  hash->Update(auth_data_size_bytes.data(), auth_data_size_bytes.size());
  parameter_section_bytes += auth_data_size_bytes;
  command_size += auth_data_size_bytes.size();

  hash->Update(auth_data_bytes.data(), auth_data_bytes.size());
  parameter_section_bytes += auth_data_bytes;
  command_size += auth_data_bytes.size();

  // Hash on authenticator data descriptor
  hash->Update(auth_data_descr_count_bytes.data(),
               auth_data_descr_count_bytes.size());
  parameter_section_bytes += auth_data_descr_count_bytes;
  command_size += auth_data_descr_count_bytes.size();

  hash->Update(auth_data_descr_bytes.data(), auth_data_descr_bytes.size());
  parameter_section_bytes += auth_data_descr_bytes;
  command_size += auth_data_descr_bytes.size();

  // Hash on auth
  hash->Update(auth_bytes.data(), auth_bytes.size());
  parameter_section_bytes += auth_bytes;
  command_size += auth_bytes.size();

  std::string command_hash(32, 0);
  hash->Finish(std::data(command_hash), command_hash.size());

  // Construct the authorization section
  std::string authorization_section_bytes;
  std::string authorization_size_bytes;

  if (authorization_delegate) {
    if (!authorization_delegate->GetCommandAuthorization(
            command_hash, is_command_parameter_encryption_possible,
            is_response_parameter_encryption_possible,
            &authorization_section_bytes))
      return TRUNKS_RC_AUTHORIZATION_FAILED;

    if (!authorization_section_bytes.empty()) {
      tag = TPM_ST_SESSIONS;

      rc = Serialize_UINT32(authorization_section_bytes.size(),
                            &authorization_size_bytes);
      if (rc != TPM_RC_SUCCESS)
        return rc;

      command_size +=
          authorization_size_bytes.size() + authorization_section_bytes.size();
    }
  }

  // Construct the header section
  std::string tag_bytes;

  rc = Serialize_TPMI_ST_COMMAND_TAG(tag, &tag_bytes);
  if (rc != TPM_RC_SUCCESS)
    return rc;

  std::string command_size_bytes;

  rc = Serialize_UINT32(command_size, &command_size_bytes);
  if (rc != TPM_RC_SUCCESS)
    return rc;

  *serialized_command = tag_bytes + command_size_bytes + command_code_bytes +
                        handle_section_bytes + authorization_size_bytes +
                        authorization_section_bytes + parameter_section_bytes;
  CHECK(serialized_command->size() == command_size) << "Command size mismatch!";
  VLOG(2) << "Command: "
          << base::HexEncode(serialized_command->data(),
                             serialized_command->size());
  return TPM_RC_SUCCESS;
}

// static
TPM_RC Tpm::ParseResponse_PolicyFidoSigned(
    const std::string& response,
    AuthorizationDelegate* authorization_delegate) {
  VLOG(3) << __func__;
  VLOG(2) << "Response: " << base::HexEncode(response.data(), response.size());
  TPM_RC rc = TPM_RC_SUCCESS;
  std::string buffer(response);
  TPM_ST tag;
  std::string tag_bytes;

  rc = Parse_TPM_ST(&buffer, &tag, &tag_bytes);
  if (rc != TPM_RC_SUCCESS)
    return rc;

  UINT32 response_size;
  std::string response_size_bytes;

  rc = Parse_UINT32(&buffer, &response_size, &response_size_bytes);
  if (rc != TPM_RC_SUCCESS)
    return rc;

  TPM_RC response_code;
  std::string response_code_bytes;

  rc = Parse_TPM_RC(&buffer, &response_code, &response_code_bytes);
  if (rc != TPM_RC_SUCCESS)
    return rc;
  if (response_size != response.size())
    return TPM_RC_SIZE;
  if (response_code != TPM_RC_SUCCESS)
    return response_code;

  TPM_CC command_code = TPM_CCE_PolicyFidoSigned;
  std::string command_code_bytes;

  rc = Serialize_TPM_CC(command_code, &command_code_bytes);
  if (rc != TPM_RC_SUCCESS)
    return rc;

  std::string authorization_section_bytes;

  if (tag == TPM_ST_SESSIONS) {
    UINT32 parameter_section_size = buffer.size();

    rc = Parse_UINT32(&buffer, &parameter_section_size, nullptr);
    if (rc != TPM_RC_SUCCESS)
      return rc;
    if (parameter_section_size > buffer.size())
      return TPM_RC_INSUFFICIENT;

    authorization_section_bytes = buffer.substr(parameter_section_size);
    // Keep the parameter section in |buffer|.
    buffer.erase(parameter_section_size);
  }
  std::unique_ptr<crypto::SecureHash> hash(
      crypto::SecureHash::Create(crypto::SecureHash::SHA256));
  hash->Update(response_code_bytes.data(), response_code_bytes.size());
  hash->Update(command_code_bytes.data(), command_code_bytes.size());
  hash->Update(buffer.data(), buffer.size());
  std::string response_hash(32, 0);
  hash->Finish(std::data(response_hash), response_hash.size());
  if (tag == TPM_ST_SESSIONS) {
    if (!authorization_delegate)
      return TRUNKS_RC_AUTHORIZATION_FAILED;
    if (!authorization_delegate->CheckResponseAuthorization(
            response_hash, authorization_section_bytes))
      return TRUNKS_RC_AUTHORIZATION_FAILED;
  }

  return TPM_RC_SUCCESS;
}

void PolicyFidoSignedErrorCallback(Tpm::PolicyFidoSignedResponse callback,
                                   TPM_RC response_code) {
  VLOG(1) << __func__;
  std::move(callback).Run(response_code);
}

void PolicyFidoSignedResponseParser(
    Tpm::PolicyFidoSignedResponse callback,
    AuthorizationDelegate* authorization_delegate,
    const std::string& response) {
  VLOG(1) << __func__;
  TPM_RC rc =
      Tpm::ParseResponse_PolicyFidoSigned(response, authorization_delegate);
  if (rc != TPM_RC_SUCCESS) {
    base::OnceCallback<void(TPM_RC)> error_reporter =
        base::BindOnce(PolicyFidoSignedErrorCallback, std::move(callback));
    std::move(error_reporter).Run(rc);
    return;
  }
  std::move(callback).Run(rc);
}

void Tpm::PolicyFidoSigned(const TPMI_DH_OBJECT& auth_object,
                           const std::string& auth_object_name,
                           const TPMI_SH_POLICY& policy_session,
                           const std::string& policy_session_name,
                           const std::string& auth_data,
                           const std::vector<FIDO_DATA_RANGE>& auth_data_descr,
                           const TPMT_SIGNATURE& auth,
                           AuthorizationDelegate* authorization_delegate,
                           PolicyFidoSignedResponse callback) {
  VLOG(1) << __func__;
  std::string command;
  TPM_RC rc = SerializeCommand_PolicyFidoSigned(
      auth_object, auth_object_name, policy_session, policy_session_name,
      auth_data, auth_data_descr, auth, &command, authorization_delegate);
  if (rc != TPM_RC_SUCCESS) {
    base::OnceCallback<void(TPM_RC)> error_reporter =
        base::BindOnce(PolicyFidoSignedErrorCallback, std::move(callback));
    std::move(error_reporter).Run(rc);
    return;
  }
  base::OnceCallback<void(const std::string&)> parser =
      base::BindOnce(PolicyFidoSignedResponseParser, std::move(callback),
                     authorization_delegate);
  transceiver_->SendCommand(command, std::move(parser));
}

TPM_RC Tpm::PolicyFidoSignedSync(
    const TPMI_DH_OBJECT& auth_object,
    const std::string& auth_object_name,
    const TPMI_SH_POLICY& policy_session,
    const std::string& policy_session_name,
    const std::string& auth_data,
    const std::vector<FIDO_DATA_RANGE>& auth_data_descr,
    const TPMT_SIGNATURE& auth,
    AuthorizationDelegate* authorization_delegate) {
  VLOG(1) << __func__;
  std::string command;
  TPM_RC rc = SerializeCommand_PolicyFidoSigned(
      auth_object, auth_object_name, policy_session, policy_session_name,
      auth_data, auth_data_descr, auth, &command, authorization_delegate);

  if (rc != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error from SerializeCommand_PolicyFidoSigned: "
               << GetErrorString(rc);
    return rc;
  }

  std::string response = transceiver_->SendCommandAndWait(command);

  rc = ParseResponse_PolicyFidoSigned(response, authorization_delegate);
  return rc;
}

}  // namespace trunks
