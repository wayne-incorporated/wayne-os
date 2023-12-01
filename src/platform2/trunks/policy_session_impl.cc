// Copyright 2015 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "trunks/policy_session_impl.h"

#include <iterator>
#include <map>
#include <string>
#include <vector>

#include <base/check.h>
#include <base/logging.h>
#include <crypto/sha2.h>
#include <openssl/rand.h>

#include "trunks/error_codes.h"
#include "trunks/tpm_generated.h"

namespace {

// Returns a serialized representation of the unmodified handle. This is useful
// for predefined handle values, like TPM_RH_OWNER. For details on what types of
// handles use this name formula see Table 3 in the TPM 2.0 Library Spec Part 1
// (Section 16 - Names).
std::string NameFromHandle(trunks::TPM_HANDLE handle) {
  std::string name;
  trunks::Serialize_TPM_HANDLE(handle, &name);
  return name;
}

}  // namespace

namespace trunks {

PolicySessionImpl::PolicySessionImpl(const TrunksFactory& factory)
    : factory_(factory), session_type_(TPM_SE_POLICY) {
  session_manager_ = factory_.GetSessionManager();
}

PolicySessionImpl::PolicySessionImpl(const TrunksFactory& factory,
                                     TPM_SE session_type)
    : factory_(factory), session_type_(session_type) {
  session_manager_ = factory_.GetSessionManager();
}

PolicySessionImpl::~PolicySessionImpl() {
  session_manager_->CloseSession();
}

AuthorizationDelegate* PolicySessionImpl::GetDelegate() {
  if (session_manager_->GetSessionHandle() == kUninitializedHandle) {
    return nullptr;
  }
  return &hmac_delegate_;
}

TPM_RC PolicySessionImpl::StartBoundSession(
    TPMI_DH_ENTITY bind_entity,
    const std::string& bind_authorization_value,
    bool salted,
    bool enable_encryption) {
  hmac_delegate_.set_use_entity_authorization_for_encryption_only(true);
  if (session_type_ != TPM_SE_POLICY && session_type_ != TPM_SE_TRIAL) {
    LOG(ERROR) << "Cannot start a session of that type.";
    return SAPI_RC_INVALID_SESSIONS;
  }
  return session_manager_->StartSession(session_type_, bind_entity,
                                        bind_authorization_value, salted,
                                        enable_encryption, &hmac_delegate_);
}

TPM_RC PolicySessionImpl::StartUnboundSession(bool salted,
                                              bool enable_encryption) {
  // Just like a HmacAuthorizationSession, an unbound policy session is just
  // a session bound to TPM_RH_NULL.
  return StartBoundSession(TPM_RH_NULL, "", salted, enable_encryption);
}

TPM_RC PolicySessionImpl::GetDigest(std::string* digest) {
  CHECK(digest);
  TPM2B_DIGEST policy_digest;
  TPM_RC result = factory_.GetTpm()->PolicyGetDigestSync(
      session_manager_->GetSessionHandle(),
      "",  // No name is needed for this command, as it does no authorization.
      &policy_digest, nullptr);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error getting policy digest: " << GetErrorString(result);
    return result;
  }
  *digest = StringFrom_TPM2B_DIGEST(policy_digest);
  return TPM_RC_SUCCESS;
}

TPM_RC PolicySessionImpl::PolicyOR(const std::vector<std::string>& digests) {
  TPML_DIGEST tpm_digests;
  if (digests.size() >= std::size(tpm_digests.digests)) {
    LOG(ERROR) << "TPM2.0 Spec only allows for up to 8 digests.";
    return SAPI_RC_BAD_PARAMETER;
  }
  tpm_digests.count = digests.size();
  for (size_t i = 0; i < digests.size(); i++) {
    tpm_digests.digests[i] = Make_TPM2B_DIGEST(digests[i]);
  }
  TPM_RC result = factory_.GetTpm()->PolicyORSync(
      session_manager_->GetSessionHandle(),
      "",  // No policy name is needed as we do no authorization checks.
      tpm_digests, nullptr);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error performing PolicyOR: " << GetErrorString(result);
    return result;
  }

  return TPM_RC_SUCCESS;
}

TPM_RC PolicySessionImpl::PolicyPCR(
    const std::map<uint32_t, std::string>& pcr_map) {
  TPML_PCR_SELECTION pcr_select;
  memset(&pcr_select, 0, sizeof(TPML_PCR_SELECTION));
  // This process of selecting pcrs is highlighted in TPM 2.0 Library Spec
  // Part 2 (Section 10.5 - PCR structures).
  pcr_select.count = 1;
  pcr_select.pcr_selections[0].hash = TPM_ALG_SHA256;
  pcr_select.pcr_selections[0].sizeof_select = PCR_SELECT_MIN;
  TPM2B_DIGEST pcr_digest;
  std::string concatenated_pcr_values;

  bool map_contains_empty_value = false;
  for (const auto& map_pair : pcr_map) {
    uint32_t pcr_index = map_pair.first;
    const std::string& pcr_value = map_pair.second;
    if (pcr_value.empty()) {
      map_contains_empty_value = true;
    }
    uint8_t pcr_select_index = pcr_index / 8;
    uint8_t pcr_select_byte = 1 << (pcr_index % 8);
    if (pcr_select_index >= PCR_SELECT_MIN) {
      LOG(ERROR) << "Out of bounds pcr_index provided: " << pcr_index;
      return SAPI_RC_BAD_PARAMETER;
    }
    pcr_select.pcr_selections[0].pcr_select[pcr_select_index] |=
        pcr_select_byte;
    concatenated_pcr_values += pcr_value;
  }

  if (concatenated_pcr_values.empty()) {
    if (session_type_ == TPM_SE_TRIAL) {
      LOG(ERROR) << "Trial sessions have to define a PCR value.";
      return SAPI_RC_BAD_PARAMETER;
    }
    pcr_digest = Make_TPM2B_DIGEST("");
  } else {
    if (map_contains_empty_value) {
      LOG(ERROR) << "PCR map must not have both empty and non-empty values.";
      return SAPI_RC_BAD_PARAMETER;
    }
    pcr_digest =
        Make_TPM2B_DIGEST(crypto::SHA256HashString(concatenated_pcr_values));
  }

  TPM_RC result = factory_.GetTpm()->PolicyPCRSync(
      session_manager_->GetSessionHandle(),
      "",  // No policy name is needed as we do no authorization checks.
      pcr_digest, pcr_select, nullptr);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error performing PolicyPCR: " << GetErrorString(result);
    return result;
  }
  return TPM_RC_SUCCESS;
}

TPM_RC PolicySessionImpl::PolicyCommandCode(TPM_CC command_code) {
  TPM_RC result = factory_.GetTpm()->PolicyCommandCodeSync(
      session_manager_->GetSessionHandle(),
      "",  // No policy name is needed as we do no authorization checks.
      command_code, nullptr);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error performing PolicyCommandCode: "
               << GetErrorString(result);
    return result;
  }
  return TPM_RC_SUCCESS;
}

TPM_RC PolicySessionImpl::PolicySecret(TPMI_DH_ENTITY auth_entity,
                                       const std::string& auth_entity_name,
                                       const std::string& nonce,
                                       const std::string& cp_hash,
                                       const std::string& policy_ref,
                                       int32_t expiration,
                                       AuthorizationDelegate* delegate) {
  TPM2B_TIMEOUT timeout;
  TPMT_TK_AUTH policy_ticket;
  TPM_HANDLE policy_session_handle = session_manager_->GetSessionHandle();
  std::string policy_session_name;
  trunks::Serialize_TPM_HANDLE(policy_session_handle, &policy_session_name);

  TPM_RC result = factory_.GetTpm()->PolicySecretSync(
      auth_entity, auth_entity_name, policy_session_handle, policy_session_name,
      Make_TPM2B_DIGEST(nonce), Make_TPM2B_DIGEST(cp_hash),
      Make_TPM2B_DIGEST(policy_ref), expiration, &timeout, &policy_ticket,
      delegate);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error performing PolicySecret: " << GetErrorString(result);
    return result;
  }
  return TPM_RC_SUCCESS;
}

TPM_RC PolicySessionImpl::PolicySigned(TPMI_DH_ENTITY auth_entity,
                                       const std::string& auth_entity_name,
                                       const std::string& nonce,
                                       const std::string& cp_hash,
                                       const std::string& policy_ref,
                                       int32_t expiration,
                                       const trunks::TPMT_SIGNATURE& signature,
                                       AuthorizationDelegate* delegate) {
  TPM2B_TIMEOUT timeout;
  TPMT_TK_AUTH policy_ticket;
  TPM_HANDLE policy_session_handle = session_manager_->GetSessionHandle();
  std::string policy_session_name;
  trunks::Serialize_TPM_HANDLE(policy_session_handle, &policy_session_name);

  TPM_RC result = factory_.GetTpm()->PolicySignedSync(
      auth_entity, auth_entity_name, policy_session_handle, policy_session_name,
      Make_TPM2B_DIGEST(nonce), Make_TPM2B_DIGEST(cp_hash),
      Make_TPM2B_DIGEST(policy_ref), expiration, signature, &timeout,
      &policy_ticket, delegate);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error performing PolicySigned: " << GetErrorString(result);
    return result;
  }
  return TPM_RC_SUCCESS;
}

TPM_RC PolicySessionImpl::PolicyAuthValue() {
  TPM_RC result = factory_.GetTpm()->PolicyAuthValueSync(
      session_manager_->GetSessionHandle(),
      "",  // No policy name is needed as we do no authorization checks.
      nullptr);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error performing PolicyAuthValue: "
               << GetErrorString(result);
    return result;
  }
  hmac_delegate_.set_use_entity_authorization_for_encryption_only(false);
  return TPM_RC_SUCCESS;
}

TPM_RC PolicySessionImpl::PolicyRestart() {
  TPM_RC result = factory_.GetTpm()->PolicyAuthValueSync(
      session_manager_->GetSessionHandle(),
      "",  // No policy name is needed as we do no authorization checks.
      nullptr);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error performing PolicyRestart: " << GetErrorString(result);
    return result;
  }
  return TPM_RC_SUCCESS;
}

void PolicySessionImpl::SetEntityAuthorizationValue(const std::string& value) {
  hmac_delegate_.set_entity_authorization_value(value);
}

TPM_RC PolicySessionImpl::PolicyFidoSigned(
    TPMI_DH_ENTITY auth_entity,
    const std::string& auth_entity_name,
    const std::string& auth_data,
    const std::vector<FIDO_DATA_RANGE>& auth_data_descr,
    const TPMT_SIGNATURE& signature,
    AuthorizationDelegate* delegate) {
  TPM_HANDLE policy_session_handle = session_manager_->GetSessionHandle();
  std::string policy_session_name;
  Serialize_TPM_HANDLE(policy_session_handle, &policy_session_name);

  TPM_RC result = factory_.GetTpm()->PolicyFidoSignedSync(
      auth_entity, auth_entity_name, policy_session_handle, policy_session_name,
      auth_data, auth_data_descr, signature, delegate);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error performing PolicyFidoSigned: "
               << GetErrorString(result);
    return result;
  }
  return TPM_RC_SUCCESS;
}

TPM_RC PolicySessionImpl::PolicyNV(uint32_t index,
                                   uint32_t offset,
                                   bool using_owner_authorization,
                                   TPM2B_OPERAND operand,
                                   TPM_EO operation,
                                   AuthorizationDelegate* delegate) {
  TPM_RC result;
  std::string nv_name;
  result = factory_.GetTpmUtility()->GetNVSpaceName(index, &nv_name);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << __func__ << ": Could not find space at " << index << " "
               << GetErrorString(result);
    return result;
  }
  uint32_t nv_index = NV_INDEX_FIRST + index;
  TPMI_RH_NV_AUTH auth_entity = nv_index;
  std::string auth_entity_name = nv_name;
  if (using_owner_authorization) {
    auth_entity = TPM_RH_OWNER;
    auth_entity_name = NameFromHandle(TPM_RH_OWNER);
  }

  TPM_HANDLE policy_session_handle = session_manager_->GetSessionHandle();
  std::string policy_session_name = NameFromHandle(policy_session_handle);

  result = factory_.GetTpm()->PolicyNVSync(
      auth_entity, auth_entity_name, nv_index, nv_name, policy_session_handle,
      policy_session_name, operand, offset, operation, delegate);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error performing PolicyNV: " << GetErrorString(result);
  }
  return result;
}

}  // namespace trunks
