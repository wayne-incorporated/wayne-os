// Copyright 2015 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "tpm_manager/server/tpm_initializer_impl.h"

#include <iterator>
#include <memory>
#include <string>
#include <vector>

#include <base/check.h>
#include <base/functional/callback_helpers.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <brillo/secure_blob.h>
#include <libhwsec/overalls/overalls_api.h>
#include <tpm_manager-client/tpm_manager/dbus-constants.h>
#include <trousers/scoped_tss_type.h>
#include <trousers/trousers.h>
#include <trousers/tss.h>

#include "tpm_manager/server/local_data_store.h"
#include "tpm_manager/server/tpm_connection.h"
#include "tpm_manager/server/tpm_status.h"
#include "tpm_manager/server/tpm_util.h"

using ::hwsec::overalls::GetOveralls;

namespace {

constexpr int kMaxOwnershipTimeoutRetries = 5;
constexpr char kWellKnownSrkSecret[] = "well_known_srk_secret";
constexpr int kDelegateSecretSize = 20;
constexpr uint8_t kDefaultDelegateLabel = 2;
constexpr uint8_t kDefaultDelegateFamilyLabel = 1;

// Checks the |delegate| has the reset lock permission or not, return true
// when we should resave the delegate to storage.
bool CheckResetLockPermissions(tpm_manager::AuthDelegate* delegate) {
  if (!delegate->has_reset_lock_permissions()) {
    // No need to resave the delegate.
    return false;
  }

  if (!USE_DOUBLE_EXTEND_PCR_ISSUE) {
    // No need to resave the delegate.
    return false;
  }

  brillo::Blob blob = brillo::BlobFromString(delegate->blob());

  uint64_t offset = 0;
  TPM_DELEGATE_OWNER_BLOB owner_blob;

  TSS_RESULT result = Trspi_UnloadBlob_TPM_DELEGATE_OWNER_BLOB_s(
      &offset, blob.data(), blob.size(), &owner_blob);
  if (result != TPM_SUCCESS) {
    // Save the reset_lock_permissions to false.
    delegate->set_has_reset_lock_permissions(false);
    return true;
  }

  base::ScopedClosureRunner cleanup_owner_blob(base::BindOnce(
      [](TPM_DELEGATE_OWNER_BLOB& owner_blob) {
        free(owner_blob.pub.pcrInfo.pcrSelection.pcrSelect);
        free(owner_blob.additionalArea);
        free(owner_blob.sensitiveArea);
      },
      std::ref(owner_blob)));

  // If the delegate is pound to any PCR, we may not be able to reset the lock.
  if (owner_blob.pub.pcrInfo.pcrSelection.sizeOfSelect > 0 &&
      owner_blob.pub.pcrInfo.pcrSelection.pcrSelect != nullptr) {
    for (int i = 0; i < owner_blob.pub.pcrInfo.pcrSelection.sizeOfSelect; i++) {
      if (owner_blob.pub.pcrInfo.pcrSelection.pcrSelect[i] != 0) {
        // Save the reset_lock_permissions to false.
        delegate->set_has_reset_lock_permissions(false);
        return true;
      }
    }
  }

  // No need to resave the delegate.
  return false;
}

}  // namespace

namespace tpm_manager {

TpmInitializerImpl::TpmInitializerImpl(LocalDataStore* local_data_store,
                                       TpmStatus* tpm_status)
    : local_data_store_(local_data_store), tpm_status_(tpm_status) {}

bool TpmInitializerImpl::PreInitializeTpm() {
  // No pre-initialization steps are performed for 1.2.
  return true;
}

bool TpmInitializerImpl::InitializeTpm(bool* already_owned) {
  TpmStatus::TpmOwnershipStatus ownership_status;
  if (!tpm_status_->GetTpmOwned(&ownership_status)) {
    LOG(ERROR) << __func__ << ": failed to get tpm ownership status";
    return false;
  }
  if (ownership_status == TpmStatus::kTpmOwned) {
    // Tpm is already owned, so we do not need to do anything.
    VLOG(1) << "Tpm already owned.";
    *already_owned = true;
    return true;
  }
  if (ownership_status == TpmStatus::kTpmSrkNoAuth) {
    // The SRK isn't usable, we can't take ownership in this case.
    VLOG(1) << "SRK isn't using default auth.";
    *already_owned = false;
    return false;
  }
  *already_owned = false;
  // Makes sure EK is there when unowned.
  if (ownership_status != TpmStatus::kTpmUnowned) {
    LOG(INFO) << __func__
              << ": TPM ownership is taken already; skip initializing EK.";
  } else if (!InitializeEndorsementKey()) {
    LOG(ERROR) << __func__ << ": failed to initialize endorsement key";
    return false;
  }
  TpmConnection connection(GetDefaultOwnerPassword());
  if (ownership_status != TpmStatus::kTpmUnowned) {
    LOG(INFO) << __func__
              << ": TPM ownership is taken already; skip taking ownership.";
  } else if (!TakeOwnership(&connection)) {
    LOG(ERROR) << __func__ << ": failed to take TPM ownership";
    return false;
  }
  // TPM ownership is taken; now the status is pre-owned.
  if (!InitializeSrk(&connection)) {
    LOG(ERROR) << __func__ << ": failed to initialize SRK";
    return false;
  }
  std::string owner_password;
  std::string random_bytes;
  if (!openssl_util_.GetRandomBytes(kOwnerPasswordRandomBytes, &random_bytes)) {
    return false;
  }
  owner_password = base::HexEncode(random_bytes.data(), random_bytes.size());
  LocalData local_data;
  local_data.clear_owner_dependency();
  for (auto value : kInitialTpmOwnerDependencies) {
    local_data.add_owner_dependency(value);
  }
  local_data.set_owner_password(owner_password);
  if (!local_data_store_->Write(local_data)) {
    LOG(ERROR) << ": Error saving local data after |set_owner_password|.";
    return false;
  }
  if (!ChangeOwnerPassword(&connection, owner_password)) {
    return false;
  }
  tpm_status_->MarkRandomOwnerPasswordSet();

  // for performance sake, continue using the same |local_data| so we don't need
  // to read the data from file once again.
  AuthDelegate owner_delegate;
  if (CreateDelegateWithDefaultLabel(&owner_delegate)) {
    local_data.mutable_owner_delegate()->Swap(&owner_delegate);
    if (!local_data_store_->Write(local_data)) {
      LOG(ERROR) << ": Cannot persist delegate.";
      return false;
    }
  } else {
    LOG(ERROR) << __func__ << ": Cannot create delegate.";
    return false;
  }

  reset_da_lock_auth_failed_ = false;
  return true;
}

void TpmInitializerImpl::VerifiedBootHelper() {
  // Nothing to do.
}

DictionaryAttackResetStatus TpmInitializerImpl::ResetDictionaryAttackLock() {
  if (reset_da_lock_auth_failed_) {
    // An auth error was encountered in a previous attempt, and there was no
    // auth update after the attempt. Skips the request to avoid further
    // increasing the counter.
    LOG(ERROR) << __func__
               << ": skipped the request to avoid repeating a "
                  "previous auth error.";
    return DictionaryAttackResetStatus::kResetAttemptFailed;
  }

  TpmStatus::TpmOwnershipStatus ownership_status;
  if (!tpm_status_->GetTpmOwned(&ownership_status)) {
    // Can't tell if we really can't get tpm ownership status or lockout is in
    // our way, so let's still go ahead.
    LOG(WARNING) << __func__
                 << ": failed to get tpm ownership status, but that could be "
                    "caused by a locked out TPM, so proceeding anyway.";
  } else {
    if (ownership_status != TpmStatus::kTpmOwned) {
      LOG(ERROR) << __func__ << ": TPM is not initialized yet.";
      return DictionaryAttackResetStatus::kResetAttemptFailed;
    }
  }

  std::string owner_password;
  AuthDelegate owner_delegate;
  if (!ReadOwnerAuthFromLocalData(&owner_password, &owner_delegate)) {
    // Note that if it failed here, it could be because the TPM is not owned,
    // but we tried anyway because we can't get the TPM status. See comments
    // above on GetTpmOwned().
    LOG(ERROR) << __func__ << ": failed to get owner auth.";
    return DictionaryAttackResetStatus::kResetAttemptFailed;
  }

  std::unique_ptr<TpmConnection> connection;
  if (!owner_password.empty()) {
    connection = std::make_unique<TpmConnection>(owner_password);
  } else if (!owner_delegate.blob().empty() &&
             !owner_delegate.secret().empty()) {
    if (!owner_delegate.has_reset_lock_permissions()) {
      return DictionaryAttackResetStatus::kDelegateNotAllowed;
    }
    connection = std::make_unique<TpmConnection>(owner_delegate);
  } else {
    LOG(ERROR) << __func__ << ": available owner auth not found.";
    return DictionaryAttackResetStatus::kDelegateNotAvailable;
  }

  TSS_HTPM tpm_handle = connection->GetTpm();
  if (!tpm_handle) {
    LOG(ERROR) << __func__ << ": Error getting a TPM handle.";
    return DictionaryAttackResetStatus::kResetAttemptFailed;
  }

  TSS_RESULT result = GetOveralls()->Ospi_TPM_SetStatus(
      tpm_handle, TSS_TPMSTATUS_RESETLOCK, true /* value will be ignored */);
  if (result != TSS_SUCCESS) {
    TPM_LOG(ERROR, result) << __func__ << ": failed to reset DA lock.";
    if (TPM_ERROR(TPM_E_AUTHFAIL) == result ||
        TPM_ERROR(TPM_E_AUTH2FAIL) == result) {
      reset_da_lock_auth_failed_ = true;
    }

    return result == TPM_ERROR(TPM_E_WRONGPCRVAL)
               ? DictionaryAttackResetStatus::kInvalidPcr0State
               : DictionaryAttackResetStatus::kResetAttemptFailed;
  }

  LOG(INFO) << __func__ << ": dictionary attack counter has been reset.";
  return DictionaryAttackResetStatus::kResetAttemptSucceeded;
}

TpmInitializerStatus TpmInitializerImpl::DisableDictionaryAttackMitigation() {
  return TpmInitializerStatus::kNotSupport;
}

void TpmInitializerImpl::PruneStoredPasswords() {
  TpmStatus::TpmOwnershipStatus ownership_status;
  if (!tpm_status_->GetTpmOwned(&ownership_status)) {
    LOG(ERROR) << __func__ << ": failed to get tpm ownership status";
    return;
  }

  if (ownership_status == TpmStatus::kTpmOwned) {
    LOG(WARNING) << __func__
                 << ": TPM is already owned. Local data won't be touched.";
    return;
  }

  LocalData local_data;
  if (!local_data_store_->Read(&local_data)) {
    LOG(ERROR) << __func__ << ": failed to read local data.";
    return;
  }

  local_data.clear_owner_password();
  local_data.clear_owner_delegate();
  local_data.clear_owner_dependency();

  if (!local_data_store_->Write(local_data)) {
    LOG(ERROR) << __func__ << ": failed to write local data.";
  }
}

bool TpmInitializerImpl::ChangeOwnerPassword(const std::string& old_password,
                                             const std::string& new_password) {
  LOG(INFO) << __func__ << ": attempting to change old tpm owner password"
            << " to a new owner password";
  TpmConnection connection(old_password);
  return ChangeOwnerPassword(&connection, new_password);
}

bool TpmInitializerImpl::InitializeEndorsementKey() {
  TpmConnection connection;
  trousers::ScopedTssKey local_key_handle(connection.GetContext());
  TSS_RESULT result = Tspi_TPM_GetPubEndorsementKey(
      connection.GetTpm(), false, nullptr, local_key_handle.ptr());
  if (TPM_ERROR(result) == TPM_SUCCESS) {
    // In this case the EK already exists, so we can return true here.
    VLOG(1) << "EK already exists.";
    return true;
  } else if (TPM_ERROR(result) != TPM_E_NO_ENDORSEMENT) {
    TPM_LOG(ERROR, result) << "Error calling Tspi_TPM_GetPubEndorsementKey";
    return false;
  }
  TPM_LOG(INFO, result) << "No EK is present; creating it.";
  TSS_FLAG init_flags = TSS_KEY_TYPE_LEGACY | TSS_KEY_SIZE_2048;
  if (TPM_ERROR(result = Tspi_Context_CreateObject(
                    connection.GetContext(), TSS_OBJECT_TYPE_RSAKEY, init_flags,
                    local_key_handle.ptr()))) {
    TPM_LOG(ERROR, result) << "Error calling Tspi_Context_CreateObject";
    return false;
  }
  if (TPM_ERROR(result = Tspi_TPM_CreateEndorsementKey(
                    connection.GetTpm(), local_key_handle, NULL))) {
    TPM_LOG(ERROR, result) << "Error calling Tspi_TPM_CreateEndorsementKey";
    return false;
  }
  return true;
}

bool TpmInitializerImpl::TakeOwnership(TpmConnection* connection) {
  TSS_RESULT result;
  trousers::ScopedTssKey srk_handle(connection->GetContext());
  TSS_FLAG init_flags = TSS_KEY_TSP_SRK | TSS_KEY_AUTHORIZATION;
  if (TPM_ERROR(result = Tspi_Context_CreateObject(
                    connection->GetContext(), TSS_OBJECT_TYPE_RSAKEY,
                    init_flags, srk_handle.ptr()))) {
    TPM_LOG(ERROR, result) << "Error calling Tspi_Context_CreateObject";
    return false;
  }
  TSS_HPOLICY srk_usage_policy;
  if (TPM_ERROR(result = Tspi_GetPolicyObject(srk_handle, TSS_POLICY_USAGE,
                                              &srk_usage_policy))) {
    TPM_LOG(ERROR, result) << "Error calling Tspi_GetPolicyObject";
    return false;
  }
  if (TPM_ERROR(result = Tspi_Policy_SetSecret(
                    srk_usage_policy, TSS_SECRET_MODE_PLAIN,
                    strlen(kWellKnownSrkSecret),
                    const_cast<BYTE*>(
                        reinterpret_cast<const BYTE*>(kWellKnownSrkSecret))))) {
    TPM_LOG(ERROR, result) << "Error calling Tspi_Policy_SetSecret";
    return false;
  }
  // Tspi_TPM_TakeOwnership can potentially take a long time to complete,
  // so we retry if there is a timeout in any layer. I chose 5, because the
  // longest TakeOwnership call that I have seen took ~2min, and the default
  // TSS timeout is 30s. This means that after 5 calls, it is quite likely that
  // this call will succeed.
  int retry_count = 0;
  do {
    result = Tspi_TPM_TakeOwnership(connection->GetTpm(), srk_handle, 0);
    retry_count++;
  } while (((result == TDDL_E_TIMEOUT) ||
            (result == (TSS_LAYER_TDDL | TDDL_E_TIMEOUT)) ||
            (result == (TSS_LAYER_TDDL | TDDL_E_IOERROR))) &&
           (retry_count < kMaxOwnershipTimeoutRetries));
  if (result) {
    TPM_LOG(ERROR, result) << "Error calling Tspi_TPM_TakeOwnership, attempts: "
                           << retry_count;
    return false;
  }

  return true;
}

bool TpmInitializerImpl::InitializeSrk(TpmConnection* connection) {
  TSS_RESULT result;
  trousers::ScopedTssKey srk_handle(connection->GetContext());
  TSS_UUID SRK_UUID = TSS_UUID_SRK;
  if (TPM_ERROR(result = Tspi_Context_LoadKeyByUUID(
                    connection->GetContext(), TSS_PS_TYPE_SYSTEM, SRK_UUID,
                    srk_handle.ptr()))) {
    TPM_LOG(ERROR, result) << "Error calling Tspi_Context_LoadKeyByUUID";
    return false;
  }

  trousers::ScopedTssPolicy policy_handle(connection->GetContext());
  if (TPM_ERROR(result = Tspi_Context_CreateObject(
                    connection->GetContext(), TSS_OBJECT_TYPE_POLICY,
                    TSS_POLICY_USAGE, policy_handle.ptr()))) {
    TPM_LOG(ERROR, result) << "Error calling Tspi_Context_CreateObject";
    return false;
  }
  BYTE new_password[0];
  if (TPM_ERROR(result = Tspi_Policy_SetSecret(
                    policy_handle, TSS_SECRET_MODE_PLAIN, 0, new_password))) {
    TPM_LOG(ERROR, result) << "Error calling Tspi_Policy_SetSecret";
    return false;
  }

  if (TPM_ERROR(result = Tspi_ChangeAuth(srk_handle, connection->GetTpm(),
                                         policy_handle))) {
    TPM_LOG(ERROR, result) << "Error calling Tspi_ChangeAuth";
    return false;
  }
  TSS_BOOL is_srk_restricted = false;
  if (TPM_ERROR(result = Tspi_TPM_GetStatus(connection->GetTpm(),
                                            TSS_TPMSTATUS_DISABLEPUBSRKREAD,
                                            &is_srk_restricted))) {
    TPM_LOG(ERROR, result) << "Error calling Tspi_TPM_GetStatus";
    return false;
  }
  // If the SRK is restricted, we unrestrict it.
  if (is_srk_restricted) {
    if (TPM_ERROR(result = Tspi_TPM_SetStatus(connection->GetTpm(),
                                              TSS_TPMSTATUS_DISABLEPUBSRKREAD,
                                              false))) {
      TPM_LOG(ERROR, result) << "Error calling Tspi_TPM_SetStatus";
      return false;
    }
  }
  return true;
}

bool TpmInitializerImpl::ChangeOwnerPassword(
    TpmConnection* connection, const std::string& owner_password) {
  TSS_RESULT result;
  trousers::ScopedTssPolicy policy_handle(connection->GetContext());
  if (TPM_ERROR(result = Tspi_Context_CreateObject(
                    connection->GetContext(), TSS_OBJECT_TYPE_POLICY,
                    TSS_POLICY_USAGE, policy_handle.ptr()))) {
    TPM_LOG(ERROR, result) << "Error calling Tspi_Context_CreateObject";
    return false;
  }
  std::string mutable_owner_password(owner_password);
  if (TPM_ERROR(
          result = Tspi_Policy_SetSecret(
              policy_handle, TSS_SECRET_MODE_PLAIN, owner_password.size(),
              reinterpret_cast<BYTE*>(std::data(mutable_owner_password))))) {
    TPM_LOG(ERROR, result) << "Error calling Tspi_Policy_SetSecret";
    return false;
  }

  if (TPM_ERROR(result =
                    Tspi_ChangeAuth(connection->GetTpm(), 0, policy_handle))) {
    TPM_LOG(ERROR, result) << "Error calling Tspi_ChangeAuth";
    return false;
  }

  return true;
}

bool TpmInitializerImpl::ReadOwnerAuthFromLocalData(
    std::string* owner_password, AuthDelegate* owner_delegate) {
  LocalData local_data;
  if (!local_data_store_->Read(&local_data)) {
    LOG(ERROR) << __func__ << ": Failed to read local data.";
    return false;
  }

  if (owner_password) {
    *owner_password = local_data.owner_password();
  }

  if (owner_delegate) {
    *owner_delegate = local_data.owner_delegate();
  }

  return true;
}

bool TpmInitializerImpl::CreateDelegateWithDefaultLabel(
    AuthDelegate* delegate) {
  std::string delegate_blob;
  std::string delegate_secret;
  // No PCR value bound to the delegate by default (crbug/990322, b/139099154).
  if (!CreateAuthDelegate(/*bound_pcrs=*/{}, kDefaultDelegateFamilyLabel,
                          kDefaultDelegateLabel, &delegate_blob,
                          &delegate_secret)) {
    LOG(ERROR) << __func__ << ": Failed to create delegate.";
    return false;
  }
  delegate->set_blob(delegate_blob);
  delegate->set_secret(delegate_secret);
  delegate->set_has_reset_lock_permissions(true);
  return true;
}

bool TpmInitializerImpl::EnsurePersistentOwnerDelegate() {
  LocalData local_data;
  if (!local_data_store_->Read(&local_data)) {
    LOG(ERROR) << __func__ << ": Failed to read local data.";
    return false;
  }
  auto owner_delegate = local_data.mutable_owner_delegate();
  if (!owner_delegate->blob().empty() && !owner_delegate->secret().empty()) {
    if (CheckResetLockPermissions(owner_delegate)) {
      // Resave the local data.
      if (!local_data_store_->Write(local_data)) {
        LOG(ERROR) << __func__ << ": Failed to write local data change.";
        return false;
      }
    }

    return true;
  }
  LOG(WARNING) << __func__ << ": Owner delegate is missing; re-creating.";
  if (!CreateDelegateWithDefaultLabel(owner_delegate)) {
    LOG(ERROR) << __func__ << ": Failed to create owner delegate.";
    return false;
  }
  if (!local_data_store_->Write(local_data)) {
    LOG(ERROR) << __func__ << ": Failed to write local data change.";
    return false;
  }
  return true;
}

bool TpmInitializerImpl::CreateAuthDelegate(
    const std::vector<uint32_t>& bound_pcrs,
    uint8_t delegate_family_label,
    uint8_t delegate_label,
    std::string* delegate_blob,
    std::string* delegate_secret) {
  CHECK(delegate_blob && delegate_secret);

  // Connects to the TPM as the owner.

  // read the owner password.
  // TODO(cylai): provide a clean way to retrieve owner password for this class.
  std::string owner_password;
  if (!ReadOwnerAuthFromLocalData(&owner_password, nullptr) ||
      owner_password.empty()) {
    LOG(ERROR) << __func__ << ": couldn't get owner password.";
    return false;
  }

  TpmConnection connection(owner_password);
  TSS_HCONTEXT context_handle = connection.GetContext();
  TSS_HTPM tpm_handle = connection.GetTpm();
  if (!context_handle || !tpm_handle) {
    LOG(ERROR) << __func__ << "TPM connection error.";
    return false;
  }

  // Generate a delegate secret.
  if (!openssl_util_.GetRandomBytes(kDelegateSecretSize, delegate_secret)) {
    return false;
  }

  // Create an owner delegation policy.
  trousers::ScopedTssPolicy policy(context_handle);
  TSS_RESULT result;
  result = Tspi_Context_CreateObject(context_handle, TSS_OBJECT_TYPE_POLICY,
                                     TSS_POLICY_USAGE, policy.ptr());
  if (TPM_ERROR(result)) {
    TPM_LOG(ERROR, result) << "CreateDelegate: Failed to create policy.";
    return false;
  }
  result = Tspi_Policy_SetSecret(
      policy, TSS_SECRET_MODE_PLAIN, delegate_secret->size(),
      reinterpret_cast<BYTE*>(const_cast<char*>(delegate_secret->data())));
  if (TPM_ERROR(result)) {
    TPM_LOG(ERROR, result) << "CreateDelegate: Failed to set policy secret.";
    return false;
  }
  result =
      Tspi_SetAttribUint32(policy, TSS_TSPATTRIB_POLICY_DELEGATION_INFO,
                           TSS_TSPATTRIB_POLDEL_TYPE, TSS_DELEGATIONTYPE_OWNER);
  if (TPM_ERROR(result)) {
    TPM_LOG(ERROR, result) << "CreateDelegate: Failed to set delegation type.";
    return false;
  }
  // These are the privileged operations we will allow the delegate to perform.
  constexpr UINT32 permissions =
      TPM_DELEGATE_ActivateIdentity | TPM_DELEGATE_DAA_Join |
      TPM_DELEGATE_DAA_Sign | TPM_DELEGATE_ResetLockValue |
      TPM_DELEGATE_OwnerReadInternalPub | TPM_DELEGATE_CMK_ApproveMA |
      TPM_DELEGATE_CMK_CreateTicket | TPM_DELEGATE_AuthorizeMigrationKey;
  result = Tspi_SetAttribUint32(policy, TSS_TSPATTRIB_POLICY_DELEGATION_INFO,
                                TSS_TSPATTRIB_POLDEL_PER1, permissions);
  if (TPM_ERROR(result)) {
    TPM_LOG(ERROR, result) << "CreateDelegate: Failed to set permissions.";
    return false;
  }
  result = Tspi_SetAttribUint32(policy, TSS_TSPATTRIB_POLICY_DELEGATION_INFO,
                                TSS_TSPATTRIB_POLDEL_PER2, 0);
  if (TPM_ERROR(result)) {
    TPM_LOG(ERROR, result) << "CreateDelegate: Failed to set permissions.";
    return false;
  }

  // Bind the delegate to the specified PCRs. Note: it's crucial to pass a null
  // TSS_HPCRS to Tspi_TPM_Delegate_CreateDelegation() when no PCR is selected,
  // otherwise it will fail with TPM_E_BAD_PARAM_SIZE.
  trousers::ScopedTssPcrs pcrs_handle(context_handle);
  if (!bound_pcrs.empty()) {
    result = Tspi_Context_CreateObject(context_handle, TSS_OBJECT_TYPE_PCRS,
                                       TSS_PCRS_STRUCT_INFO_SHORT,
                                       pcrs_handle.ptr());
    if (TPM_ERROR(result)) {
      TPM_LOG(ERROR, result) << "CreateDelegate: Failed to create PCRS object.";
      return false;
    }
    for (auto bound_pcr : bound_pcrs) {
      UINT32 pcr_len = 0;
      trousers::ScopedTssMemory pcr_value(context_handle);
      if (TPM_ERROR(result = Tspi_TPM_PcrRead(tpm_handle, bound_pcr, &pcr_len,
                                              pcr_value.ptr()))) {
        TPM_LOG(ERROR, result) << "Could not read PCR value";
        return false;
      }
      result = Tspi_PcrComposite_SetPcrValue(pcrs_handle, bound_pcr, pcr_len,
                                             pcr_value.value());
      if (TPM_ERROR(result)) {
        TPM_LOG(ERROR, result) << "Could not set value for PCR in PCRS handle";
        return false;
      }
    }
    constexpr unsigned int kTpmPCRLocality = 1;
    result = Tspi_PcrComposite_SetPcrLocality(pcrs_handle, kTpmPCRLocality);
    if (TPM_ERROR(result)) {
      TPM_LOG(ERROR, result)
          << "Could not set locality for PCRs in PCRS handle";
      return false;
    }
  }

  // Create a delegation family.
  trousers::ScopedTssObject<TSS_HDELFAMILY> family(context_handle);
  result = Tspi_TPM_Delegate_AddFamily(tpm_handle, delegate_family_label,
                                       family.ptr());
  if (TPM_ERROR(result)) {
    TPM_LOG(ERROR, result) << "CreateDelegate: Failed to create family.";
    return false;
  }

  // Create the delegation.
  result = Tspi_TPM_Delegate_CreateDelegation(tpm_handle, delegate_label, 0,
                                              pcrs_handle, family, policy);
  if (TPM_ERROR(result)) {
    TPM_LOG(ERROR, result) << "CreateDelegate: Failed to create delegation.";
    return false;
  }

  // Enable the delegation family.
  result = Tspi_SetAttribUint32(family, TSS_TSPATTRIB_DELFAMILY_STATE,
                                TSS_TSPATTRIB_DELFAMILYSTATE_ENABLED, TRUE);
  if (TPM_ERROR(result)) {
    TPM_LOG(ERROR, result) << "CreateDelegate: Failed to enable family.";
    return false;
  }

  // Save the delegation blob for later.
  if (!GetDataAttribute(context_handle, policy,
                        TSS_TSPATTRIB_POLICY_DELEGATION_INFO,
                        TSS_TSPATTRIB_POLDEL_OWNERBLOB, delegate_blob)) {
    LOG(ERROR) << "CreateDelegate: Failed to get delegate blob.";
    return false;
  }

  return true;
}

bool TpmInitializerImpl::GetDataAttribute(TSS_HCONTEXT context,
                                          TSS_HOBJECT object,
                                          TSS_FLAG flag,
                                          TSS_FLAG sub_flag,
                                          std::string* data) {
  UINT32 length = 0;
  trousers::ScopedTssMemory buffer(context);
  TSS_RESULT result =
      Tspi_GetAttribData(object, flag, sub_flag, &length, buffer.ptr());
  if (TPM_ERROR(result)) {
    TPM_LOG(ERROR, result) << __func__ << "Failed to read object attribute.";
    return false;
  }
  data->assign(buffer.value(), buffer.value() + length);
  return true;
}

}  // namespace tpm_manager
