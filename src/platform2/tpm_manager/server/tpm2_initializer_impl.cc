// Copyright 2015 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "tpm_manager/server/tpm2_initializer_impl.h"

#include <string>

#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <tpm_manager/proto_bindings/tpm_manager.pb.h>
#include <tpm_manager-client/tpm_manager/dbus-constants.h>
#include <trunks/error_codes.h>
#include <trunks/tpm_state.h>
#include <trunks/tpm_utility.h>
#include <trunks/trunks_factory_impl.h>

using trunks::TPM_RC;
using trunks::TPM_RC_SUCCESS;

namespace {
// Owner password is human-readable, so produce N random bytes and then
// hexdump them into N*2 password characters. For other passwords, just
// generate N*2 random bytes.
const size_t kOwnerPasswordRandomBytes = 10;
const size_t kDefaultPasswordSize = kOwnerPasswordRandomBytes * 2;
}  // namespace

namespace tpm_manager {

Tpm2InitializerImpl::Tpm2InitializerImpl(const trunks::TrunksFactory& factory,
                                         LocalDataStore* local_data_store,
                                         TpmStatus* tpm_status)
    : trunks_factory_(factory),
      openssl_util_(&default_openssl_util_),
      local_data_store_(local_data_store),
      tpm_status_(tpm_status) {}

Tpm2InitializerImpl::Tpm2InitializerImpl(const trunks::TrunksFactory& factory,
                                         OpensslCryptoUtil* openssl_util,
                                         LocalDataStore* local_data_store,
                                         TpmStatus* tpm_status)
    : trunks_factory_(factory),
      openssl_util_(openssl_util),
      local_data_store_(local_data_store),
      tpm_status_(tpm_status) {}

bool Tpm2InitializerImpl::PreInitializeTpm() {
  TPM_RC result = trunks_factory_.GetTpmUtility()->PrepareForOwnership();
  if (result != TPM_RC_SUCCESS) {
    LOG(WARNING) << "Pre-initializing TPM2.0 failed.";
    return false;
  }

  return true;
}

bool Tpm2InitializerImpl::InitializeTpm(bool* already_owned) {
  if (!SeedTpmRng()) {
    return false;
  }

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
  *already_owned = false;

  // First we read the local data. If we did not finish removing owner
  // dependencies or if TakeOwnership failed, we want to retake ownership
  // with the same passwords.
  LocalData local_data;
  if (!local_data_store_->Read(&local_data)) {
    LOG(ERROR) << "Error reading local data.";
    return false;
  }
  std::string owner_password;
  std::string endorsement_password;
  std::string lockout_password;
  // If there are valid owner dependencies, we need to reuse the old passwords.
  if (local_data.owner_dependency_size() > 0) {
    owner_password.assign(local_data.owner_password());
    endorsement_password.assign(local_data.endorsement_password());
    lockout_password.assign(local_data.lockout_password());
  } else {
    // Generate a human-readable owner password as a hexdump of random bytes.
    std::string random_bytes;
    if (!GetTpmRandomData(kOwnerPasswordRandomBytes, &random_bytes)) {
      LOG(ERROR) << "Error generating a random owner password.";
      return false;
    }
    owner_password = base::HexEncode(random_bytes.data(), random_bytes.size());
    // Other passwords don't have to be printable.
    if (!GetTpmRandomData(kDefaultPasswordSize, &endorsement_password)) {
      LOG(ERROR) << "Error generating a random endorsement password.";
      return false;
    }
    if (!GetTpmRandomData(kDefaultPasswordSize, &lockout_password)) {
      LOG(ERROR) << "Error generating a random lockout password.";
      return false;
    }
  }
  // We write the passwords to disk, in case there is an error while taking
  // ownership.
  local_data.clear_owner_dependency();
  for (auto dependency : kInitialTpmOwnerDependencies) {
    local_data.add_owner_dependency(dependency);
  }
  local_data.set_owner_password(owner_password);
  local_data.set_endorsement_password(endorsement_password);
  local_data.set_lockout_password(lockout_password);
  if (!local_data_store_->Write(local_data)) {
    LOG(ERROR) << "Error saving local data.";
    return false;
  }
  TPM_RC result = trunks_factory_.GetTpmUtility()->TakeOwnership(
      owner_password, endorsement_password, lockout_password);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error taking ownership of TPM2.0";
    return false;
  }

  return true;
}

void Tpm2InitializerImpl::VerifiedBootHelper() {
// TODO(http://crosbug.com/p/59837): restore when TPM_RC_PCR_CHANGED is
// properly handled.
#if 0
  constexpr char kVerifiedBootLateStageTag[] = "BOOT_PCR_LATE_STAGE";
#endif
  std::unique_ptr<trunks::TpmUtility> tpm_utility =
      trunks_factory_.GetTpmUtility();
  // Make sure PCRs 0-3 can't be spoofed from this point forward.
  for (int pcr : {0, 1, 2, 3}) {
    std::string value;
    TPM_RC result = tpm_utility->ReadPCR(pcr, &value);
    if (result) {
      LOG(ERROR) << "Failed to read PCR " << pcr << ": "
                 << trunks::GetErrorString(result);
      continue;
    }
    if (value == std::string(32, 0)) {
      LOG(WARNING) << "WARNING: Verified boot PCR " << pcr
                   << " is not initialized.";
// TODO(http://crosbug.com/p/59837): restore when TPM_RC_PCR_CHANGED is
// properly handled.
#if 0
      result = tpm_utility->ExtendPCR(pcr, kVerifiedBootLateStageTag, nullptr);
      if (result) {
        LOG(ERROR) << "Failed to extend PCR " << pcr << ": "
                   << trunks::GetErrorString(result);
      }
#endif
    }
  }
}

DictionaryAttackResetStatus Tpm2InitializerImpl::ResetDictionaryAttackLock() {
  LocalData local_data;
  if (!local_data_store_->Read(&local_data)) {
    LOG(ERROR) << __func__ << ": Error reading local data.";
    return DictionaryAttackResetStatus::kResetAttemptFailed;
  }
  if (local_data.lockout_password().empty()) {
    LOG(ERROR) << __func__ << ": Lockout password not available.";
    return DictionaryAttackResetStatus::kResetAttemptFailed;
  }
  std::unique_ptr<trunks::HmacSession> session =
      trunks_factory_.GetHmacSession();
  TPM_RC result = session->StartUnboundSession(true, false);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << __func__ << ": Error initializing AuthorizationSession: "
               << trunks::GetErrorString(result);
    return DictionaryAttackResetStatus::kResetAttemptFailed;
  }
  session->SetEntityAuthorizationValue(local_data.lockout_password());
  std::unique_ptr<trunks::TpmUtility> tpm_utility =
      trunks_factory_.GetTpmUtility();
  result = tpm_utility->ResetDictionaryAttackLock(session->GetDelegate());
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << __func__
               << ": Error resetting lock: " << trunks::GetErrorString(result);
    return DictionaryAttackResetStatus::kResetAttemptFailed;
  }
  return DictionaryAttackResetStatus::kResetAttemptSucceeded;
}

TpmInitializerStatus Tpm2InitializerImpl::DisableDictionaryAttackMitigation() {
  LocalData local_data;
  if (!local_data_store_->Read(&local_data)) {
    LOG(ERROR) << __func__ << ": Error reading local data.";
    return TpmInitializerStatus::kFailure;
  }
  if (local_data.lockout_password().empty()) {
    LOG(ERROR) << __func__ << ": Lockout password not available.";
    return TpmInitializerStatus::kFailure;
  }
  std::unique_ptr<trunks::HmacSession> session =
      trunks_factory_.GetHmacSession();
  TPM_RC result = session->StartUnboundSession(true, false);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << __func__ << ": Error initializing AuthorizationSession: "
               << trunks::GetErrorString(result);
    return TpmInitializerStatus::kFailure;
  }
  session->SetEntityAuthorizationValue(local_data.lockout_password());
  std::unique_ptr<trunks::TpmUtility> tpm_utility =
      trunks_factory_.GetTpmUtility();
  result = tpm_utility->SetDictionaryAttackParameters(
      /*max_tries=*/200, /*recovery_time=*/0, /*lockout_recovery=*/0,
      session->GetDelegate());
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << __func__ << ": Error calling SetDictionaryAttackParameters: "
               << trunks::GetErrorString(result);
    return TpmInitializerStatus::kFailure;
  }
  return TpmInitializerStatus::kSuccess;
}

void Tpm2InitializerImpl::PruneStoredPasswords() {
  std::unique_ptr<trunks::TpmState> trunks_tpm_state =
      trunks_factory_.GetTpmState();
  if (trunks_tpm_state->Initialize() != trunks::TPM_RC_SUCCESS) {
    LOG(ERROR) << __func__ << ": failed to refresh trunks tpm state";
    return;
  }

  if (trunks_tpm_state->IsEndorsementPasswordSet()) {
    LOG(WARNING) << __func__ << ": take ownership already started. "
                 << "Local data won't be touched.";
    return;
  }

  LocalData local_data;
  if (!local_data_store_->Read(&local_data)) {
    LOG(ERROR) << __func__ << ": failed to read local data.";
    return;
  }

  local_data.clear_owner_password();
  local_data.clear_lockout_password();
  local_data.clear_endorsement_password();
  local_data.clear_owner_dependency();

  if (!local_data_store_->Write(local_data)) {
    LOG(ERROR) << __func__ << ": failed to write local data.";
  }
}

bool Tpm2InitializerImpl::ChangeOwnerPassword(const std::string& old_password,
                                              const std::string& new_password) {
  LOG(INFO) << __func__ << ": attempting to change old tpm2.0 owner password"
            << " to a new owner password";
  TPM_RC result = trunks_factory_.GetTpmUtility()->ChangeOwnerPassword(
      old_password, new_password);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error changing owner password of TPM2.0";
    return false;
  }

  return true;
}

bool Tpm2InitializerImpl::SeedTpmRng() {
  std::string random_bytes;
  if (!openssl_util_->GetRandomBytes(kDefaultPasswordSize, &random_bytes)) {
    return false;
  }
  TPM_RC result = trunks_factory_.GetTpmUtility()->StirRandom(
      random_bytes, nullptr /* No Authorization */);
  if (result != TPM_RC_SUCCESS) {
    return false;
  }
  return true;
}

bool Tpm2InitializerImpl::GetTpmRandomData(size_t num_bytes,
                                           std::string* random_data) {
  TPM_RC result = trunks_factory_.GetTpmUtility()->GenerateRandom(
      num_bytes, nullptr /* No Authorization */, random_data);
  if (result != TPM_RC_SUCCESS) {
    return false;
  }
  return true;
}

bool Tpm2InitializerImpl::EnsurePersistentOwnerDelegate() {
  return true;
}

}  // namespace tpm_manager
