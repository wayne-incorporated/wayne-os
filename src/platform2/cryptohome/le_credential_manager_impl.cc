// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/le_credential_manager_impl.h"

#include <fcntl.h>

#include <optional>
#include <string>
#include <utility>

#include <base/check.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <libhwsec-foundation/crypto/secure_blob_util.h>
#include <libhwsec-foundation/status/status_chain_macros.h>

#include "cryptohome/cryptohome_metrics.h"
#include "cryptohome/error/cryptohome_tpm_error.h"
#include "cryptohome/error/location_utils.h"

namespace {

// Constants used to define the hash tree.
constexpr uint32_t kLengthLabels = 14;
constexpr uint32_t kBitsPerLevel = 2;

}  // namespace

using ::cryptohome::error::CryptohomeLECredError;
using ::cryptohome::error::CryptohomeTPMError;
using ::cryptohome::error::ErrorActionSet;
using ::cryptohome::error::PossibleAction;
using ::cryptohome::error::PrimaryAction;
using ::hwsec_foundation::GetSecureRandom;
using ::hwsec_foundation::status::MakeStatus;
using ::hwsec_foundation::status::OkStatus;
using ::hwsec_foundation::status::StatusChain;

using CredentialTreeResult = hwsec::PinWeaverFrontend::CredentialTreeResult;
using DelaySchedule = hwsec::PinWeaverFrontend::DelaySchedule;
using GetLogResult = hwsec::PinWeaverFrontend::GetLogResult;
using ReplayLogOperationResult =
    hwsec::PinWeaverFrontend::ReplayLogOperationResult;

namespace cryptohome {

LECredentialManagerImpl::LECredentialManagerImpl(
    const hwsec::PinWeaverFrontend* pinweaver, const base::FilePath& le_basedir)
    : is_locked_(false), pinweaver_(pinweaver), basedir_(le_basedir) {
  CHECK(pinweaver_);

  // Check if hash tree already exists.
  bool new_hash_tree = !base::PathExists(le_basedir);

  hash_tree_ = std::make_unique<SignInHashTree>(kLengthLabels, kBitsPerLevel,
                                                le_basedir);
  if (!hash_tree_->IsValid()) {
    LOG(ERROR)
        << "Failed to initialize LE credential manager: invalid hash tree";
    return;
  }

  // Reset the root hash in the TPM to its initial value.
  if (new_hash_tree) {
    hwsec::StatusOr<CredentialTreeResult> result =
        pinweaver_->Reset(kBitsPerLevel, kLengthLabels);
    if (!result.ok()) {
      LOG(ERROR) << "Failed to reset pinweaver: " << result.status();
      return;
    }
    root_hash_ = result->new_root;

    hash_tree_->GenerateAndStoreHashCache();
  }
}

LECredStatus LECredentialManagerImpl::InsertCredential(
    const std::vector<hwsec::OperationPolicySetting>& policies,
    const brillo::SecureBlob& le_secret,
    const brillo::SecureBlob& he_secret,
    const brillo::SecureBlob& reset_secret,
    const DelaySchedule& delay_sched,
    std::optional<uint32_t> expiration_delay,
    uint64_t* ret_label) {
  return InsertLeaf(nullptr, policies, &le_secret, &he_secret, reset_secret,
                    delay_sched, expiration_delay, /*is_rate_limiter=*/false,
                    ret_label);
}

LECredStatus LECredentialManagerImpl::CheckCredential(
    uint64_t label,
    const brillo::SecureBlob& le_secret,
    brillo::SecureBlob* he_secret,
    brillo::SecureBlob* reset_secret) {
  return CheckSecret(label, le_secret, he_secret, reset_secret, false, true);
}

LECredStatus LECredentialManagerImpl::ResetCredential(
    uint64_t label, const brillo::SecureBlob& reset_secret, bool strong_reset) {
  return CheckSecret(label, reset_secret, nullptr, nullptr, strong_reset,
                     false);
}

LECredStatus LECredentialManagerImpl::RemoveCredential(uint64_t label) {
  return RemoveCredentialInternal(label, /*during_sync=*/false);
}

LECredStatus LECredentialManagerImpl::CheckSecret(
    uint64_t label,
    const brillo::SecureBlob& secret,
    brillo::SecureBlob* he_secret,
    brillo::SecureBlob* reset_secret,
    bool strong_reset,
    bool is_le_secret) {
  if (!hash_tree_->IsValid() || !Sync()) {
    return MakeStatus<CryptohomeLECredError>(
        CRYPTOHOME_ERR_LOC(kLocLECredManInvalidTreeInCheckSecret),
        ErrorActionSet({PossibleAction::kReboot, PossibleAction::kAuth}),
        LECredError::LE_CRED_ERROR_HASH_TREE);
  }

  if (he_secret) {
    he_secret->clear();
  }

  if (reset_secret) {
    reset_secret->clear();
  }

  const char* uma_log_op = is_le_secret ? kLEOpCheck : kLEOpReset;

  SignInHashTree::Label label_object(label, kLengthLabels, kBitsPerLevel);

  brillo::Blob orig_cred, orig_mac;
  std::vector<brillo::Blob> h_aux;
  bool metadata_lost;
  LECredStatus ret = RetrieveLabelInfo(label_object, &orig_cred, &orig_mac,
                                       &h_aux, &metadata_lost);
  if (!ret.ok()) {
    ReportLEResult(uma_log_op, kLEActionLoadFromDisk,
                   ret->local_lecred_error());
    return ret;
  }

  if (metadata_lost) {
    LOG(ERROR) << "Invalid cred metadata for label: " << label;
    ReportLEResult(uma_log_op, kLEActionLoadFromDisk,
                   LE_CRED_ERROR_INVALID_METADATA);
    return MakeStatus<CryptohomeLECredError>(
        CRYPTOHOME_ERR_LOC(kLocLECredManInvalidMetadataInCheckSecret),
        ErrorActionSet({PossibleAction::kReboot, PossibleAction::kAuth}),
        LECredError::LE_CRED_ERROR_INVALID_METADATA);
  }

  ReportLEResult(uma_log_op, kLEActionLoadFromDisk, LE_CRED_SUCCESS);

  hwsec::StatusOr<CredentialTreeResult> result =
      is_le_secret
          ? pinweaver_->CheckCredential(label, h_aux, orig_cred, secret)
          : pinweaver_->ResetCredential(label, h_aux, orig_cred, secret,
                                        strong_reset);

  if (!result.ok()) {
    LOG(ERROR) << "Failed to call pinweaver in check secret: "
               << result.status();
    return MakeStatus<CryptohomeLECredError>(
               CRYPTOHOME_ERR_LOC(kLocLECredManPinWeaverFailedInCheckSecret),
               ErrorActionSet({PossibleAction::kReboot, PossibleAction::kAuth}),
               LECredError::LE_CRED_ERROR_HASH_TREE)
        .Wrap(MakeStatus<CryptohomeTPMError>(std::move(result).err_status()));
  }
  root_hash_ = result->new_root;

  ReportLEResult(uma_log_op, kLEActionBackend,
                 BackendErrorToCredError(result->error));

  // Store the new credential meta data and MAC in case the backend performed a
  // state change. Note that this might also be needed for some failure cases.
  if (result->new_cred_metadata.has_value() && result->new_mac.has_value()) {
    if (!hash_tree_->StoreLabel(label_object, result->new_mac.value(),
                                result->new_cred_metadata.value(), false)) {
      ReportLEResult(uma_log_op, kLEActionSaveToDisk, LE_CRED_ERROR_HASH_TREE);
      LOG(ERROR) << "Failed to update credential in disk hash tree for label: "
                 << label;
      // This is an un-salvageable state. We can't make LE updates anymore,
      // since the disk state can't be updated.
      // We block further LE operations until at least the next boot.
      // The hope is that on reboot, the disk operations start working. In that
      // case, we will be able to replay this operation from the TPM log.
      is_locked_ = true;
      return MakeStatus<CryptohomeLECredError>(
          CRYPTOHOME_ERR_LOC(kLocLECredManStoreLabelFailedInCheckSecret),
          ErrorActionSet({PossibleAction::kReboot, PossibleAction::kAuth}),
          LECredError::LE_CRED_ERROR_HASH_TREE);
    }
  }

  if (he_secret && result->he_secret.has_value()) {
    *he_secret = result->he_secret.value();
  }

  if (reset_secret && result->reset_secret.has_value()) {
    *reset_secret = result->reset_secret.value();
  }

  ReportLEResult(uma_log_op, kLEActionSaveToDisk, LE_CRED_SUCCESS);

  LECredStatus converted = ConvertTpmError(result->error);
  if (converted.ok())
    return OkStatus<CryptohomeLECredError>();

  return MakeStatus<CryptohomeLECredError>(
             CRYPTOHOME_ERR_LOC(kLocLECredManTpmFailedInCheckSecret),
             ErrorActionSet({PossibleAction::kReboot, PossibleAction::kAuth}))
      .Wrap(std::move(converted));
}

LECredStatus LECredentialManagerImpl::RemoveCredentialInternal(
    uint64_t label, bool during_sync) {
  if (!hash_tree_->IsValid()) {
    return MakeStatus<CryptohomeLECredError>(
        CRYPTOHOME_ERR_LOC(kLocLECredManInvalidTreeInRemoveCred),
        ErrorActionSet({PossibleAction::kReboot}),
        LECredError::LE_CRED_ERROR_HASH_TREE);
  }
  if (!during_sync && !Sync()) {
    return MakeStatus<CryptohomeLECredError>(
        CRYPTOHOME_ERR_LOC(kLocLECredManUnSyncedTreeInRemoveCred),
        ErrorActionSet({PossibleAction::kReboot}),
        LECredError::LE_CRED_ERROR_HASH_TREE);
  }

  SignInHashTree::Label label_object(label, kLengthLabels, kBitsPerLevel);
  brillo::Blob orig_cred, orig_mac;
  std::vector<brillo::Blob> h_aux;
  bool metadata_lost;
  LECredStatus ret = RetrieveLabelInfo(label_object, &orig_cred, &orig_mac,
                                       &h_aux, &metadata_lost);
  if (!ret.ok()) {
    ReportLEResult(kLEOpRemove, kLEActionLoadFromDisk,
                   ret->local_lecred_error());
    return MakeStatus<CryptohomeLECredError>(
               CRYPTOHOME_ERR_LOC(kLocLECredManRetrieveLabelFailedInRemoveCred))
        .Wrap(std::move(ret));
  }

  ReportLEResult(kLEOpRemove, kLEActionLoadFromDisk, LE_CRED_SUCCESS);

  hwsec::StatusOr<CredentialTreeResult> result =
      pinweaver_->RemoveCredential(label, h_aux, orig_mac);
  if (!result.ok()) {
    ReportLEResult(kLEOpRemove, kLEActionBackend, LE_CRED_ERROR_HASH_TREE);
    LOG(ERROR) << "Error executing TPM RemoveCredential command: "
               << result.status();
    return MakeStatus<CryptohomeLECredError>(
        CRYPTOHOME_ERR_LOC(kLocLECredManRemoveCredFailedInRemoveCred),
        ErrorActionSet({PossibleAction::kReboot}),
        LECredError::LE_CRED_ERROR_HASH_TREE);
  }
  root_hash_ = result->new_root;

  ReportLEResult(kLEOpRemove, kLEActionBackend, LE_CRED_SUCCESS);

  if (!hash_tree_->RemoveLabel(label_object)) {
    LOG(ERROR) << "Removed label from TPM but hash tree removal "
                  "encountered error: "
               << label;
    ReportLEResult(kLEOpRemove, kLEActionSaveToDisk, LE_CRED_ERROR_HASH_TREE);
    // This is an un-salvageable state. We can't make LE updates anymore,
    // since the disk state can't be updated.
    // We block further LE operations until at least the next boot.
    // The hope is that on reboot, the disk operations start working. In that
    // case, we will be able to replay this operation from the TPM log.
    is_locked_ = true;
    return MakeStatus<CryptohomeLECredError>(
        CRYPTOHOME_ERR_LOC(kLocLECredManRemoveLabelFailedInRemoveCred),
        ErrorActionSet({PossibleAction::kReboot}),
        LECredError::LE_CRED_ERROR_HASH_TREE);
  }
  ReportLEResult(kLEOpRemove, kLEActionSaveToDisk, LE_CRED_SUCCESS);

  return OkStatus<CryptohomeLECredError>();
}

int LECredentialManagerImpl::GetWrongAuthAttempts(uint64_t label) {
  if (!hash_tree_->IsValid()) {
    return -1;
  }
  SignInHashTree::Label label_object(label, kLengthLabels, kBitsPerLevel);

  brillo::Blob orig_cred, orig_mac;
  std::vector<brillo::Blob> h_aux;
  bool metadata_lost;

  LECredStatus ret = RetrieveLabelInfo(label_object, &orig_cred, &orig_mac,
                                       &h_aux, &metadata_lost);
  if (!ret.ok()) {
    LOG(ERROR) << "Failed to retrieve label info: " << std::move(ret);
    return -1;
  }

  hwsec::StatusOr<int> result = pinweaver_->GetWrongAuthAttempts(orig_cred);
  if (!result.ok()) {
    LOG(ERROR) << "Failed to get wrong auth attempts: "
               << std::move(result).status();
    return -1;
  }

  return result.value();
}

LECredStatusOr<uint32_t> LECredentialManagerImpl::GetDelayInSeconds(
    uint64_t label) {
  ASSIGN_OR_RETURN(brillo::Blob metadata,
                   GetCredentialMetadata(label, kLEOpGetDelayInSeconds));

  hwsec::StatusOr<uint32_t> result = pinweaver_->GetDelayInSeconds(metadata);
  if (!result.ok()) {
    return MakeStatus<CryptohomeLECredError>(
               CRYPTOHOME_ERR_LOC(
                   kLocLECredManPinWeaverFailedInGetDelayInSeconds),
               ErrorActionSet({PossibleAction::kReboot, PossibleAction::kAuth}),
               LECredError::LE_CRED_ERROR_HASH_TREE)
        .Wrap(MakeStatus<CryptohomeTPMError>(std::move(result).err_status()));
  }

  return result.value();
}

LECredStatusOr<std::optional<uint32_t>>
LECredentialManagerImpl::GetExpirationInSeconds(uint64_t label) {
  ASSIGN_OR_RETURN(brillo::Blob metadata,
                   GetCredentialMetadata(label, kLEOpGetExpirationInSeconds));

  hwsec::StatusOr<std::optional<uint32_t>> result =
      pinweaver_->GetExpirationInSeconds(metadata);
  if (!result.ok()) {
    return MakeStatus<CryptohomeLECredError>(
               CRYPTOHOME_ERR_LOC(
                   kLocLECredManPinWeaverFailedInGetExpirationInSeconds),
               ErrorActionSet({PossibleAction::kReboot, PossibleAction::kAuth}),
               LECredError::LE_CRED_ERROR_HASH_TREE)
        .Wrap(MakeStatus<CryptohomeTPMError>(std::move(result).err_status()));
  }

  return result.value();
}

LECredStatusOr<DelaySchedule> LECredentialManagerImpl::GetDelaySchedule(
    uint64_t label) {
  ASSIGN_OR_RETURN(brillo::Blob metadata,
                   GetCredentialMetadata(label, kLEOpGetDelaySchedule));

  hwsec::StatusOr<DelaySchedule> result =
      pinweaver_->GetDelaySchedule(metadata);
  if (!result.ok()) {
    return MakeStatus<CryptohomeLECredError>(
               CRYPTOHOME_ERR_LOC(
                   kLocLECredManPinWeaverFailedInGetDelaySchedule),
               ErrorActionSet({PossibleAction::kReboot, PossibleAction::kAuth}),
               LECredError::LE_CRED_ERROR_HASH_TREE)
        .Wrap(MakeStatus<CryptohomeTPMError>(std::move(result).err_status()));
  }

  return result.value();
}

LECredStatus LECredentialManagerImpl::InsertRateLimiter(
    uint8_t auth_channel,
    const std::vector<hwsec::OperationPolicySetting>& policies,
    const brillo::SecureBlob& reset_secret,
    const DelaySchedule& delay_sched,
    std::optional<uint32_t> expiration_delay,
    uint64_t* ret_label) {
  return InsertLeaf(&auth_channel, policies, nullptr, nullptr, reset_secret,
                    delay_sched, expiration_delay, /*is_rate_limiter=*/true,
                    ret_label);
}

LECredStatusOr<LECredentialManager::StartBiometricsAuthReply>
LECredentialManagerImpl::StartBiometricsAuth(uint8_t auth_channel,
                                             uint64_t label,
                                             const brillo::Blob& client_nonce) {
  if (!hash_tree_->IsValid() || !Sync()) {
    return MakeStatus<CryptohomeLECredError>(
        CRYPTOHOME_ERR_LOC(kLocLECredManInvalidTreeInStartBiometricsAuth),
        ErrorActionSet({PossibleAction::kReboot, PossibleAction::kAuth}),
        LECredError::LE_CRED_ERROR_HASH_TREE);
  }

  SignInHashTree::Label label_object(label, kLengthLabels, kBitsPerLevel);

  brillo::Blob orig_cred, orig_mac;
  std::vector<brillo::Blob> h_aux;
  bool metadata_lost;
  LECredStatus ret = RetrieveLabelInfo(label_object, &orig_cred, &orig_mac,
                                       &h_aux, &metadata_lost);
  if (!ret.ok()) {
    ReportLEResult(kLEOpStartBiometricsAuth, kLEActionLoadFromDisk,
                   ret->local_lecred_error());
    return ret;
  }

  if (metadata_lost) {
    LOG(ERROR) << "Invalid cred metadata for label: " << label;
    ReportLEResult(kLEOpStartBiometricsAuth, kLEActionLoadFromDisk,
                   LE_CRED_ERROR_INVALID_METADATA);
    return MakeStatus<CryptohomeLECredError>(
        CRYPTOHOME_ERR_LOC(kLocLECredManInvalidMetadataInStartBiometricsAuth),
        ErrorActionSet({PossibleAction::kReboot, PossibleAction::kAuth}),
        LECredError::LE_CRED_ERROR_INVALID_METADATA);
  }

  ReportLEResult(kLEOpStartBiometricsAuth, kLEActionLoadFromDisk,
                 LE_CRED_SUCCESS);

  hwsec::StatusOr<CredentialTreeResult> result =
      pinweaver_->StartBiometricsAuth(auth_channel, label, h_aux, orig_cred,
                                      client_nonce);

  if (!result.ok()) {
    LOG(ERROR) << "Failed to call pinweaver in start biometrics auth: "
               << result.status();
    return MakeStatus<CryptohomeLECredError>(
               CRYPTOHOME_ERR_LOC(
                   kLocLECredManPinWeaverFailedInStartBiometricsAuth),
               ErrorActionSet({PossibleAction::kReboot, PossibleAction::kAuth}),
               LECredError::LE_CRED_ERROR_HASH_TREE)
        .Wrap(MakeStatus<CryptohomeTPMError>(std::move(result).err_status()));
  }
  root_hash_ = result->new_root;

  ReportLEResult(kLEOpStartBiometricsAuth, kLEActionBackend,
                 BackendErrorToCredError(result->error));

  // Store the new credential meta data and MAC in case the backend performed a
  // state change. Note that this might also be needed for some failure cases.
  if (result->new_cred_metadata.has_value() && result->new_mac.has_value()) {
    if (!hash_tree_->StoreLabel(label_object, result->new_mac.value(),
                                result->new_cred_metadata.value(), false)) {
      ReportLEResult(kLEOpStartBiometricsAuth, kLEActionSaveToDisk,
                     LE_CRED_ERROR_HASH_TREE);
      LOG(ERROR) << "Failed to update credential in disk hash tree for label: "
                 << label;
      // This is an un-salvageable state. We can't make LE updates anymore,
      // since the disk state can't be updated.
      // We block further LE operations until at least the next boot.
      // The hope is that on reboot, the disk operations start working. In that
      // case, we will be able to replay this operation from the TPM log.
      is_locked_ = true;
      return MakeStatus<CryptohomeLECredError>(
          CRYPTOHOME_ERR_LOC(
              kLocLECredManStoreLabelFailedInStartBiometricsAuth),
          ErrorActionSet({PossibleAction::kReboot, PossibleAction::kAuth}),
          LECredError::LE_CRED_ERROR_HASH_TREE);
    }
  }

  ReportLEResult(kLEOpStartBiometricsAuth, kLEActionSaveToDisk,
                 LE_CRED_SUCCESS);

  LECredStatus converted = ConvertTpmError(result->error);
  if (!converted.ok()) {
    return MakeStatus<CryptohomeLECredError>(
               CRYPTOHOME_ERR_LOC(kLocLECredManTpmFailedInStartBiometricsAuth),
               ErrorActionSet({PossibleAction::kReboot, PossibleAction::kAuth}))
        .Wrap(std::move(converted));
  }

  if (!result->server_nonce.has_value() || !result->iv.has_value() ||
      !result->encrypted_he_secret.has_value()) {
    return MakeStatus<CryptohomeLECredError>(
        CRYPTOHOME_ERR_LOC(kLocLECredManInvalidOutputInStartBiometricsAuth),
        ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
        LECredError::LE_CRED_ERROR_HASH_TREE);
  }

  LECredentialManager::StartBiometricsAuthReply reply{
      .server_nonce = std::move(result->server_nonce.value()),
      .iv = std::move(result->iv.value()),
      .encrypted_he_secret = std::move(result->encrypted_he_secret.value()),
  };

  return reply;
}

LECredStatusOr<brillo::Blob> LECredentialManagerImpl::GetCredentialMetadata(
    uint64_t label, const char* le_operation_type) {
  if (!hash_tree_->IsValid()) {
    return MakeStatus<CryptohomeLECredError>(
        CRYPTOHOME_ERR_LOC(kLocLECredManInvalidTreeInGetCredentialMetadata),
        ErrorActionSet({PossibleAction::kReboot, PossibleAction::kAuth}),
        LECredError::LE_CRED_ERROR_HASH_TREE);
  }
  SignInHashTree::Label label_object(label, kLengthLabels, kBitsPerLevel);

  brillo::Blob orig_cred, orig_mac;
  std::vector<brillo::Blob> h_aux;
  bool metadata_lost;

  LECredStatus status = RetrieveLabelInfo(label_object, &orig_cred, &orig_mac,
                                          &h_aux, &metadata_lost);
  if (!status.ok()) {
    ReportLEResult(le_operation_type, kLEActionLoadFromDisk,
                   status->local_lecred_error());
    return MakeStatus<CryptohomeLECredError>(
               CRYPTOHOME_ERR_LOC(
                   kLocLECredManRetrieveLabelFailedInGetCredentialMetadata))
        .Wrap(std::move(status));
  }

  if (metadata_lost) {
    LOG(ERROR) << "Invalid cred metadata for label: " << label;
    ReportLEResult(le_operation_type, kLEActionLoadFromDisk,
                   LE_CRED_ERROR_INVALID_METADATA);
    return MakeStatus<CryptohomeLECredError>(
        CRYPTOHOME_ERR_LOC(kLocLECredManInvalidMetadataInGetCredentialMetadata),
        ErrorActionSet({PossibleAction::kReboot, PossibleAction::kAuth}),
        LECredError::LE_CRED_ERROR_INVALID_METADATA);
  }

  ReportLEResult(le_operation_type, kLEActionLoadFromDisk, LE_CRED_SUCCESS);
  return orig_cred;
}

LECredStatus LECredentialManagerImpl::InsertLeaf(
    uint8_t* auth_channel,
    const std::vector<hwsec::OperationPolicySetting>& policies,
    const brillo::SecureBlob* le_secret,
    const brillo::SecureBlob* he_secret,
    const brillo::SecureBlob& reset_secret,
    const DelaySchedule& delay_sched,
    std::optional<uint32_t> expiration_delay,
    bool is_rate_limiter,
    uint64_t* ret_label) {
  if (!hash_tree_->IsValid() || !Sync()) {
    return MakeStatus<CryptohomeLECredError>(
        CRYPTOHOME_ERR_LOC(kLocLECredManInvalidTreeInInsertCred),
        ErrorActionSet({PossibleAction::kReboot, PossibleAction::kAuth}),
        LECredError::LE_CRED_ERROR_HASH_TREE);
  }

  if ((is_rate_limiter && !auth_channel) ||
      (!is_rate_limiter && (!le_secret || !he_secret))) {
    return MakeStatus<CryptohomeLECredError>(
        CRYPTOHOME_ERR_LOC(kLocLECredManInvalidParamInInsertCred),
        error::ErrorActionSet(
            {error::PossibleAction::kDevCheckUnexpectedState}),
        LECredError::LE_CRED_ERROR_HASH_TREE);
  }

  const char* uma_log_op =
      is_rate_limiter ? kLEOpInsertRateLimiter : kLEOpInsert;

  SignInHashTree::Label label = hash_tree_->GetFreeLabel();
  if (!label.is_valid()) {
    LOG(ERROR) << "No free labels available.";
    ReportLEResult(uma_log_op, kLEActionLoadFromDisk,
                   LE_CRED_ERROR_NO_FREE_LABEL);
    return MakeStatus<CryptohomeLECredError>(
        CRYPTOHOME_ERR_LOC(kLocLECredManLabelUnavailableInInsertCred),
        ErrorActionSet({PossibleAction::kReboot, PossibleAction::kAuth}),
        LECredError::LE_CRED_ERROR_NO_FREE_LABEL);
  }

  std::vector<brillo::Blob> h_aux = GetAuxHashes(label);
  if (h_aux.empty()) {
    LOG(ERROR) << "Error getting aux hashes for label: " << label.value();
    ReportLEResult(uma_log_op, kLEActionLoadFromDisk, LE_CRED_ERROR_HASH_TREE);
    return MakeStatus<CryptohomeLECredError>(
        CRYPTOHOME_ERR_LOC(kLocLECredManEmptyAuxInInsertCred),
        ErrorActionSet({PossibleAction::kReboot, PossibleAction::kAuth}),
        LECredError::LE_CRED_ERROR_HASH_TREE);
  }

  ReportLEResult(uma_log_op, kLEActionLoadFromDisk, LE_CRED_SUCCESS);

  hwsec::StatusOr<CredentialTreeResult> result =
      is_rate_limiter
          ? pinweaver_->InsertRateLimiter(*auth_channel, policies,
                                          label.value(), h_aux, reset_secret,
                                          delay_sched, expiration_delay)
          : pinweaver_->InsertCredential(policies, label.value(), h_aux,
                                         *le_secret, *he_secret, reset_secret,
                                         delay_sched, expiration_delay);
  if (!result.ok()) {
    LOG(ERROR) << "Error executing pinweaver InsertCredential command: "
               << result.status();
    ReportLEResult(uma_log_op, kLEActionBackend, LE_CRED_ERROR_HASH_TREE);
    return MakeStatus<CryptohomeLECredError>(
               CRYPTOHOME_ERR_LOC(kLocLECredManTpmFailedInInsertCred),
               ErrorActionSet({PossibleAction::kReboot, PossibleAction::kAuth}),
               LECredError::LE_CRED_ERROR_HASH_TREE)
        .Wrap(MakeStatus<CryptohomeTPMError>(std::move(result).err_status()));
  }
  root_hash_ = result->new_root;

  ReportLEResult(uma_log_op, kLEActionBackend, LE_CRED_SUCCESS);

  if (!hash_tree_->StoreLabel(label, result->new_mac.value(),
                              result->new_cred_metadata.value(), false)) {
    ReportLEResult(uma_log_op, kLEActionSaveToDisk, LE_CRED_ERROR_HASH_TREE);
    LOG(ERROR) << "InsertCredential succeeded in PinWeaver but disk updated "
                  "failed, label: "
               << label.value();
    // The insert into the disk hash tree failed, so let us remove
    // the credential from the TPM state so that we are back to where
    // we started.
    hwsec::StatusOr<CredentialTreeResult> remove_result =
        pinweaver_->RemoveCredential(label.value(), h_aux,
                                     result->new_mac.value());
    if (!remove_result.ok()) {
      ReportLEResult(uma_log_op, kLEActionBackendRecoverInsert,
                     LE_CRED_ERROR_HASH_TREE);
      LOG(ERROR)
          << " Failed to rewind aborted InsertCredential in PinWeaver, label: "
          << label.value() << ": " << std::move(remove_result).status();
      // The attempt to undo the PinWeaver side operation has also failed, Can't
      // do much else now. We block further LE operations until at least the
      // next boot.
      is_locked_ = true;
    } else {
      root_hash_ = remove_result->new_root;
    }

    ReportLEResult(uma_log_op, kLEActionBackendRecoverInsert, LE_CRED_SUCCESS);

    return MakeStatus<CryptohomeLECredError>(
        CRYPTOHOME_ERR_LOC(kLocLECredManStoreFailedInInsertCred),
        ErrorActionSet({PossibleAction::kReboot, PossibleAction::kAuth}),
        LECredError::LE_CRED_ERROR_HASH_TREE);
  }

  ReportLEResult(uma_log_op, kLEActionSaveToDisk, LE_CRED_SUCCESS);

  *ret_label = label.value();
  return OkStatus<CryptohomeLECredError>();
}

LECredStatus LECredentialManagerImpl::RetrieveLabelInfo(
    const SignInHashTree::Label& label,
    brillo::Blob* cred_metadata,
    brillo::Blob* mac,
    std::vector<brillo::Blob>* h_aux,
    bool* metadata_lost) {
  if (!hash_tree_->GetLabelData(label, mac, cred_metadata, metadata_lost)) {
    LOG(ERROR) << "Failed to get the credential in disk hash tree for label: "
               << label.value();
    return MakeStatus<CryptohomeLECredError>(
        CRYPTOHOME_ERR_LOC(kLocLECredManTreeGetDataFailedInRetrieveLabel),
        ErrorActionSet({PossibleAction::kReboot, PossibleAction::kAuth}),
        LECredError::LE_CRED_ERROR_INVALID_LABEL);
  }

  // Any empty |cred_metadata| means the label isn't present in the hash tree.
  if (cred_metadata->empty()) {
    LOG(ERROR) << "Label doesn't exist in hash tree: " << label.value();
    return MakeStatus<CryptohomeLECredError>(
        CRYPTOHOME_ERR_LOC(kLocLECredManNonexistentInRetrieveLabel),
        ErrorActionSet({PossibleAction::kReboot, PossibleAction::kAuth}),
        LECredError::LE_CRED_ERROR_INVALID_LABEL);
  }

  *h_aux = GetAuxHashes(label);
  if (h_aux->empty()) {
    LOG(ERROR) << "Error retrieving aux hashes from hash tree for label: "
               << label.value();
    return MakeStatus<CryptohomeLECredError>(
        CRYPTOHOME_ERR_LOC(kLocLECredManEmptyAuxInRetrieveLabel),
        ErrorActionSet({PossibleAction::kReboot, PossibleAction::kAuth}),
        LECredError::LE_CRED_ERROR_HASH_TREE);
  }
  return OkStatus<CryptohomeLECredError>();
}

std::vector<brillo::Blob> LECredentialManagerImpl::GetAuxHashes(
    const SignInHashTree::Label& label) {
  auto aux_labels = hash_tree_->GetAuxiliaryLabels(label);
  std::vector<brillo::Blob> h_aux;
  if (aux_labels.empty()) {
    LOG(ERROR) << "Error getting h_aux for label:" << label.value();
    return h_aux;
  }

  h_aux.reserve(aux_labels.size());
  for (auto cur_aux_label : aux_labels) {
    brillo::Blob hash, cred_data;
    bool metadata_lost;
    if (!hash_tree_->GetLabelData(cur_aux_label, &hash, &cred_data,
                                  &metadata_lost)) {
      LOG(INFO) << "Error getting aux label :" << cur_aux_label.value()
                << " for label: " << label.value();
      h_aux.clear();
      break;
    }
    h_aux.push_back(std::move(hash));
  }

  return h_aux;
}

LECredStatus LECredentialManagerImpl::ConvertTpmError(
    CredentialTreeResult::ErrorCode err) {
  LECredError conv_err = BackendErrorToCredError(err);

  // We want to split out various cases of LE Credential errors so that their
  // statistics are tallied separately from the other LECredential errors.
  switch (conv_err) {
    case LE_CRED_SUCCESS:
      return OkStatus<CryptohomeLECredError>();

    case LE_CRED_ERROR_INVALID_LE_SECRET:
      // Incorrect password.
      return MakeStatus<CryptohomeLECredError>(
          CRYPTOHOME_ERR_LOC(kLocLECredManInvalidLESecretInConvertTpmError),
          ErrorActionSet(PrimaryAction::kIncorrectAuth), conv_err);

    case LE_CRED_ERROR_INVALID_RESET_SECRET:
      // The reset secret is invalid. We don't expect this to occur so
      // kDevCheckUnexpectedState is specified. The user can always try to use
      // non-LE auth methods to get around this, so kAuth is specified.
      return MakeStatus<CryptohomeLECredError>(
          CRYPTOHOME_ERR_LOC(kLocLECredManInvalidResetSecretInConvertTpmError),
          ErrorActionSet({PossibleAction::kDevCheckUnexpectedState,
                          PossibleAction::kAuth}),
          conv_err);
    case LE_CRED_ERROR_TOO_MANY_ATTEMPTS:
      // Too many attempts.
      return MakeStatus<CryptohomeLECredError>(
          CRYPTOHOME_ERR_LOC(kLocLECredManTooManyAttemptsInConvertTpmError),
          ErrorActionSet(PrimaryAction::kLeLockedOut), conv_err);
    case LE_CRED_ERROR_PCR_NOT_MATCH:
      // In usual operation, we don't expect PCR to be incorrect, so
      // kDevCheckUnexpectedState is specified. If the PCR is incorrect, a
      // reboot might fix it. Alternatively, the user can try a different auth
      // that doesn't require a correct PCR value. If all else fails, powerwash
      // might allow us to restart from a correct PCR value.
      return MakeStatus<CryptohomeLECredError>(
          CRYPTOHOME_ERR_LOC(kLocLECredManPCRNotMatchInConvertTpmError),
          ErrorActionSet({PossibleAction::kDevCheckUnexpectedState,
                          PossibleAction::kAuth, PossibleAction::kReboot,
                          PossibleAction::kPowerwash}),
          conv_err);
    case LE_CRED_ERROR_HASH_TREE:
      // In usual operation, we don't expect the hash tree to go bad, so
      // kDevCheckUnexpectedState is specified. The user can always try to use
      // non-LE auth methods to get around this, so kAuth is specified. User can
      // delete the vault start fresh so kDeleteVault is specified.
      return MakeStatus<CryptohomeLECredError>(
          CRYPTOHOME_ERR_LOC(kLocLECredManHashTreeInConvertTpmError),
          ErrorActionSet({PossibleAction::kDevCheckUnexpectedState,
                          PossibleAction::kAuth, PossibleAction::kDeleteVault}),
          conv_err);
    case LE_CRED_ERROR_EXPIRED:
      return MakeStatus<CryptohomeLECredError>(
          CRYPTOHOME_ERR_LOC(kLocLECredManExpiredInConvertTpmError),
          ErrorActionSet(PrimaryAction::kLeExpired), conv_err);
    default:
      ErrorActionSet action_set;
      return MakeStatus<CryptohomeLECredError>(
          CRYPTOHOME_ERR_LOC(kLocLECredManConvertTpmError),
          std::move(action_set), conv_err);
  }
}

LECredError LECredentialManagerImpl::BackendErrorToCredError(
    CredentialTreeResult::ErrorCode err) {
  switch (err) {
    case CredentialTreeResult::ErrorCode::kSuccess:
      return LE_CRED_SUCCESS;
    case CredentialTreeResult::ErrorCode::kInvalidLeSecret:
      return LE_CRED_ERROR_INVALID_LE_SECRET;
    case CredentialTreeResult::ErrorCode::kInvalidResetSecret:
      return LE_CRED_ERROR_INVALID_RESET_SECRET;
    case CredentialTreeResult::ErrorCode::kTooManyAttempts:
      return LE_CRED_ERROR_TOO_MANY_ATTEMPTS;
    case CredentialTreeResult::ErrorCode::kHashTreeOutOfSync:
      return LE_CRED_ERROR_HASH_TREE;
    case CredentialTreeResult::ErrorCode::kPolicyNotMatch:
      return LE_CRED_ERROR_PCR_NOT_MATCH;
    case CredentialTreeResult::ErrorCode::kExpired:
      return LE_CRED_ERROR_EXPIRED;
    default:
      return LE_CRED_ERROR_HASH_TREE;
  }
}

bool LECredentialManagerImpl::Sync() {
  if (is_locked_) {
    ReportLESyncOutcome(LE_CRED_ERROR_LE_LOCKED);
    return false;
  }

  brillo::Blob disk_root_hash;
  hash_tree_->GetRootHash(&disk_root_hash);

  // If we don't have it, get the root hash from the LE Backend.
  std::vector<GetLogResult::LogEntry> log;
  if (root_hash_.empty()) {
    hwsec::StatusOr<GetLogResult> result = pinweaver_->GetLog(disk_root_hash);
    if (!result.ok()) {
      ReportLEResult(kLEOpSync, kLEActionBackendGetLog,
                     LE_CRED_ERROR_UNCLASSIFIED);
      ReportLESyncOutcome(LE_CRED_ERROR_HASH_TREE);
      LOG(ERROR) << "Couldn't get LE Log: " << std::move(result).status();
      is_locked_ = true;
      return false;
    }
    root_hash_ = result->root_hash;
    log = std::move(result->log_entries);
    ReportLEResult(kLEOpSync, kLEActionBackendGetLog, LE_CRED_SUCCESS);
  }

  if (disk_root_hash == root_hash_) {
    ReportLESyncOutcome(LE_CRED_SUCCESS);
    return true;
  }

  LOG(WARNING) << "LE HashCache is stale; reconstructing.";
  hash_tree_->GenerateAndStoreHashCache();
  disk_root_hash.clear();
  hash_tree_->GetRootHash(&disk_root_hash);

  if (disk_root_hash == root_hash_) {
    ReportLESyncOutcome(LE_CRED_SUCCESS);
    return true;
  }

  LOG(WARNING) << "LE sync loss between OS and GSC, attempting log replay.";

  // Get the log again, since |disk_root_hash| may have changed.
  log.clear();
  hwsec::StatusOr<GetLogResult> result = pinweaver_->GetLog(disk_root_hash);
  if (!result.ok()) {
    ReportLEResult(kLEOpSync, kLEActionBackendGetLog,
                   LE_CRED_ERROR_UNCLASSIFIED);
    ReportLESyncOutcome(LE_CRED_ERROR_HASH_TREE);
    LOG(ERROR) << "Couldn't get LE Log.";
    is_locked_ = true;
    return false;
  }
  root_hash_ = result->root_hash;
  log = std::move(result->log_entries);

  ReportLEResult(kLEOpSync, kLEActionBackendGetLog, LE_CRED_SUCCESS);
  if (!ReplayLogEntries(log, disk_root_hash)) {
    ReportLESyncOutcome(LE_CRED_ERROR_HASH_TREE);
    LOG(ERROR) << "Failed to Synchronize LE disk state after log replay.";
    is_locked_ = true;
    return false;
  }
  ReportLESyncOutcome(LE_CRED_SUCCESS);
  return true;
}

bool LECredentialManagerImpl::ReplayInsert(uint64_t label,
                                           const brillo::Blob& log_root,
                                           const brillo::Blob& mac) {
  LOG(INFO) << "Replaying insert for label " << label;

  // Fill cred_metadata with some random data since LECredentialManager
  // considers empty cred_metadata as a non-existent label.
  brillo::Blob cred_metadata(mac.size());
  GetSecureRandom(cred_metadata.data(), cred_metadata.size());
  SignInHashTree::Label label_obj(label, kLengthLabels, kBitsPerLevel);
  if (!hash_tree_->StoreLabel(label_obj, mac, cred_metadata, true)) {
    ReportLEResult(kLEOpReplayInsert, kLEActionSaveToDisk,
                   LE_CRED_ERROR_HASH_TREE);
    LOG(ERROR) << "InsertCredentialReplay disk update "
                  "failed, label: "
               << label_obj.value();
    return false;
  }
  ReportLEResult(kLEOpReplayInsert, kLEActionSaveToDisk, LE_CRED_SUCCESS);

  return true;
}

bool LECredentialManagerImpl::ReplayCheck(uint64_t label,
                                          const brillo::Blob& log_root,
                                          bool is_full_replay) {
  LOG(INFO) << "Replaying check for label " << label;

  SignInHashTree::Label label_obj(label, kLengthLabels, kBitsPerLevel);
  brillo::Blob orig_cred, orig_mac;
  std::vector<brillo::Blob> h_aux;
  bool metadata_lost;
  if (!RetrieveLabelInfo(label_obj, &orig_cred, &orig_mac, &h_aux,
                         &metadata_lost)
           .ok()) {
    ReportLEResult(kLEOpReplayCheck, kLEActionLoadFromDisk,
                   LE_CRED_ERROR_HASH_TREE);
    return false;
  }

  ReportLEResult(kLEOpReplayCheck, kLEActionLoadFromDisk, LE_CRED_SUCCESS);

  // We separate the results between a normal replay and a full replay because
  // the error distribution in a full replay might be very different (since
  // we're just doing a best-effort attempt hoping that we are only 1 entry
  // behind the first log entry). Only the replay_log action of ReplayCheck
  // needs this separation because other individual actions aren't affected by
  // whether the assumed root hash is correct.
  const char* replay_log_action = is_full_replay
                                      ? kLEActionBackendReplayLogForFullReplay
                                      : kLEActionBackendReplayLog;
  hwsec::StatusOr<ReplayLogOperationResult> result =
      pinweaver_->ReplayLogOperation(log_root, h_aux, orig_cred);
  if (!result.ok()) {
    ReportLEResult(kLEOpReplayCheck, replay_log_action,
                   LE_CRED_ERROR_UNCLASSIFIED);
    LOG(ERROR) << "Auth replay failed on LE Backend, label: " << label << ": "
               << std::move(result).status();
    return false;
  }

  ReportLEResult(kLEOpReplayCheck, replay_log_action, LE_CRED_SUCCESS);

  // Store the new credential metadata and MAC.
  if (!result->new_cred_metadata.empty() && !result->new_mac.empty()) {
    if (!hash_tree_->StoreLabel(label_obj, result->new_mac,
                                result->new_cred_metadata, false)) {
      ReportLEResult(kLEOpReplayCheck, kLEActionSaveToDisk,
                     LE_CRED_ERROR_HASH_TREE);
      LOG(ERROR) << "Error in LE auth replay disk hash tree update, label: "
                 << label;
      return false;
    }

    ReportLEResult(kLEOpReplayCheck, kLEActionSaveToDisk, LE_CRED_SUCCESS);
  }

  return true;
}

bool LECredentialManagerImpl::ReplayResetTree() {
  LOG(INFO) << "Replaying tree reset";

  hash_tree_.reset();
  if (!base::DeletePathRecursively(basedir_)) {
    PLOG(ERROR) << "Failed to delete disk hash tree during replay.";
    ReportLEResult(kLEOpReplayResetTree, kLEActionSaveToDisk,
                   LE_CRED_ERROR_HASH_TREE);
    return false;
  }

  auto new_hash_tree =
      std::make_unique<SignInHashTree>(kLengthLabels, kBitsPerLevel, basedir_);
  if (!new_hash_tree->IsValid()) {
    ReportLEResult(kLEOpReplayResetTree, kLEActionSaveToDisk,
                   LE_CRED_ERROR_HASH_TREE);
    return false;
  }

  ReportLEResult(kLEOpReplayResetTree, kLEActionSaveToDisk, LE_CRED_SUCCESS);

  hash_tree_ = std::move(new_hash_tree);
  hash_tree_->GenerateAndStoreHashCache();
  return true;
}

bool LECredentialManagerImpl::ReplayRemove(uint64_t label) {
  LOG(INFO) << "Replaying remove for label " << label;

  SignInHashTree::Label label_obj(label, kLengthLabels, kBitsPerLevel);
  if (!hash_tree_->RemoveLabel(label_obj)) {
    ReportLEResult(kLEOpReplayRemove, kLEActionSaveToDisk,
                   LE_CRED_ERROR_HASH_TREE);
    LOG(ERROR) << "RemoveLabel LE Replay failed for label: " << label;
    return false;
  }
  ReportLEResult(kLEOpReplayRemove, kLEActionSaveToDisk, LE_CRED_SUCCESS);
  return true;
}

bool LECredentialManagerImpl::ReplayLogEntries(
    const std::vector<GetLogResult::LogEntry>& log,
    const brillo::Blob& disk_root_hash) {
  // The log entries are in reverse chronological order. Because the log entries
  // only store the root hash after the operation, the strategy here is:
  // - Parse the logs in reverse.
  // - First try to find a log entry which matches the on-disk root hash,
  //   and start with the log entry following that. If you can't, then just
  //   start from the earliest log.
  // - For all other entries, simply attempt to replay the operation.
  auto it = log.rbegin();
  size_t replay_count = 0;
  for (; it != log.rend(); ++it) {
    const GetLogResult::LogEntry& log_entry = *it;
    if (log_entry.root == disk_root_hash) {
      // 1-based count, zero indicates no root hash match.
      replay_count = it - log.rbegin() + 1;
      LOG(INFO) << "Starting replay at log entry #" << it - log.rbegin();
      ++it;
      break;
    }
  }

  ReportLELogReplayEntryCount(replay_count);

  bool is_full_replay = false;
  if (it == log.rend()) {
    LOG(WARNING) << "No matching root hash, starting replay at oldest entry";
    it = log.rbegin();
    is_full_replay = true;
  }

  brillo::Blob cur_root_hash = disk_root_hash;
  std::vector<uint64_t> inserted_leaves;
  for (; it != log.rend(); ++it) {
    const GetLogResult::LogEntry& log_entry = *it;
    bool ret;
    switch (log_entry.type) {
      case GetLogResult::LogEntryType::kInsert:
        ret = ReplayInsert(log_entry.label, log_entry.root, log_entry.mac);
        if (ret) {
          inserted_leaves.push_back(log_entry.label);
        }
        break;
      case GetLogResult::LogEntryType::kRemove:
        ret = ReplayRemove(log_entry.label);
        break;
      case GetLogResult::LogEntryType::kCheck:
        ret = ReplayCheck(log_entry.label, log_entry.root, is_full_replay);
        break;
      case GetLogResult::LogEntryType::kReset:
        ret = ReplayResetTree();
        break;
      case GetLogResult::LogEntryType::kInvalid:
        LOG(ERROR) << "Invalid log entry.";
        ReportLEReplayResult(is_full_replay, LEReplayError::kInvalidLogEntry);
        return false;
    }
    if (!ret) {
      LOG(ERROR) << "Failure to replay LE Cred log entries.";
      ReportLEReplayResult(is_full_replay, LEReplayError::kOperationError);
      return false;
    }
    cur_root_hash.clear();
    hash_tree_->GetRootHash(&cur_root_hash);
    if (cur_root_hash != log_entry.root) {
      LOG(ERROR) << "Root hash doesn't match log root after replaying entry.";
      ReportLEReplayResult(is_full_replay, LEReplayError::kHashMismatch);
      return false;
    }
  }

  // Remove any inserted leaves since they are unusable.
  for (const auto& label : inserted_leaves) {
    if (!RemoveCredentialInternal(label, /*during_sync=*/true).ok()) {
      LOG(ERROR) << "Failed to remove re-inserted label: " << label;
      ReportLEReplayResult(is_full_replay,
                           LEReplayError::kRemoveInsertedCredentialsError);
      return false;
    }
  }
  ReportLEReplayResult(is_full_replay, LEReplayError::kSuccess);

  return true;
}

}  // namespace cryptohome
