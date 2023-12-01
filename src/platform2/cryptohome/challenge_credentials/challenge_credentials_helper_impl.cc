// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/challenge_credentials/challenge_credentials_helper_impl.h"

#include <optional>
#include <utility>

#include <base/check.h>
#include <base/check_op.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/strings/string_util.h>
#include <base/system/sys_info.h>
#include <libhwsec/status.h>
#include <libhwsec/frontend/cryptohome/frontend.h>

#include "cryptohome/challenge_credentials/challenge_credentials_decrypt_operation.h"
#include "cryptohome/challenge_credentials/challenge_credentials_generate_new_operation.h"
#include "cryptohome/challenge_credentials/challenge_credentials_operation.h"
#include "cryptohome/challenge_credentials/challenge_credentials_verify_key_operation.h"
#include "cryptohome/error/location_utils.h"
#include "cryptohome/error/utilities.h"
#include "cryptohome/key_challenge_service.h"

using brillo::Blob;
using cryptohome::error::CryptohomeCryptoError;
using cryptohome::error::CryptohomeTPMError;
using cryptohome::error::ErrorActionSet;
using cryptohome::error::PossibleAction;
using cryptohome::error::PrimaryAction;
using hwsec::TPMRetryAction;
using hwsec_foundation::error::CreateError;
using hwsec_foundation::error::WrapError;
using hwsec_foundation::status::MakeStatus;
using hwsec_foundation::status::OkStatus;
using hwsec_foundation::status::StatusChain;

namespace cryptohome {

namespace {

bool IsOperationFailureTransient(
    const StatusChain<CryptohomeCryptoError>& status
    [[clang::param_typestate(unconsumed)]]) {
  return PossibleActionsInclude(status, PossibleAction::kRetry);
}

// Returns whether the Chrome OS image is a test one.
bool IsOsTestImage() {
  std::string chromeos_release_track;
  if (!base::SysInfo::GetLsbReleaseValue("CHROMEOS_RELEASE_TRACK",
                                         &chromeos_release_track)) {
    // Fall back to the safer assumption that we're not in a test image.
    return false;
  }
  return base::StartsWith(chromeos_release_track, "test",
                          base::CompareCase::SENSITIVE);
}

}  // namespace

ChallengeCredentialsHelperImpl::ChallengeCredentialsHelperImpl(
    const hwsec::CryptohomeFrontend* hwsec)
    : roca_vulnerable_(std::nullopt), hwsec_(hwsec) {
  DCHECK(hwsec_);
}

ChallengeCredentialsHelperImpl::~ChallengeCredentialsHelperImpl() {
  DCHECK(thread_checker_.CalledOnValidThread());
}

CryptoStatus ChallengeCredentialsHelperImpl::CheckTPMStatus() {
  // Prepare the CryptoStatus for fault case because it will be used in
  // multiple places.
  auto tpm_unavailable_status = MakeStatus<CryptohomeCryptoError>(
      CRYPTOHOME_ERR_LOC(kLocChalCredHelperTpmUnavailableInCheckTpmStatus),
      ErrorActionSet({PossibleAction::kDevCheckUnexpectedState,
                      PossibleAction::kReboot, PossibleAction::kPowerwash}),
      CryptoError::CE_OTHER_FATAL);

  // Have we checked before?
  if (tpm_ready_.has_value()) {
    if (tpm_ready_.value()) {
      return OkStatus<CryptohomeCryptoError>();
    } else {
      return tpm_unavailable_status;
    }
  }

  hwsec::StatusOr<bool> is_ready = hwsec_->IsReady();
  if (!is_ready.ok()) {
    LOG(ERROR) << "Failed to get the hwsec ready state: " << is_ready.status();
    return tpm_unavailable_status;
  }

  if (!is_ready.value()) {
    LOG(ERROR) << "HWSec must be initialized in order to do challenge-response "
                  "authentication";
    tpm_ready_ = false;
    return tpm_unavailable_status;
  }

  tpm_ready_ = true;
  return OkStatus<CryptohomeCryptoError>();
}

CryptoStatus ChallengeCredentialsHelperImpl::CheckSrkRocaStatus() {
  // Prepare the CryptoStatus for vulnerable case because it will be used in
  // multiple places.
  auto vulnerable_status = MakeStatus<CryptohomeCryptoError>(
      CRYPTOHOME_ERR_LOC(kLocChalCredHelperROCAVulnerableInCheckSrkRocaStatus),
      ErrorActionSet(PrimaryAction::kTpmUpdateRequired),
      CryptoError::CE_OTHER_FATAL,
      user_data_auth::CRYPTOHOME_ERROR_TPM_UPDATE_REQUIRED);

  // Have we checked before?
  if (roca_vulnerable_.has_value()) {
    if (roca_vulnerable_.value()) {
      return vulnerable_status;
    }
    return OkStatus<CryptohomeCryptoError>();
  }

  // Fail if the security chip is known to be vulnerable and we're not in a test
  // image.
  hwsec::StatusOr<bool> is_srk_roca_vulnerable = hwsec_->IsSrkRocaVulnerable();
  if (!is_srk_roca_vulnerable.ok()) {
    LOG(ERROR) << "Failed to get the hwsec SRK ROCA vulnerable status: "
               << is_srk_roca_vulnerable.status();
    return MakeStatus<CryptohomeCryptoError>(
               CRYPTOHOME_ERR_LOC(
                   kLocChalCredHelperCantQueryROCAVulnInCheckSrkRocaStatus),
               ErrorActionSet({PossibleAction::kReboot}),
               CryptoError::CE_OTHER_FATAL)
        .Wrap(MakeStatus<CryptohomeTPMError>(
            std::move(is_srk_roca_vulnerable).err_status()));
  }

  if (is_srk_roca_vulnerable.value()) {
    if (!IsOsTestImage()) {
      LOG(ERROR)
          << "Cannot do challenge-response mount: HWSec is ROCA vulnerable";
      roca_vulnerable_ = true;
      return vulnerable_status;
    }
    LOG(WARNING) << "HWSec is ROCA vulnerable; ignoring this for "
                    "challenge-response mount due to running in test image";
  }

  roca_vulnerable_ = false;
  return OkStatus<CryptohomeCryptoError>();
}

void ChallengeCredentialsHelperImpl::GenerateNew(
    const Username& account_id,
    const structure::ChallengePublicKeyInfo& public_key_info,
    const ObfuscatedUsername& obfuscated_username,
    std::unique_ptr<KeyChallengeService> key_challenge_service,
    GenerateNewCallback callback) {
  DCHECK(thread_checker_.CalledOnValidThread());
  DCHECK(!callback.is_null());

  // Check if TPM is enabled.
  CryptoStatus status = CheckTPMStatus();
  if (!status.ok()) {
    // We can forward the CryptoStatus directly without wrapping because the
    // callback will usually Wrap() the resulting error status anyway.
    std::move(callback).Run(std::move(status));
    return;
  }

  // Check SRK ROCA status.
  status = CheckSrkRocaStatus();
  if (!status.ok()) {
    std::move(callback).Run(std::move(status));
    return;
  }

  CancelRunningOperation();
  key_challenge_service_ = std::move(key_challenge_service);
  operation_ = std::make_unique<ChallengeCredentialsGenerateNewOperation>(
      key_challenge_service_.get(), hwsec_, account_id, public_key_info,
      obfuscated_username,
      base::BindOnce(&ChallengeCredentialsHelperImpl::OnGenerateNewCompleted,
                     base::Unretained(this), std::move(callback)));
  operation_->Start();
}

void ChallengeCredentialsHelperImpl::Decrypt(
    const Username& account_id,
    const structure::ChallengePublicKeyInfo& public_key_info,
    const structure::SignatureChallengeInfo& keyset_challenge_info,
    std::unique_ptr<KeyChallengeService> key_challenge_service,
    DecryptCallback callback) {
  DCHECK(thread_checker_.CalledOnValidThread());
  DCHECK(!callback.is_null());

  // Check if TPM is enabled.
  CryptoStatus status = CheckTPMStatus();
  if (!status.ok()) {
    // We can forward the CryptoStatus directly without wrapping because the
    // callback will usually Wrap() the resulting error status anyway.
    std::move(callback).Run(std::move(status));
    return;
  }

  // Check SRK ROCA status.
  status = CheckSrkRocaStatus();
  if (!status.ok()) {
    std::move(callback).Run(std::move(status));
    return;
  }

  CancelRunningOperation();
  key_challenge_service_ = std::move(key_challenge_service);
  StartDecryptOperation(account_id, public_key_info, keyset_challenge_info,
                        1 /* attempt_number */, std::move(callback));
}

void ChallengeCredentialsHelperImpl::VerifyKey(
    const Username& account_id,
    const structure::ChallengePublicKeyInfo& public_key_info,
    std::unique_ptr<KeyChallengeService> key_challenge_service,
    VerifyKeyCallback callback) {
  DCHECK(thread_checker_.CalledOnValidThread());
  DCHECK(!callback.is_null());

  // Check if TPM is enabled.
  CryptoStatus status = CheckTPMStatus();
  if (!status.ok()) {
    // We can forward the CryptoStatus directly without wrapping because the
    // callback will usually Wrap() the resulting error status anyway.
    std::move(callback).Run(std::move(status));
    return;
  }

  // Check SRK ROCA status.
  status = CheckSrkRocaStatus();
  if (!status.ok()) {
    std::move(callback).Run(std::move(status));
    return;
  }

  CancelRunningOperation();
  key_challenge_service_ = std::move(key_challenge_service);
  operation_ = std::make_unique<ChallengeCredentialsVerifyKeyOperation>(
      key_challenge_service_.get(), hwsec_, account_id, public_key_info,
      base::BindOnce(&ChallengeCredentialsHelperImpl::OnVerifyKeyCompleted,
                     base::Unretained(this), std::move(callback)));
  operation_->Start();
}

void ChallengeCredentialsHelperImpl::StartDecryptOperation(
    const Username& account_id,
    const structure::ChallengePublicKeyInfo& public_key_info,
    const structure::SignatureChallengeInfo& keyset_challenge_info,
    int attempt_number,
    DecryptCallback callback) {
  DCHECK(!operation_);
  operation_ = std::make_unique<ChallengeCredentialsDecryptOperation>(
      key_challenge_service_.get(), hwsec_, account_id, public_key_info,
      keyset_challenge_info,
      base::BindOnce(&ChallengeCredentialsHelperImpl::OnDecryptCompleted,
                     base::Unretained(this), account_id, public_key_info,
                     keyset_challenge_info, attempt_number,
                     std::move(callback)));
  operation_->Start();
}

void ChallengeCredentialsHelperImpl::CancelRunningOperation() {
  // Destroy the previous Operation before instantiating a new one, to keep the
  // resource usage constrained (for example, there must be only one instance of
  // hwsec::CryptohomeFrontend::ChallengeWithSignatureAndCurrentUser at a time).
  if (operation_) {
    DLOG(INFO) << "Cancelling an old challenge-response credentials operation";
    // Note: kReboot is specified here instead of kRetry because kRetry could
    // trigger upper layer to retry immediately, causing failures again.
    operation_->Abort(MakeStatus<CryptohomeCryptoError>(
        CRYPTOHOME_ERR_LOC(kLocChalCredHelperConcurrencyNotAllowed),
        ErrorActionSet({PossibleAction::kReboot}),
        CryptoError::CE_OTHER_FATAL));
    operation_.reset();
    // It's illegal for the consumer code to request a new operation in
    // immediate response to completion of a previous one.
    DCHECK(!operation_);
  }
}

void ChallengeCredentialsHelperImpl::OnGenerateNewCompleted(
    GenerateNewCallback original_callback,
    CryptoStatusOr<ChallengeCredentialsHelper::GenerateNewOrDecryptResult>
        result) {
  DCHECK(thread_checker_.CalledOnValidThread());
  CancelRunningOperation();
  std::move(original_callback).Run(std::move(result));
}

void ChallengeCredentialsHelperImpl::OnDecryptCompleted(
    const Username& account_id,
    const structure::ChallengePublicKeyInfo& public_key_info,
    const structure::SignatureChallengeInfo& keyset_challenge_info,
    int attempt_number,
    DecryptCallback original_callback,
    CryptoStatusOr<ChallengeCredentialsHelper::GenerateNewOrDecryptResult>
        result) {
  DCHECK(thread_checker_.CalledOnValidThread());
  CancelRunningOperation();
  if (!result.ok() && IsOperationFailureTransient(result.err_status()) &&
      attempt_number < kRetryAttemptCount) {
    LOG(WARNING) << "Retrying the decryption operation after transient error: "
                 << result.status();
    StartDecryptOperation(account_id, public_key_info, keyset_challenge_info,
                          attempt_number + 1, std::move(original_callback));
  } else {
    if (!result.ok()) {
      LOG(ERROR) << "Decryption completed with error: " << result.status();
    }
    std::move(original_callback).Run(std::move(result));
  }
}

void ChallengeCredentialsHelperImpl::OnVerifyKeyCompleted(
    VerifyKeyCallback original_callback, CryptoStatus verify_status) {
  DCHECK(thread_checker_.CalledOnValidThread());
  CancelRunningOperation();
  std::move(original_callback).Run(std::move(verify_status));
}

}  // namespace cryptohome
