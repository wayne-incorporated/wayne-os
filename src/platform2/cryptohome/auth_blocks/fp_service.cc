// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <string>
#include <utility>

#include <absl/cleanup/cleanup.h>
#include <base/functional/bind.h>
#include <cryptohome/proto_bindings/UserDataAuth.pb.h>

#include "cryptohome/auth_blocks/fp_service.h"
#include "cryptohome/error/cryptohome_error.h"
#include "cryptohome/error/location_utils.h"
#include "cryptohome/error/locations.h"
#include "cryptohome/fingerprint_manager.h"
#include "cryptohome/util/async_init.h"

namespace cryptohome {
namespace {

using cryptohome::error::CryptohomeError;
using cryptohome::error::ErrorActionSet;
using cryptohome::error::PossibleAction;
using cryptohome::error::PrimaryAction;
using hwsec_foundation::status::MakeStatus;
using hwsec_foundation::status::OkStatus;

}  // namespace

FingerprintAuthBlockService::Token::Token()
    : PreparedAuthFactorToken(AuthFactorType::kLegacyFingerprint),
      terminate_(*this) {}

void FingerprintAuthBlockService::Token::AttachToService(
    FingerprintAuthBlockService* service) {
  service_ = service;
}

CryptohomeStatus FingerprintAuthBlockService::Token::TerminateAuthFactor() {
  if (service_) {
    service_->Terminate();
  }
  return OkStatus<CryptohomeError>();
}

void FingerprintAuthBlockService::CheckSessionStartResult(
    std::unique_ptr<Token> token,
    PreparedAuthFactorToken::Consumer on_done,
    bool success) {
  // If Start fails, the token will be destroyed and considered no longer
  // active. On success the token is still active and this will be cancelled.
  absl::Cleanup clear_active_token = [this]() { active_token_ = nullptr; };

  if (!success) {
    CryptohomeStatus cryptohome_status = MakeStatus<CryptohomeError>(
        CRYPTOHOME_ERR_LOC(kLocFpServiceStartSessionFailure),
        ErrorActionSet({PossibleAction::kRetry}),
        user_data_auth::CryptohomeErrorCode::
            CRYPTOHOME_ERROR_FINGERPRINT_ERROR_INTERNAL);
    std::move(on_done).Run(std::move(cryptohome_status));
    return;
  }

  if (!fp_manager_) {
    CryptohomeStatus status = MakeStatus<CryptohomeError>(
        CRYPTOHOME_ERR_LOC(kLocFpServiceCheckSessionStartCouldNotGetFpManager),
        ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
        user_data_auth::CryptohomeErrorCode::
            CRYPTOHOME_ERROR_FINGERPRINT_ERROR_INTERNAL);
    std::move(on_done).Run(std::move(status));
    return;
  }

  std::move(clear_active_token).Cancel();
  fp_manager_->SetSignalCallback(base::BindRepeating(
      &FingerprintAuthBlockService::Capture, base::Unretained(this)));
  token->AttachToService(this);
  std::move(on_done).Run(std::move(token));
}

FingerprintAuthBlockService::FingerprintAuthBlockService(
    AsyncInitPtr<FingerprintManager> fp_manager,
    base::RepeatingCallback<void(user_data_auth::FingerprintScanResult)>
        signal_sender)
    : fp_manager_(fp_manager), signal_sender_(signal_sender) {}

std::unique_ptr<FingerprintAuthBlockService>
FingerprintAuthBlockService::MakeNullService() {
  // Construct an instance of the service with a getter callbacks that always
  // return null and a signal sender that does nothing.
  return std::make_unique<FingerprintAuthBlockService>(
      AsyncInitPtr<FingerprintManager>(nullptr),
      base::BindRepeating([](user_data_auth::FingerprintScanResult) {}));
}

CryptohomeStatus FingerprintAuthBlockService::Verify() {
  if (!fp_manager_) {
    return MakeStatus<CryptohomeError>(
        CRYPTOHOME_ERR_LOC(kLocFpServiceVerifyCouldNotGetFpManager),
        ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
        user_data_auth::CryptohomeErrorCode::
            CRYPTOHOME_ERROR_FINGERPRINT_ERROR_INTERNAL);
  }

  // If there is no active token then the service has not been started and the
  // verification should fail.
  if (!active_token_) {
    return MakeStatus<CryptohomeError>(
        CRYPTOHOME_ERR_LOC(kLocFpServiceCheckResultNoAuthSession),
        ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
        user_data_auth::CryptohomeErrorCode::
            CRYPTOHOME_ERROR_FINGERPRINT_ERROR_INTERNAL);
  }

  // Use the latest scan result to decide the response status.
  switch (scan_result_) {
    case FingerprintScanStatus::SUCCESS:
      return OkStatus<CryptohomeError>();
    case FingerprintScanStatus::FAILED_RETRY_ALLOWED:
      return MakeStatus<CryptohomeError>(
          CRYPTOHOME_ERR_LOC(kLocFpServiceCheckResultFailedYesRetry),
          ErrorActionSet(PrimaryAction::kIncorrectAuth),
          user_data_auth::CryptohomeErrorCode::
              CRYPTOHOME_ERROR_FINGERPRINT_RETRY_REQUIRED);
    case FingerprintScanStatus::FAILED_RETRY_NOT_ALLOWED:
      return MakeStatus<CryptohomeError>(
          CRYPTOHOME_ERR_LOC(kLocFpServiceCheckResultFailedNoRetry),
          ErrorActionSet(PrimaryAction::kLeLockedOut),
          user_data_auth::CryptohomeErrorCode::
              CRYPTOHOME_ERROR_FINGERPRINT_DENIED);
  }
}

void FingerprintAuthBlockService::Start(
    ObfuscatedUsername obfuscated_username,
    PreparedAuthFactorToken::Consumer on_done) {
  if (!fp_manager_) {
    CryptohomeStatus status = MakeStatus<CryptohomeError>(
        CRYPTOHOME_ERR_LOC(kLocFpServiceStartScanCouldNotGetFpManager),
        ErrorActionSet({PossibleAction::kRetry}),
        user_data_auth::CryptohomeErrorCode::
            CRYPTOHOME_ERROR_ATTESTATION_NOT_READY);
    std::move(on_done).Run(std::move(status));
    return;
  }

  if (active_token_) {
    CryptohomeStatus status = MakeStatus<CryptohomeError>(
        CRYPTOHOME_ERR_LOC(kLocFpServiceStartConcurrentSession),
        ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
        user_data_auth::CryptohomeErrorCode::
            CRYPTOHOME_ERROR_FINGERPRINT_DENIED);
    std::move(on_done).Run(std::move(status));
    return;
  }

  // Set up a callback with the manager to check the start session result.
  auto token = std::make_unique<Token>();
  active_token_ = token.get();
  fp_manager_->StartAuthSessionAsyncForUser(
      obfuscated_username,
      base::BindOnce(&FingerprintAuthBlockService::CheckSessionStartResult,
                     base::Unretained(this), std::move(token),
                     std::move(on_done)));
}

void FingerprintAuthBlockService::Terminate() {
  active_token_ = nullptr;
  scan_result_ = FingerprintScanStatus::FAILED_RETRY_NOT_ALLOWED;
  EndAuthSession();
}

void FingerprintAuthBlockService::Capture(FingerprintScanStatus status) {
  // If the session has been terminated, there will be no active token. In this
  // case, no-op when the callback is triggered.
  if (!active_token_) {
    return;
  }
  scan_result_ = status;
  user_data_auth::FingerprintScanResult outgoing_signal;
  switch (status) {
    case FingerprintScanStatus::SUCCESS:
      outgoing_signal = user_data_auth::FINGERPRINT_SCAN_RESULT_SUCCESS;
      break;
    case FingerprintScanStatus::FAILED_RETRY_ALLOWED:
      outgoing_signal = user_data_auth::FINGERPRINT_SCAN_RESULT_RETRY;
      break;
    case FingerprintScanStatus::FAILED_RETRY_NOT_ALLOWED:
      outgoing_signal = user_data_auth::FINGERPRINT_SCAN_RESULT_LOCKOUT;
  }
  if (signal_sender_) {
    signal_sender_.Run(outgoing_signal);
  }
}

void FingerprintAuthBlockService::EndAuthSession() {
  if (fp_manager_) {
    fp_manager_->EndAuthSession();
  }
}

FingerprintVerifier::FingerprintVerifier(FingerprintAuthBlockService* service)
    : AsyncCredentialVerifier(AuthFactorType::kLegacyFingerprint, "", {}),
      service_(service) {}

void FingerprintVerifier::VerifyAsync(const AuthInput& unused,
                                      StatusCallback callback) const {
  return std::move(callback).Run(service_->Verify());
}

}  // namespace cryptohome
