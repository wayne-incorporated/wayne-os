// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/auth_blocks/biometrics_auth_block_service.h"

#include <memory>
#include <optional>
#include <utility>

#include <base/functional/callback.h>
#include <cryptohome/proto_bindings/UserDataAuth.pb.h>

#include "cryptohome/auth_blocks/biometrics_command_processor.h"
#include "cryptohome/auth_blocks/prepare_token.h"
#include "cryptohome/error/cryptohome_error.h"
#include "cryptohome/error/location_utils.h"
#include "cryptohome/error/locations.h"

namespace cryptohome {

namespace {
using cryptohome::error::CryptohomeError;
using cryptohome::error::ErrorActionSet;
using cryptohome::error::PossibleAction;
using cryptohome::error::PrimaryAction;
using hwsec_foundation::status::MakeStatus;
using hwsec_foundation::status::OkStatus;
}  // namespace

BiometricsAuthBlockService::BiometricsAuthBlockService(
    std::unique_ptr<BiometricsCommandProcessor> processor,
    base::RepeatingCallback<void(user_data_auth::AuthEnrollmentProgress)>
        enroll_signal_sender,
    base::RepeatingCallback<void(user_data_auth::AuthScanDone)>
        auth_signal_sender)
    : processor_(std::move(processor)),
      enroll_signal_sender_(enroll_signal_sender),
      auth_signal_sender_(auth_signal_sender) {
  // Unretained is safe here because processor_ is owned by this.
  processor_->SetEnrollScanDoneCallback(base::BindRepeating(
      &BiometricsAuthBlockService::OnEnrollScanDone, base::Unretained(this)));
  processor_->SetAuthScanDoneCallback(base::BindRepeating(
      &BiometricsAuthBlockService::OnAuthScanDone, base::Unretained(this)));
  processor_->SetSessionFailedCallback(base::BindRepeating(
      &BiometricsAuthBlockService::OnSessionFailed, base::Unretained(this)));
}

bool BiometricsAuthBlockService::IsReady() {
  return processor_->IsReady();
}

void BiometricsAuthBlockService::StartEnrollSession(
    AuthFactorType auth_factor_type,
    ObfuscatedUsername obfuscated_username,
    PreparedAuthFactorToken::Consumer on_done) {
  if (active_token_ || pending_token_) {
    CryptohomeStatus status = MakeStatus<CryptohomeError>(
        CRYPTOHOME_ERR_LOC(kLocBiometricsServiceStartEnrollConcurrentSession),
        ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
        user_data_auth::CryptohomeErrorCode::CRYPTOHOME_ERROR_BIOMETRICS_BUSY);
    std::move(on_done).Run(std::move(status));
    return;
  }

  // Set up a callback with the processor to check the start session result.
  pending_token_ =
      std::make_unique<Token>(auth_factor_type, Token::TokenType::kEnroll,
                              std::move(obfuscated_username));
  processor_->StartEnrollSession(
      base::BindOnce(&BiometricsAuthBlockService::CheckSessionStartResult,
                     base::Unretained(this), std::move(on_done)));
}

void BiometricsAuthBlockService::CreateCredential(OperationInput payload,
                                                  OperationCallback on_done) {
  if (!active_token_ || active_token_->type() != Token::TokenType::kEnroll) {
    std::move(on_done).Run(MakeStatus<CryptohomeError>(
        CRYPTOHOME_ERR_LOC(kLocBiometricsServiceCreateCredentialNoSession),
        ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
        user_data_auth::CryptohomeErrorCode::
            CRYPTOHOME_ERROR_FINGERPRINT_ERROR_INTERNAL));
    return;
  }

  processor_->CreateCredential(active_token_->user_id(), std::move(payload),
                               std::move(on_done));
}

void BiometricsAuthBlockService::EndEnrollSession() {
  if (!active_token_ || active_token_->type() != Token::TokenType::kEnroll) {
    return;
  }

  active_token_ = nullptr;
  processor_->EndEnrollSession();
}

void BiometricsAuthBlockService::StartAuthenticateSession(
    AuthFactorType auth_factor_type,
    ObfuscatedUsername obfuscated_username,
    PreparedAuthFactorToken::Consumer on_done) {
  if (active_token_ || pending_token_) {
    CryptohomeStatus status = MakeStatus<CryptohomeError>(
        CRYPTOHOME_ERR_LOC(
            kLocBiometricsServiceStartAuthenticateConcurrentSession),
        ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
        user_data_auth::CryptohomeErrorCode::CRYPTOHOME_ERROR_BIOMETRICS_BUSY);
    std::move(on_done).Run(std::move(status));
    return;
  }

  // Set up a callback with the manager to check the start session result.
  pending_token_ = std::make_unique<Token>(
      auth_factor_type, Token::TokenType::kAuthenticate, obfuscated_username);
  processor_->StartAuthenticateSession(
      std::move(obfuscated_username),
      base::BindOnce(&BiometricsAuthBlockService::CheckSessionStartResult,
                     base::Unretained(this), std::move(on_done)));
}

void BiometricsAuthBlockService::MatchCredential(OperationInput payload,
                                                 OperationCallback on_done) {
  if (!active_token_ ||
      active_token_->type() != Token::TokenType::kAuthenticate) {
    std::move(on_done).Run(MakeStatus<CryptohomeError>(
        CRYPTOHOME_ERR_LOC(kLocBiometricsServiceMatchCredentialNoSession),
        ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
        user_data_auth::CryptohomeErrorCode::
            CRYPTOHOME_ERROR_FINGERPRINT_ERROR_INTERNAL));
    return;
  }

  processor_->MatchCredential(
      std::move(payload),
      base::BindOnce(&BiometricsAuthBlockService::OnMatchCredentialResponse,
                     base::Unretained(this), std::move(on_done)));
}

void BiometricsAuthBlockService::EndAuthenticateSession() {
  if (!active_token_ ||
      active_token_->type() != Token::TokenType::kAuthenticate) {
    return;
  }

  active_token_ = nullptr;
  processor_->EndAuthenticateSession();
}

std::optional<brillo::Blob> BiometricsAuthBlockService::TakeNonce() {
  return std::exchange(auth_nonce_, std::nullopt);
}

BiometricsAuthBlockService::Token::Token(AuthFactorType auth_factor_type,
                                         TokenType token_type,
                                         ObfuscatedUsername user_id)
    : PreparedAuthFactorToken(auth_factor_type),
      token_type_(token_type),
      user_id_(std::move(user_id)),
      terminate_(*this) {}

void BiometricsAuthBlockService::Token::AttachToService(
    BiometricsAuthBlockService* service) {
  service_ = service;
}

void BiometricsAuthBlockService::Token::DetachFromService() {
  service_ = nullptr;
}

CryptohomeStatus BiometricsAuthBlockService::Token::TerminateAuthFactor() {
  if (service_) {
    switch (token_type_) {
      case TokenType::kEnroll:
        service_->EndEnrollSession();
        break;
      case TokenType::kAuthenticate:
        service_->EndAuthenticateSession();
        break;
    }
  }
  return OkStatus<CryptohomeError>();
}

void BiometricsAuthBlockService::CheckSessionStartResult(
    PreparedAuthFactorToken::Consumer on_done, bool success) {
  if (active_token_) {
    CryptohomeStatus status = MakeStatus<CryptohomeError>(
        CRYPTOHOME_ERR_LOC(kLocBiometricsServiceCheckStartConcurrentSession),
        ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
        user_data_auth::CryptohomeErrorCode::CRYPTOHOME_ERROR_BIOMETRICS_BUSY);
    std::move(on_done).Run(std::move(status));
    return;
  }
  if (!pending_token_) {
    CryptohomeStatus status = MakeStatus<CryptohomeError>(
        CRYPTOHOME_ERR_LOC(kLocBiometricsServiceStartSessionNoToken),
        ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
        user_data_auth::CryptohomeErrorCode::
            CRYPTOHOME_ERROR_FINGERPRINT_ERROR_INTERNAL);
    std::move(on_done).Run(std::move(status));
    return;
  }
  std::unique_ptr<Token> token = std::move(pending_token_);
  if (!success) {
    CryptohomeStatus status = MakeStatus<CryptohomeError>(
        CRYPTOHOME_ERR_LOC(kLocBiometricsServiceStartSessionFailure),
        ErrorActionSet({PossibleAction::kRetry}),
        user_data_auth::CryptohomeErrorCode::
            CRYPTOHOME_ERROR_FINGERPRINT_ERROR_INTERNAL);
    std::move(on_done).Run(std::move(status));
    return;
  }
  token->AttachToService(this);
  active_token_ = token.get();
  std::move(on_done).Run(std::move(token));
}

void BiometricsAuthBlockService::OnEnrollScanDone(
    user_data_auth::AuthEnrollmentProgress signal,
    std::optional<brillo::Blob> nonce) {
  if (!active_token_ || active_token_->type() != Token::TokenType::kEnroll) {
    return;
  }

  if (nonce.has_value()) {
    auth_nonce_ = std::move(*nonce);
  }
  enroll_signal_sender_.Run(std::move(signal));
}

void BiometricsAuthBlockService::OnAuthScanDone(
    user_data_auth::AuthScanDone signal, brillo::Blob nonce) {
  if (!active_token_ ||
      active_token_->type() != Token::TokenType::kAuthenticate) {
    return;
  }

  auth_nonce_ = std::move(nonce);
  auth_signal_sender_.Run(std::move(signal));
}

void BiometricsAuthBlockService::OnSessionFailed() {
  if (!active_token_) {
    return;
  }

  Token::TokenType type = active_token_->type();
  active_token_->DetachFromService();
  active_token_ = nullptr;
  // Use FINGERPRINT_SCAN_RESULT_FATAL_ERROR to indicate session failure. We
  // don't have to make an explicit end session call here because it's assumed
  // that the session will be ended itself when an error occurs.
  switch (type) {
    case Token::TokenType::kEnroll: {
      user_data_auth::AuthEnrollmentProgress enroll_signal;
      enroll_signal.mutable_scan_result()->set_fingerprint_result(
          user_data_auth::FINGERPRINT_SCAN_RESULT_FATAL_ERROR);
      enroll_signal_sender_.Run(std::move(enroll_signal));
      break;
    }
    case Token::TokenType::kAuthenticate: {
      user_data_auth::AuthScanDone auth_signal;
      auth_signal.mutable_scan_result()->set_fingerprint_result(
          user_data_auth::FINGERPRINT_SCAN_RESULT_FATAL_ERROR);
      auth_signal_sender_.Run(std::move(auth_signal));
      break;
    }
  }
}

void BiometricsAuthBlockService::OnMatchCredentialResponse(
    OperationCallback callback, CryptohomeStatusOr<OperationOutput> resp) {
  // This means that the session is already terminated by the caller, and we
  // just need to return the MatchCredential response.
  if (!active_token_ ||
      active_token_->type() != Token::TokenType::kAuthenticate) {
    std::move(callback).Run(std::move(resp));
    return;
  }

  // Restart the session before returning the MatchCredential, so that when the
  // user sees the match verdict it's guaranteed that they can already perform
  // the next touch.
  processor_->StartAuthenticateSession(
      active_token_->user_id(),
      base::BindOnce(&BiometricsAuthBlockService::OnSessionRestartResult,
                     base::Unretained(this), std::move(callback),
                     std::move(resp)));
}

void BiometricsAuthBlockService::OnSessionRestartResult(
    OperationCallback callback,
    CryptohomeStatusOr<OperationOutput> resp,
    bool success) {
  // We need to check active_token_ here because if the session is already ended
  // by the caller, we shouldn't emit any signals afterwards.
  if (active_token_ &&
      active_token_->type() == Token::TokenType::kAuthenticate && !success) {
    active_token_->DetachFromService();
    active_token_ = nullptr;
    // If restarting session failed, Chrome will stop receiving auth scan
    // signals. Send a signal that indicates failure to inform Chrome about
    // this.
    user_data_auth::AuthScanDone session_failed_signal;
    session_failed_signal.mutable_scan_result()->set_fingerprint_result(
        user_data_auth::FingerprintScanResult::
            FINGERPRINT_SCAN_RESULT_FATAL_ERROR);
    auth_signal_sender_.Run(std::move(session_failed_signal));
  }
  std::move(callback).Run(std::move(resp));
}

}  // namespace cryptohome
