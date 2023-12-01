// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/auth_blocks/challenge_credential_auth_block.h"

#include <memory>
#include <optional>
#include <utility>
#include <variant>

#include <base/check.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/notreached.h>
#include <libhwsec/frontend/cryptohome/frontend.h>
#include <libhwsec/status.h>

#include "cryptohome/auth_blocks/scrypt_auth_block.h"
#include "cryptohome/auth_blocks/tpm_auth_block_utils.h"
#include "cryptohome/challenge_credentials/challenge_credentials_helper_impl.h"
#include "cryptohome/crypto.h"
#include "cryptohome/crypto_error.h"
#include "cryptohome/cryptohome_metrics.h"
#include "cryptohome/error/action.h"
#include "cryptohome/error/cryptohome_crypto_error.h"
#include "cryptohome/error/location_utils.h"
#include "cryptohome/error/locations.h"
#include "cryptohome/flatbuffer_schemas/auth_block_state.h"
#include "cryptohome/key_objects.h"
#include "cryptohome/username.h"

using cryptohome::error::CryptohomeCryptoError;
using cryptohome::error::ErrorActionSet;
using cryptohome::error::PossibleAction;
using cryptohome::error::PrimaryAction;
using hwsec_foundation::status::MakeStatus;
using hwsec_foundation::status::OkStatus;
using hwsec_foundation::status::StatusChain;

namespace cryptohome {

CryptoStatus ChallengeCredentialAuthBlock::IsSupported(Crypto& crypto) {
  DCHECK(crypto.GetHwsec());
  hwsec::StatusOr<bool> is_ready = crypto.GetHwsec()->IsReady();
  if (!is_ready.ok()) {
    return MakeStatus<CryptohomeCryptoError>(
               CRYPTOHOME_ERR_LOC(
                   kLocChalCredAuthBlockHwsecReadyErrorInIsSupported),
               ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}))
        .Wrap(TpmAuthBlockUtils::TPMErrorToCryptohomeCryptoError(
            std::move(is_ready).err_status()));
  }
  if (!is_ready.value()) {
    return MakeStatus<CryptohomeCryptoError>(
        CRYPTOHOME_ERR_LOC(kLocChalCredAuthBlockHwsecNotReadyInIsSupported),
        ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
        CryptoError::CE_OTHER_CRYPTO);
  }

  // TODO(b/262038957): Move checks from
  // `ChallengeCredentialsHelperImpl::CheckTPMStatus()` here.
  return OkStatus<CryptohomeCryptoError>();
}

std::unique_ptr<AuthBlock> ChallengeCredentialAuthBlock::New(
    const AuthInput& auth_input,
    AsyncInitPtr<ChallengeCredentialsHelper> challenge_credentials_helper,
    KeyChallengeServiceFactory* key_challenge_service_factory) {
  if (challenge_credentials_helper && key_challenge_service_factory &&
      auth_input.challenge_credential_auth_input &&
      !auth_input.challenge_credential_auth_input->dbus_service_name.empty()) {
    auto key_challenge_service = key_challenge_service_factory->New(
        auth_input.challenge_credential_auth_input->dbus_service_name);
    return std::make_unique<ChallengeCredentialAuthBlock>(
        challenge_credentials_helper.get(), std::move(key_challenge_service),
        auth_input.username);
  }
  LOG(ERROR) << "No valid ChallengeCredentialsHelper, KeyChallengeService, or "
                "account id available";
  return nullptr;
}

ChallengeCredentialAuthBlock::ChallengeCredentialAuthBlock(
    ChallengeCredentialsHelper* challenge_credentials_helper,
    std::unique_ptr<KeyChallengeService> key_challenge_service,
    const Username& account_id)
    : AuthBlock(kSignatureChallengeProtected),
      challenge_credentials_helper_(challenge_credentials_helper),
      key_challenge_service_(std::move(key_challenge_service)),
      account_id_(account_id) {
  CHECK(challenge_credentials_helper_);
  CHECK(key_challenge_service_);
}

void ChallengeCredentialAuthBlock::Create(const AuthInput& auth_input,
                                          CreateCallback callback) {
  if (!key_challenge_service_) {
    LOG(ERROR) << __func__ << ": No valid key challenge service.";
    std::move(callback).Run(
        MakeStatus<CryptohomeCryptoError>(
            CRYPTOHOME_ERR_LOC(kLocChalCredAuthBlockNoKeyServiceInCreate),
            ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
            CryptoError::CE_OTHER_CRYPTO),
        nullptr, nullptr);
    return;
  }

  if (!auth_input.obfuscated_username.has_value()) {
    LOG(ERROR) << __func__ << ": No valid obfuscated username.";
    std::move(callback).Run(
        MakeStatus<CryptohomeCryptoError>(
            CRYPTOHOME_ERR_LOC(kLocChalCredAuthBlockNoInputUserInCreate),
            ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
            CryptoError::CE_OTHER_CRYPTO),
        nullptr, nullptr);
    return;
  }

  if (!auth_input.challenge_credential_auth_input.has_value()) {
    LOG(ERROR) << __func__ << ": No valid challenge credential auth input.";
    std::move(callback).Run(
        MakeStatus<CryptohomeCryptoError>(
            CRYPTOHOME_ERR_LOC(kLocChalCredAuthBlockNoInputAuthInCreate),
            ErrorActionSet({PossibleAction::kDevCheckUnexpectedState,
                            PossibleAction::kAuth}),
            CryptoError::CE_OTHER_CRYPTO),
        nullptr, nullptr);
    return;
  }

  if (auth_input.challenge_credential_auth_input.value()
          .challenge_signature_algorithms.empty()) {
    LOG(ERROR) << __func__ << ": No valid challenge signature algorithms.";
    std::move(callback).Run(
        MakeStatus<CryptohomeCryptoError>(
            CRYPTOHOME_ERR_LOC(kLocChalCredAuthBlockNoInputAlgInCreate),
            ErrorActionSet({PossibleAction::kDevCheckUnexpectedState,
                            PossibleAction::kAuth}),
            CryptoError::CE_OTHER_CRYPTO),
        nullptr, nullptr);
    return;
  }

  structure::ChallengePublicKeyInfo public_key_info{
      .public_key_spki_der = auth_input.challenge_credential_auth_input.value()
                                 .public_key_spki_der,
      .signature_algorithm = auth_input.challenge_credential_auth_input.value()
                                 .challenge_signature_algorithms,
  };

  const ObfuscatedUsername& obfuscated_username =
      auth_input.obfuscated_username.value();

  challenge_credentials_helper_->GenerateNew(
      std::move(account_id_), std::move(public_key_info), obfuscated_username,
      std::move(key_challenge_service_),
      base::BindOnce(&ChallengeCredentialAuthBlock::CreateContinue,
                     weak_factory_.GetWeakPtr(), std::move(callback)));
}

void ChallengeCredentialAuthBlock::CreateContinue(
    CreateCallback callback,
    CryptoStatusOr<ChallengeCredentialsHelper::GenerateNewOrDecryptResult>
        result) {
  if (!result.ok()) {
    LOG(ERROR) << __func__ << ": Failed to obtain challenge-response passkey.";
    std::move(callback).Run(
        MakeStatus<CryptohomeCryptoError>(
            CRYPTOHOME_ERR_LOC(
                kLocChalCredAuthBlockServiceGenerateFailedInCreate))
            .Wrap(std::move(result).err_status()),
        nullptr, nullptr);
    return;
  }

  ChallengeCredentialsHelper::GenerateNewOrDecryptResult result_val =
      std::move(result).value();
  std::unique_ptr<structure::SignatureChallengeInfo> signature_challenge_info =
      result_val.info();
  std::unique_ptr<brillo::SecureBlob> passkey = result_val.passkey();
  DCHECK(passkey);

  // We only need passkey for the AuthInput.
  AuthInput auth_input = {.user_input = std::move(*passkey)};

  ScryptAuthBlock scrypt_auth_block;
  scrypt_auth_block.Create(
      auth_input,
      base::BindOnce(&ChallengeCredentialAuthBlock::CreateContinueAfterScrypt,
                     weak_factory_.GetWeakPtr(), std::move(callback),
                     std::move(signature_challenge_info)));
}

void ChallengeCredentialAuthBlock::CreateContinueAfterScrypt(
    CreateCallback callback,
    std::unique_ptr<structure::SignatureChallengeInfo> signature_challenge_info,
    CryptohomeStatus error,
    std::unique_ptr<KeyBlobs> key_blobs,
    std::unique_ptr<AuthBlockState> auth_block_state) {
  if (!error.ok()) {
    LOG(ERROR) << __func__
               << "scrypt creation failed for challenge credential.";
    std::move(callback).Run(
        MakeStatus<error::CryptohomeError>(
            CRYPTOHOME_ERR_LOC(kLocChalCredAuthBlockCannotCreateScryptInCreate))
            .Wrap(std::move(error)),
        nullptr, nullptr);
    return;
  }

  if (auto* scrypt_state =
          std::get_if<ScryptAuthBlockState>(&auth_block_state->state)) {
    ChallengeCredentialAuthBlockState cc_state = {
        .scrypt_state = std::move(*scrypt_state),
        .keyset_challenge_info = std::move(*signature_challenge_info),
    };

    auto auth_block_state = std::make_unique<AuthBlockState>(
        AuthBlockState{.state = std::move(cc_state)});

    std::move(callback).Run(OkStatus<CryptohomeCryptoError>(),
                            std::move(key_blobs), std::move(auth_block_state));
  } else {
    // This should never happen, but handling it anyway on the safe side.
    NOTREACHED() << "scrypt derivation failed for challenge credential.";
    std::move(callback).Run(
        MakeStatus<CryptohomeCryptoError>(
            CRYPTOHOME_ERR_LOC(
                kLocChalCredAuthBlockScryptDerivationFailedInCreate),
            ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
            CryptoError::CE_OTHER_CRYPTO),
        nullptr, nullptr);
  }
}

void ChallengeCredentialAuthBlock::Derive(const AuthInput& auth_input,
                                          const AuthBlockState& state,
                                          DeriveCallback callback) {
  if (!auth_input.challenge_credential_auth_input.has_value()) {
    LOG(ERROR) << __func__ << ": No valid challenge credential auth input.";
    std::move(callback).Run(
        MakeStatus<CryptohomeCryptoError>(
            CRYPTOHOME_ERR_LOC(kLocChalCredAuthBlockNoInputAuthInDerive),
            ErrorActionSet({PossibleAction::kDevCheckUnexpectedState,
                            PossibleAction::kAuth}),
            CryptoError::CE_OTHER_CRYPTO),
        nullptr, std::nullopt);
    return;
  }

  if (!key_challenge_service_) {
    LOG(ERROR) << __func__ << ": No valid key challenge service.";
    std::move(callback).Run(
        MakeStatus<CryptohomeCryptoError>(
            CRYPTOHOME_ERR_LOC(kLocChalCredAuthBlockNoKeyServiceInDerive),
            ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
            CryptoError::CE_OTHER_CRYPTO),
        nullptr, std::nullopt);
    return;
  }

  const ChallengeCredentialAuthBlockState* cc_state =
      std::get_if<ChallengeCredentialAuthBlockState>(&state.state);
  if (cc_state == nullptr) {
    LOG(ERROR) << __func__
               << "Invalid state for challenge credential AuthBlock.";
    std::move(callback).Run(
        MakeStatus<CryptohomeCryptoError>(
            CRYPTOHOME_ERR_LOC(kLocChalCredAuthBlockInvalidBlockStateInDerive),
            ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
            CryptoError::CE_OTHER_FATAL),
        nullptr, std::nullopt);
    return;
  }

  if (!cc_state->keyset_challenge_info.has_value()) {
    LOG(ERROR)
        << __func__
        << "No signature challenge info in challenge credential AuthBlock.";
    std::move(callback).Run(
        MakeStatus<CryptohomeCryptoError>(
            CRYPTOHOME_ERR_LOC(kLocChalCredAuthBlockNoChallengeInfoInDerive),
            ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
            CryptoError::CE_OTHER_CRYPTO),
        nullptr, std::nullopt);
    return;
  }

  const structure::SignatureChallengeInfo& keyset_challenge_info =
      cc_state->keyset_challenge_info.value();
  if (!keyset_challenge_info.salt_signature_algorithm.has_value()) {
    LOG(ERROR)
        << __func__
        << "No signature algorithm info in challenge credential AuthBlock.";
    std::move(callback).Run(
        MakeStatus<CryptohomeCryptoError>(
            CRYPTOHOME_ERR_LOC(kLocChalCredAuthBlockNoAlgorithmInfoInDerive),
            ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
            CryptoError::CE_OTHER_CRYPTO),
        nullptr, std::nullopt);
    return;
  }

  structure::ChallengePublicKeyInfo public_key_info{
      .public_key_spki_der = keyset_challenge_info.public_key_spki_der,
      .signature_algorithm = auth_input.challenge_credential_auth_input.value()
                                 .challenge_signature_algorithms,
  };

  AuthBlockState scrypt_state = {.state = cc_state->scrypt_state};

  challenge_credentials_helper_->Decrypt(
      std::move(account_id_), std::move(public_key_info),
      cc_state->keyset_challenge_info.value(),
      std::move(key_challenge_service_),
      base::BindOnce(&ChallengeCredentialAuthBlock::DeriveContinue,
                     weak_factory_.GetWeakPtr(), std::move(callback),
                     std::move(scrypt_state)));
  return;
}

void ChallengeCredentialAuthBlock::DeriveContinue(
    DeriveCallback callback,
    const AuthBlockState& scrypt_state,
    CryptoStatusOr<ChallengeCredentialsHelper::GenerateNewOrDecryptResult>
        result) {
  if (!result.ok()) {
    LOG(ERROR) << __func__ << ": Failed to obtain challenge-response passkey.";
    std::move(callback).Run(
        MakeStatus<CryptohomeCryptoError>(
            CRYPTOHOME_ERR_LOC(
                kLocChalCredAuthBlockServiceDeriveFailedInDerive))
            .Wrap(std::move(result).err_status()),
        nullptr, std::nullopt);
    return;
  }

  ChallengeCredentialsHelper::GenerateNewOrDecryptResult result_val =
      std::move(result).value();
  std::unique_ptr<brillo::SecureBlob> passkey = result_val.passkey();
  DCHECK(passkey);

  // We only need passkey for the ScryptAuthBlock AuthInput.
  AuthInput auth_input = {.user_input = std::move(*passkey)};

  ScryptAuthBlock scrypt_auth_block;
  auto key_blobs = std::make_unique<KeyBlobs>();
  scrypt_auth_block.Derive(auth_input, scrypt_state, std::move(callback));
}

}  // namespace cryptohome
