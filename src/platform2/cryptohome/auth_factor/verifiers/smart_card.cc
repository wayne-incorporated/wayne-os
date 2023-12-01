// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/auth_factor/verifiers/smart_card.h"

#include <base/memory/ptr_util.h>

#include "cryptohome/auth_factor/auth_factor_metadata.h"
#include "cryptohome/auth_factor/auth_factor_type.h"
#include "cryptohome/error/cryptohome_error.h"
#include "cryptohome/error/location_utils.h"
#include "cryptohome/flatbuffer_schemas/auth_factor.h"

namespace cryptohome {

using error::CryptohomeError;
using error::ErrorActionSet;
using error::PossibleAction;
using error::PrimaryAction;
using ::hwsec_foundation::status::MakeStatus;
using ::hwsec_foundation::status::OkStatus;
using ::hwsec_foundation::status::StatusChain;

SmartCardVerifier::SmartCardVerifier(
    std::string auth_factor_label,
    const brillo::Blob& public_key_blob,
    ChallengeCredentialsHelper* challenge_credentials_helper,
    KeyChallengeServiceFactory* key_challenge_service_factory)
    : AsyncCredentialVerifier(
          AuthFactorType::kSmartCard,
          std::move(auth_factor_label),
          {.metadata = auth_factor::SmartCardMetadata{.public_key_spki_der =
                                                          public_key_blob}}),
      challenge_credentials_helper_(challenge_credentials_helper),
      key_challenge_service_factory_(key_challenge_service_factory) {
  CHECK(challenge_credentials_helper_);
  CHECK(key_challenge_service_factory_);
}

std::unique_ptr<SmartCardVerifier> SmartCardVerifier::Create(
    std::string auth_factor_label,
    const brillo::Blob& public_key_blob,
    ChallengeCredentialsHelper* challenge_credentials_helper,
    KeyChallengeServiceFactory* key_challenge_service_factory) {
  return base::WrapUnique(new SmartCardVerifier(
      std::move(auth_factor_label), public_key_blob,
      challenge_credentials_helper, key_challenge_service_factory));
}

void SmartCardVerifier::VerifyAsync(const AuthInput& auth_input,
                                    StatusCallback callback) const {
  if (!key_challenge_service_factory_) {
    LOG(ERROR) << __func__ << ": No valid key challenge service.";
    std::move(callback).Run(MakeStatus<CryptohomeError>(
        CRYPTOHOME_ERR_LOC(kLocSmartCardVerifierNoKeyService),
        ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
        user_data_auth::CryptohomeErrorCode::
            CRYPTOHOME_ERROR_INVALID_ARGUMENT));
    return;
  }

  if (auth_input.username->empty()) {
    LOG(ERROR) << __func__ << ": No valid username.";
    std::move(callback).Run(MakeStatus<CryptohomeError>(
        CRYPTOHOME_ERR_LOC(kLocSmartCardVerifierNoInputUser),
        ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
        user_data_auth::CryptohomeErrorCode::
            CRYPTOHOME_ERROR_INVALID_ARGUMENT));
    return;
  }

  if (!auth_input.challenge_credential_auth_input.has_value()) {
    LOG(ERROR) << __func__ << ": No valid challenge credential auth input.";
    std::move(callback).Run(MakeStatus<CryptohomeError>(
        CRYPTOHOME_ERR_LOC(kLocSmartCardVerifierNoInputAuth),
        ErrorActionSet(
            {PossibleAction::kDevCheckUnexpectedState, PossibleAction::kAuth}),
        user_data_auth::CryptohomeErrorCode::
            CRYPTOHOME_ERROR_INVALID_ARGUMENT));
    return;
  }

  if (auth_input.challenge_credential_auth_input.value()
          .challenge_signature_algorithms.empty()) {
    LOG(ERROR) << __func__ << ": No valid challenge signature algorithms.";

    std::move(callback).Run(MakeStatus<CryptohomeError>(
        CRYPTOHOME_ERR_LOC(kLocSmartCardVerifierNoInputAlg),
        ErrorActionSet(
            {PossibleAction::kDevCheckUnexpectedState, PossibleAction::kAuth}),
        user_data_auth::CryptohomeErrorCode::
            CRYPTOHOME_ERROR_INVALID_ARGUMENT));
    return;
  }

  auto key_challenge_service = key_challenge_service_factory_->New(
      auth_input.challenge_credential_auth_input->dbus_service_name);

  structure::ChallengePublicKeyInfo public_key_info{
      .public_key_spki_der = auth_input.challenge_credential_auth_input.value()
                                 .public_key_spki_der,
      .signature_algorithm = auth_input.challenge_credential_auth_input.value()
                                 .challenge_signature_algorithms,
  };

  // Attempt the lightweight check against the found user session.
  challenge_credentials_helper_->VerifyKey(
      std::move(auth_input.username), std::move(public_key_info),
      std::move(key_challenge_service),
      base::BindOnce(&SmartCardVerifier::OnVerifyContinue,
                     base::Unretained(this), std::move(callback)));
}

void SmartCardVerifier::OnVerifyContinue(StatusCallback callback,
                                         CryptoStatus status) const {
  if (!status.ok()) {
    std::move(callback).Run(
        MakeStatus<CryptohomeError>(
            CRYPTOHOME_ERR_LOC(kLocSmartCardVerifierCannotVerify))
            .Wrap(std::move(status)));
    return;
  }

  // Note that the LE credentials are not reset here, since we don't have the
  // full credentials after the lightweight check.
  std::move(callback).Run(OkStatus<CryptohomeError>());
}

}  // namespace cryptohome
