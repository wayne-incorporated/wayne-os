// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/auth_factor/types/smart_card.h"

#include <brillo/secure_blob.h>

#include "cryptohome/auth_blocks/challenge_credential_auth_block.h"
#include "cryptohome/auth_factor/auth_factor_label_arity.h"
#include "cryptohome/auth_factor/auth_factor_metadata.h"
#include "cryptohome/auth_factor/auth_factor_type.h"
#include "cryptohome/auth_factor/verifiers/smart_card.h"
#include "cryptohome/auth_intent.h"
#include "cryptohome/flatbuffer_schemas/auth_factor.h"

namespace cryptohome {
namespace {

// Helper function that will check the basic preconditions necessary for a
// challenge credential check to work.
bool IsChallengeCredentialReady(
    const AuthInput& auth_input,
    AsyncInitPtr<ChallengeCredentialsHelper> challenge_credentials_helper,
    KeyChallengeServiceFactory* key_challenge_service_factory) {
  return (
      challenge_credentials_helper.get() != nullptr &&
      key_challenge_service_factory != nullptr &&
      auth_input.challenge_credential_auth_input &&
      !auth_input.challenge_credential_auth_input->dbus_service_name.empty());
}

}  // namespace

bool SmartCardAuthFactorDriver::IsSupportedByHardware() const {
  return ChallengeCredentialAuthBlock::IsSupported(*crypto_).ok();
}

bool SmartCardAuthFactorDriver::IsLightAuthAllowed(
    AuthIntent auth_intent) const {
  return auth_intent == AuthIntent::kVerifyOnly;
}

std::unique_ptr<CredentialVerifier>
SmartCardAuthFactorDriver::CreateCredentialVerifier(
    const std::string& auth_factor_label, const AuthInput& auth_input) const {
  if (!IsChallengeCredentialReady(auth_input, challenge_credentials_helper_,
                                  key_challenge_service_factory_)) {
    return nullptr;
  }
  std::unique_ptr<CredentialVerifier> verifier = SmartCardVerifier::Create(
      auth_factor_label,
      auth_input.challenge_credential_auth_input->public_key_spki_der,
      challenge_credentials_helper_.get(), key_challenge_service_factory_);
  if (!verifier) {
    LOG(ERROR) << "Credential verifier initialization failed.";
    return nullptr;
  }
  return verifier;
}

bool SmartCardAuthFactorDriver::NeedsResetSecret() const {
  return false;
}

bool SmartCardAuthFactorDriver::NeedsRateLimiter() const {
  return false;
}

AuthFactorLabelArity SmartCardAuthFactorDriver::GetAuthFactorLabelArity()
    const {
  return AuthFactorLabelArity::kSingle;
}

std::optional<user_data_auth::AuthFactor>
SmartCardAuthFactorDriver::TypedConvertToProto(
    const auth_factor::CommonMetadata& common,
    const auth_factor::SmartCardMetadata& typed_metadata) const {
  user_data_auth::AuthFactor proto;
  proto.set_type(user_data_auth::AUTH_FACTOR_TYPE_SMART_CARD);
  proto.mutable_smart_card_metadata()->set_public_key_spki_der(
      brillo::BlobToString(typed_metadata.public_key_spki_der));
  return proto;
}

}  // namespace cryptohome
