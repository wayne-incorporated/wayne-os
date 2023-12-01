// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/auth_factor/types/password.h"

#include "cryptohome/auth_factor/auth_factor_label_arity.h"
#include "cryptohome/auth_factor/auth_factor_metadata.h"
#include "cryptohome/auth_factor/auth_factor_type.h"
#include "cryptohome/auth_factor/verifiers/scrypt.h"
#include "cryptohome/auth_intent.h"
#include "cryptohome/flatbuffer_schemas/auth_factor.h"

namespace cryptohome {

bool PasswordAuthFactorDriver::IsSupportedByHardware() const {
  return true;
}

bool PasswordAuthFactorDriver::IsLightAuthAllowed(
    AuthIntent auth_intent) const {
  return auth_intent == AuthIntent::kVerifyOnly;
}

std::unique_ptr<CredentialVerifier>
PasswordAuthFactorDriver::CreateCredentialVerifier(
    const std::string& auth_factor_label, const AuthInput& auth_input) const {
  if (!auth_input.user_input.has_value()) {
    LOG(ERROR) << "Cannot construct a password verifier without a password";
    return nullptr;
  }
  std::unique_ptr<CredentialVerifier> verifier =
      ScryptVerifier::Create(auth_factor_label, *auth_input.user_input);
  if (!verifier) {
    LOG(ERROR) << "Credential verifier initialization failed.";
    return nullptr;
  }
  return verifier;
}

bool PasswordAuthFactorDriver::NeedsResetSecret() const {
  return false;
}

bool PasswordAuthFactorDriver::NeedsRateLimiter() const {
  return false;
}

AuthFactorLabelArity PasswordAuthFactorDriver::GetAuthFactorLabelArity() const {
  return AuthFactorLabelArity::kSingle;
}

std::optional<user_data_auth::AuthFactor>
PasswordAuthFactorDriver::TypedConvertToProto(
    const auth_factor::CommonMetadata& common,
    const auth_factor::PasswordMetadata& typed_metadata) const {
  user_data_auth::AuthFactor proto;
  proto.set_type(user_data_auth::AUTH_FACTOR_TYPE_PASSWORD);
  proto.mutable_password_metadata();
  return proto;
}

}  // namespace cryptohome
