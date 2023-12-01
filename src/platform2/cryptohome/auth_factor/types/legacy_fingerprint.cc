// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/auth_factor/types/legacy_fingerprint.h"

#include <utility>

#include <libhwsec-foundation/status/status_chain.h>

#include "cryptohome/auth_blocks/fp_service.h"
#include "cryptohome/auth_blocks/prepare_token.h"
#include "cryptohome/auth_factor/auth_factor_label_arity.h"
#include "cryptohome/auth_factor/auth_factor_type.h"
#include "cryptohome/auth_intent.h"
#include "cryptohome/error/action.h"
#include "cryptohome/error/location_utils.h"
#include "cryptohome/error/locations.h"
#include "cryptohome/username.h"

namespace cryptohome {
namespace {

using ::cryptohome::error::CryptohomeError;
using ::cryptohome::error::ErrorActionSet;
using ::cryptohome::error::PossibleAction;
using ::hwsec_foundation::status::MakeStatus;

}  // namespace

bool LegacyFingerprintAuthFactorDriver::IsSupportedByHardware() const {
  return false;
}

bool LegacyFingerprintAuthFactorDriver::IsSupportedByStorage(
    const std::set<AuthFactorStorageType>& /*configured_storage_types*/,
    const std::set<AuthFactorType>& /*configured_factors*/) const {
  return false;
}

bool LegacyFingerprintAuthFactorDriver::IsPrepareRequired() const {
  return true;
}

void LegacyFingerprintAuthFactorDriver::PrepareForAdd(
    const ObfuscatedUsername& username,
    PreparedAuthFactorToken::Consumer callback) {
  std::move(callback).Run(MakeStatus<CryptohomeError>(
      CRYPTOHOME_ERR_LOC(kLocAuthFactorLegacyFpPrepareForAddUnsupported),
      ErrorActionSet(
          {PossibleAction::kDevCheckUnexpectedState, PossibleAction::kAuth}),
      user_data_auth::CryptohomeErrorCode::CRYPTOHOME_ERROR_INVALID_ARGUMENT));
}

void LegacyFingerprintAuthFactorDriver::PrepareForAuthenticate(
    const ObfuscatedUsername& username,
    PreparedAuthFactorToken::Consumer callback) {
  fp_service_->Start(username, std::move(callback));
}

bool LegacyFingerprintAuthFactorDriver::IsLightAuthAllowed(
    AuthIntent auth_intent) const {
  return auth_intent == AuthIntent::kWebAuthn ||
         auth_intent == AuthIntent::kVerifyOnly;
}

std::unique_ptr<CredentialVerifier>
LegacyFingerprintAuthFactorDriver::CreateCredentialVerifier(
    const std::string& auth_factor_label, const AuthInput& auth_input) const {
  if (!auth_factor_label.empty()) {
    LOG(ERROR) << "Legacy fingerprint verifiers cannot use labels";
    return nullptr;
  }
  if (!fp_service_) {
    LOG(ERROR) << "Cannot construct a legacy fingerprint verifier, "
                  "FP service not available";
    return nullptr;
  }
  return std::make_unique<FingerprintVerifier>(fp_service_);
}

bool LegacyFingerprintAuthFactorDriver::NeedsResetSecret() const {
  return false;
}

bool LegacyFingerprintAuthFactorDriver::NeedsRateLimiter() const {
  return false;
}

AuthFactorLabelArity
LegacyFingerprintAuthFactorDriver::GetAuthFactorLabelArity() const {
  return AuthFactorLabelArity::kNone;
}

std::optional<user_data_auth::AuthFactor>
LegacyFingerprintAuthFactorDriver::TypedConvertToProto(
    const auth_factor::CommonMetadata& common,
    const std::monostate& typed_metadata) const {
  user_data_auth::AuthFactor proto;
  proto.set_type(user_data_auth::AUTH_FACTOR_TYPE_LEGACY_FINGERPRINT);
  return proto;
}

}  // namespace cryptohome
