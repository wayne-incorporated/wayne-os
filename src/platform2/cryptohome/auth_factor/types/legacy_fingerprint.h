// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_AUTH_FACTOR_TYPES_LEGACY_FINGERPRINT_H_
#define CRYPTOHOME_AUTH_FACTOR_TYPES_LEGACY_FINGERPRINT_H_

#include <memory>
#include <optional>
#include <set>
#include <string>

#include "cryptohome/auth_blocks/fp_service.h"
#include "cryptohome/auth_blocks/prepare_token.h"
#include "cryptohome/auth_factor/auth_factor_label_arity.h"
#include "cryptohome/auth_factor/auth_factor_metadata.h"
#include "cryptohome/auth_factor/auth_factor_storage_type.h"
#include "cryptohome/auth_factor/auth_factor_type.h"
#include "cryptohome/auth_factor/types/common.h"
#include "cryptohome/auth_factor/types/interface.h"
#include "cryptohome/auth_intent.h"
#include "cryptohome/credential_verifier.h"
#include "cryptohome/key_objects.h"
#include "cryptohome/username.h"

namespace cryptohome {

class LegacyFingerprintAuthFactorDriver final
    : public AfDriverWithType<AuthFactorType::kLegacyFingerprint>,
      public AfDriverWithBlockTypes<>,
      public AfDriverWithMetadata<std::monostate>,
      public AfDriverFullAuthUnsupported,
      public AfDriverNoDelay,
      public AfDriverNoExpiration {
 public:
  explicit LegacyFingerprintAuthFactorDriver(
      FingerprintAuthBlockService* fp_service)
      : fp_service_(fp_service) {}

 private:
  bool IsSupportedByHardware() const override;
  bool IsSupportedByStorage(
      const std::set<AuthFactorStorageType>& configured_storage_types,
      const std::set<AuthFactorType>& configured_factors) const override;
  bool IsPrepareRequired() const override;
  void PrepareForAdd(const ObfuscatedUsername& username,
                     PreparedAuthFactorToken::Consumer callback) override;
  void PrepareForAuthenticate(
      const ObfuscatedUsername& username,
      PreparedAuthFactorToken::Consumer callback) override;
  bool IsLightAuthAllowed(AuthIntent auth_intent) const override;
  std::unique_ptr<CredentialVerifier> CreateCredentialVerifier(
      const std::string& auth_factor_label,
      const AuthInput& auth_input) const override;
  bool NeedsResetSecret() const override;
  bool NeedsRateLimiter() const override;
  AuthFactorLabelArity GetAuthFactorLabelArity() const override;

  std::optional<user_data_auth::AuthFactor> TypedConvertToProto(
      const auth_factor::CommonMetadata& common,
      const std::monostate& typed_metadata) const override;

  FingerprintAuthBlockService* fp_service_;
};

}  // namespace cryptohome

#endif  // CRYPTOHOME_AUTH_FACTOR_TYPES_LEGACY_FINGERPRINT_H_
