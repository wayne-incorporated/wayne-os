// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_AUTH_FACTOR_TYPES_NULL_H_
#define CRYPTOHOME_AUTH_FACTOR_TYPES_NULL_H_

#include <memory>
#include <optional>
#include <set>
#include <string>

#include "cryptohome/auth_factor/auth_factor_label_arity.h"
#include "cryptohome/auth_factor/auth_factor_metadata.h"
#include "cryptohome/auth_factor/auth_factor_storage_type.h"
#include "cryptohome/auth_factor/auth_factor_type.h"
#include "cryptohome/auth_factor/types/common.h"
#include "cryptohome/auth_factor/types/interface.h"
#include "cryptohome/auth_intent.h"
#include "cryptohome/credential_verifier.h"
#include "cryptohome/key_objects.h"

namespace cryptohome {

// Implementation of the null object pattern for auth factor drivers. Provides
// useful defaults (which fail or return something equivalent to nothing) for
// all functions implemented by a factor.
class NullAuthFactorDriver final
    : public AfDriverWithType<AuthFactorType::kUnspecified>,
      public AfDriverWithBlockTypes<>,
      public AfDriverNoPrepare,
      public AfDriverFullAuthUnsupported,
      public AfDriverNoCredentialVerifier,
      public AfDriverNoDelay,
      public AfDriverNoExpiration {
 public:
  NullAuthFactorDriver() = default;

 private:
  bool IsSupportedByHardware() const override { return false; }
  bool IsSupportedByStorage(
      const std::set<AuthFactorStorageType>& /*configured_storage_types*/,
      const std::set<AuthFactorType>& /*configured_factors*/) const override {
    return false;
  }
  bool NeedsResetSecret() const override { return false; }
  bool NeedsRateLimiter() const override { return false; }
  AuthFactorLabelArity GetAuthFactorLabelArity() const override {
    return AuthFactorLabelArity::kNone;
  }
  std::optional<user_data_auth::AuthFactor> ConvertToProto(
      const std::string& label,
      const AuthFactorMetadata& metadata) const override {
    return std::nullopt;
  }
};

}  // namespace cryptohome

#endif  // CRYPTOHOME_AUTH_FACTOR_TYPES_NULL_H_
