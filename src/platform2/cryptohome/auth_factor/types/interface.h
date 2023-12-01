// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_AUTH_FACTOR_TYPES_INTERFACE_H_
#define CRYPTOHOME_AUTH_FACTOR_TYPES_INTERFACE_H_

#include <cstdint>
#include <memory>
#include <optional>
#include <set>
#include <string>

#include <base/containers/span.h>
#include <base/time/time.h>
#include <cryptohome/proto_bindings/auth_factor.pb.h>

#include "cryptohome/auth_blocks/auth_block_type.h"
#include "cryptohome/auth_blocks/prepare_token.h"
#include "cryptohome/auth_factor/auth_factor.h"
#include "cryptohome/auth_factor/auth_factor_label_arity.h"
#include "cryptohome/auth_factor/auth_factor_metadata.h"
#include "cryptohome/auth_factor/auth_factor_storage_type.h"
#include "cryptohome/auth_factor/auth_factor_type.h"
#include "cryptohome/auth_intent.h"
#include "cryptohome/credential_verifier.h"
#include "cryptohome/error/cryptohome_error.h"
#include "cryptohome/key_objects.h"
#include "cryptohome/username.h"

namespace cryptohome {

// Defines a general interface that implements utility operations for
// interacting with an AuthFactor. This will be subclassed by a separate
// implementation for each AuthFactorType.
class AuthFactorDriver {
 public:
  AuthFactorDriver() = default;

  AuthFactorDriver(const AuthFactorDriver&) = delete;
  AuthFactorDriver& operator=(const AuthFactorDriver&) = delete;

  virtual ~AuthFactorDriver() = default;

  // The type of factor the driver implements.
  virtual AuthFactorType type() const = 0;

  // The underlying auth block types that the factor uses. The span lists them
  // in priority order, with the first element being the most preferred block
  // type to use.
  virtual base::span<const AuthBlockType> block_types() const = 0;

  // Indicates if the factor is supported by the current hardware. This should
  // things like along the lines of "is the necessary hardware present", "does
  // it have the right firmware", "is it running".
  virtual bool IsSupportedByHardware() const = 0;

  // Indicates if the factor is supported by the current storage configuration.
  // This depends on both what type of storage is in use, and what other factors
  // already exist.
  virtual bool IsSupportedByStorage(
      const std::set<AuthFactorStorageType>& configured_storage_types,
      const std::set<AuthFactorType>& configured_factors) const = 0;

  // Indicates if the factor requires the use of a Prepare operation before it
  // can be added or authenticated.
  virtual bool IsPrepareRequired() const = 0;

  // Prepare the factor type for the addition of a new instance of this factor.
  // Returns through the asynchronous |callback|.
  virtual void PrepareForAdd(const ObfuscatedUsername& username,
                             PreparedAuthFactorToken::Consumer callback) = 0;

  // Prepare the factor type for authentication. Returns through the
  // asynchronous |callback|.
  virtual void PrepareForAuthenticate(
      const ObfuscatedUsername& username,
      PreparedAuthFactorToken::Consumer callback) = 0;

  // Specifies if the factor supports the given intent when doing either full or
  // lightweight authentication. The full authentication is when you do a
  // complete Authenticate sequence with the factor's underlying auth block
  // while the lightweight authentication is done via a CredentialVerifier.
  virtual bool IsFullAuthAllowed(AuthIntent auth_intent) const = 0;
  virtual bool IsLightAuthAllowed(AuthIntent auth_intent) const = 0;

  // Creates a credential verifier for the specified type and input. Returns
  // null on failure or if verifiers are not supported by the driver.
  virtual std::unique_ptr<CredentialVerifier> CreateCredentialVerifier(
      const std::string& auth_factor_label,
      const AuthInput& auth_input) const = 0;

  // This returns if a type needs a reset secret.
  virtual bool NeedsResetSecret() const = 0;

  // This returns if a type is rate-limiter backed.
  virtual bool NeedsRateLimiter() const = 0;

  // This returns if a type supports delayed availability.
  virtual bool IsDelaySupported() const = 0;

  // Given an AuthFactor instance, attempt to determine how long the current
  // availability delay is. Returns a not-OK status if the delay cannot be
  // determined or the type does not support delay.
  virtual CryptohomeStatusOr<base::TimeDelta> GetFactorDelay(
      const ObfuscatedUsername& username, const AuthFactor& factor) const = 0;

  // This returns if a type supports availability expiration.
  virtual bool IsExpirationSupported() const = 0;

  // Given an AuthFactor instance, attempt to determine whether it is expired.
  // Returns a not-OK status if the expiration cannot be determined or the type
  // does not support expiration.
  virtual CryptohomeStatusOr<bool> IsExpired(const ObfuscatedUsername& username,
                                             const AuthFactor& factor) = 0;

  // Return an enum indicating the label arity of the auth factor (e.g. does the
  // factor support single-label authentication or multi-label authentication).
  virtual AuthFactorLabelArity GetAuthFactorLabelArity() const = 0;

  // Attempt to construct the D-Bus API proto for an AuthFactor using the given
  // metadata and label. Returns null if the conversion fails.
  virtual std::optional<user_data_auth::AuthFactor> ConvertToProto(
      const std::string& label, const AuthFactorMetadata& metadata) const = 0;
};

}  // namespace cryptohome

#endif  // CRYPTOHOME_AUTH_FACTOR_TYPES_INTERFACE_H_
