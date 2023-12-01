// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This class contains common, reusable implementations of various subsets of
// the AuthFactorDriver interface.
//
// Using these classes generally involves using multiple inheritance, since if
// you want to use more than one (and you almost certainly do) you'll need to
// derive from all of them. In order to keep things simple and straightforward,
// we follow a few rules:
//   * All of the classes virtually inherit directly from AuthFactorDriver.
//   * The classes do final overrides of the functions they implement, to
//     prevent you from mixing conflicting implementations.
//   * If you choose to use these classes, you should subclass them and only
//     them. Do not also directly inherit from AuthFactorDriver yourself and
//     do not try to mix them in at multiple layers in a complex hierarchy.
// This keeps the usage model simple: define your driver class, subclass from
// all of the common classes you want to use, and then implement the rest of the
// virtual functions yourself.

#ifndef CRYPTOHOME_AUTH_FACTOR_TYPES_COMMON_H_
#define CRYPTOHOME_AUTH_FACTOR_TYPES_COMMON_H_

#include <array>
#include <memory>
#include <optional>
#include <set>
#include <string>

#include <base/containers/span.h>
#include <base/time/time.h>
#include <cryptohome/proto_bindings/auth_factor.pb.h>

#include "cryptohome/auth_blocks/auth_block_type.h"
#include "cryptohome/auth_factor/auth_factor_metadata.h"
#include "cryptohome/auth_factor/auth_factor_storage_type.h"
#include "cryptohome/auth_factor/auth_factor_type.h"
#include "cryptohome/auth_factor/types/interface.h"
#include "cryptohome/auth_intent.h"
#include "cryptohome/credential_verifier.h"

namespace cryptohome {

// Common implementation of type(). Takes the type as a template parameter.
template <AuthFactorType kType>
class AfDriverWithType : public virtual AuthFactorDriver {
 protected:
  AuthFactorType type() const final { return kType; }
};

// Common implementation of block_type(). Takes the block types as a template
// parameter pack. The types should be ordered from highest to lowest priority
// the same way block_type() expects them to be listed.
template <AuthBlockType... kTypes>
class AfDriverWithBlockTypes : public virtual AuthFactorDriver {
 protected:
  base::span<const AuthBlockType> block_types() const override {
    return kTypeArray;
  }

 private:
  // The underlying storage for the auth block type list. We back all the
  // block_types lookups with a singular static array.
  static constexpr std::array<AuthBlockType, sizeof...(kTypes)> kTypeArray = {
      kTypes...};
};

// Common implementation of IsSupportedByStorage(). This implementation is
// templated on several different options that you can specify.
enum class AfDriverKioskConfig {
  kNoKiosk,    // Check that there are no kiosk factors.
  kOnlyKiosk,  // Check that there are only kiosk factors (or no factors).
};
enum class AfDriverStorageConfig {
  kNoChecks,  // Don't do any checks for storage types.
  kUsingUss,  // Check that there are USS storage types.
};
template <AfDriverStorageConfig kStorageConfig,
          AfDriverKioskConfig kKioskConfig>
class AfDriverSupportedByStorage : public virtual AuthFactorDriver {
 private:
  bool IsSupportedByStorage(
      const std::set<AuthFactorStorageType>& configured_storage_types,
      const std::set<AuthFactorType>& configured_factors) const final {
    switch (kStorageConfig) {
      case AfDriverStorageConfig::kNoChecks:
        break;
      case AfDriverStorageConfig::kUsingUss:
        if (configured_storage_types.count(
                AuthFactorStorageType::kUserSecretStash) == 0) {
          return false;
        }
        break;
    }
    switch (kKioskConfig) {
      case AfDriverKioskConfig::kNoKiosk:
        if (configured_factors.count(AuthFactorType::kKiosk) > 0) {
          return false;
        }
        break;
      case AfDriverKioskConfig::kOnlyKiosk:
        if (configured_factors.count(AuthFactorType::kKiosk) !=
            configured_factors.size()) {
          return false;
        }
        break;
    }
    return true;
  }
};

// Common implementation of ConvertToProto(). This implementation is templated
// on the variant type from AuthFactorMetadata::metadata that the driver
// requires.
template <typename MetadataType>
class AfDriverWithMetadata : public virtual AuthFactorDriver {
  std::optional<user_data_auth::AuthFactor> ConvertToProto(
      const std::string& label,
      const AuthFactorMetadata& metadata) const final {
    // Extract the factor-specific metadata and do the typed conversion.
    auto* typed_metadata = std::get_if<MetadataType>(&metadata.metadata);
    if (!typed_metadata) {
      LOG(ERROR)
          << "Cannot convert auth factor to proto, metadata has the wrong type";
      return std::nullopt;
    }
    std::optional<user_data_auth::AuthFactor> proto_factor =
        TypedConvertToProto(metadata.common, *typed_metadata);
    if (!proto_factor) {
      LOG(ERROR) << "Cannot convert auth factor to proto, type-specific "
                    "conversion failed";
      return std::nullopt;
    }
    // If we get here we were able to populate the proto with all of the
    // factor-specific data so now just fillin the common metadata and the
    // label.
    if (proto_factor->common_metadata().lockout_policy() ==
        user_data_auth::LOCKOUT_POLICY_UNKNOWN) {
      proto_factor->mutable_common_metadata()->set_lockout_policy(
          user_data_auth::LOCKOUT_POLICY_NONE);
    }
    proto_factor->set_label(label);
    proto_factor->mutable_common_metadata()->set_chromeos_version_last_updated(
        metadata.common.chromeos_version_last_updated);
    proto_factor->mutable_common_metadata()->set_chrome_version_last_updated(
        metadata.common.chrome_version_last_updated);
    return proto_factor;
  }

  // Type-specific implementation of ConvertToProto that subclasses must
  // implement. Will be called by ConvertToProto if if the given metadata
  // contains the correct type-specific metadata.
  virtual std::optional<user_data_auth::AuthFactor> TypedConvertToProto(
      const auth_factor::CommonMetadata& common,
      const MetadataType& typed_metadata) const = 0;
};

// Common implementation of the prepare functions for drivers which do not
// support prepare.
class AfDriverNoPrepare : public virtual AuthFactorDriver {
 private:
  bool IsPrepareRequired() const final { return false; }
  void PrepareForAdd(const ObfuscatedUsername& username,
                     PreparedAuthFactorToken::Consumer callback) final;
  void PrepareForAuthenticate(const ObfuscatedUsername& username,
                              PreparedAuthFactorToken::Consumer callback) final;
};

// Common implementations for full authentication support:
//   AfDriverFullAuthDecrypt: Supports full auth for all intents
//   AfDriverFullAuthUnsupported: Does not support full authentication
class AfDriverFullAuthDecrypt : public virtual AuthFactorDriver {
 private:
  bool IsFullAuthAllowed(AuthIntent auth_intent) const final;
};
class AfDriverFullAuthUnsupported : public virtual AuthFactorDriver {
 private:
  bool IsFullAuthAllowed(AuthIntent auth_intent) const final;
};

// Common implementation of the verifier functions for drivers which do not
// support verifiers.
class AfDriverNoCredentialVerifier : public virtual AuthFactorDriver {
 private:
  bool IsLightAuthAllowed(AuthIntent auth_intent) const final { return false; }
  std::unique_ptr<CredentialVerifier> CreateCredentialVerifier(
      const std::string& auth_factor_label,
      const AuthInput& auth_input) const final {
    return nullptr;
  }
};

// Common implementation of the delay functions for drivers which do not
// support delayed availability.
class AfDriverNoDelay : public virtual AuthFactorDriver {
 private:
  bool IsDelaySupported() const final { return false; }
  CryptohomeStatusOr<base::TimeDelta> GetFactorDelay(
      const ObfuscatedUsername& username, const AuthFactor& factor) const final;
};

// Common implementation of the expiration functions for drivers which do not
// support availability expiration.
class AfDriverNoExpiration : public virtual AuthFactorDriver {
 private:
  bool IsExpirationSupported() const final { return false; }
  CryptohomeStatusOr<bool> IsExpired(const ObfuscatedUsername& username,
                                     const AuthFactor& factor) final;
};

}  // namespace cryptohome

#endif  // CRYPTOHOME_AUTH_FACTOR_TYPES_COMMON_H_
