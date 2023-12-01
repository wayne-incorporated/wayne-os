// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/auth_factor/types/manager.h"

#include <memory>
#include <utility>

#include <base/check_op.h>

#include "cryptohome/auth_factor/auth_factor_type.h"
#include "cryptohome/auth_factor/types/cryptohome_recovery.h"
#include "cryptohome/auth_factor/types/fingerprint.h"
#include "cryptohome/auth_factor/types/kiosk.h"
#include "cryptohome/auth_factor/types/legacy_fingerprint.h"
#include "cryptohome/auth_factor/types/null.h"
#include "cryptohome/auth_factor/types/password.h"
#include "cryptohome/auth_factor/types/pin.h"
#include "cryptohome/auth_factor/types/smart_card.h"
#include "cryptohome/platform.h"
#include "cryptohome/user_secret_stash/user_metadata.h"

namespace cryptohome {
namespace {

// Construct a new driver instance for the given type.
std::unique_ptr<AuthFactorDriver> CreateDriver(
    AuthFactorType auth_factor_type,
    Platform* platform,
    Crypto* crypto,
    AsyncInitPtr<ChallengeCredentialsHelper> challenge_credentials_helper,
    KeyChallengeServiceFactory* key_challenge_service_factory,
    FingerprintAuthBlockService* fp_service,
    AsyncInitPtr<BiometricsAuthBlockService> bio_service,
    UserMetadataReader* user_metadata_reader) {
  // This is written using a switch to force full enum coverage.
  switch (auth_factor_type) {
    case AuthFactorType::kPassword:
      return std::make_unique<PasswordAuthFactorDriver>();
    case AuthFactorType::kPin:
      return std::make_unique<PinAuthFactorDriver>(crypto);
    case AuthFactorType::kCryptohomeRecovery:
      return std::make_unique<CryptohomeRecoveryAuthFactorDriver>(crypto);
    case AuthFactorType::kKiosk:
      return std::make_unique<KioskAuthFactorDriver>();
    case AuthFactorType::kSmartCard:
      return std::make_unique<SmartCardAuthFactorDriver>(
          crypto, challenge_credentials_helper, key_challenge_service_factory);
    case AuthFactorType::kLegacyFingerprint:
      return std::make_unique<LegacyFingerprintAuthFactorDriver>(fp_service);
    case AuthFactorType::kFingerprint:
      return std::make_unique<FingerprintAuthFactorDriver>(
          platform, crypto, bio_service, user_metadata_reader);
    case AuthFactorType::kUnspecified:
      return nullptr;
  }
}

// Construct a map of drivers for all types.
std::unordered_map<AuthFactorType, std::unique_ptr<AuthFactorDriver>>
CreateDriverMap(
    Platform* platform,
    Crypto* crypto,
    AsyncInitPtr<ChallengeCredentialsHelper> challenge_credentials_helper,
    KeyChallengeServiceFactory* key_challenge_service_factory,
    FingerprintAuthBlockService* fp_service,
    AsyncInitPtr<BiometricsAuthBlockService> bio_service,
    UserMetadataReader* user_metadata_reader) {
  std::unordered_map<AuthFactorType, std::unique_ptr<AuthFactorDriver>>
      driver_map;
  for (AuthFactorType auth_factor_type : {
           AuthFactorType::kPassword,
           AuthFactorType::kPin,
           AuthFactorType::kCryptohomeRecovery,
           AuthFactorType::kKiosk,
           AuthFactorType::kSmartCard,
           AuthFactorType::kLegacyFingerprint,
           AuthFactorType::kFingerprint,
       }) {
    auto driver = CreateDriver(auth_factor_type, platform, crypto,
                               challenge_credentials_helper,
                               key_challenge_service_factory, fp_service,
                               bio_service, user_metadata_reader);
    CHECK_NE(driver.get(), nullptr);
    driver_map[auth_factor_type] = std::move(driver);
  }
  return driver_map;
}

}  // namespace

AuthFactorDriverManager::AuthFactorDriverManager(
    Platform* platform,
    Crypto* crypto,
    AsyncInitPtr<ChallengeCredentialsHelper> challenge_credentials_helper,
    KeyChallengeServiceFactory* key_challenge_service_factory,
    FingerprintAuthBlockService* fp_service,
    AsyncInitPtr<BiometricsAuthBlockService> bio_service,
    UserMetadataReader* user_metadata_reader)
    : null_driver_(std::make_unique<NullAuthFactorDriver>()),
      driver_map_(CreateDriverMap(platform,
                                  crypto,
                                  challenge_credentials_helper,
                                  key_challenge_service_factory,
                                  fp_service,
                                  bio_service,
                                  user_metadata_reader)) {}

AuthFactorDriver& AuthFactorDriverManager::GetDriver(
    AuthFactorType auth_factor_type) {
  auto iter = driver_map_.find(auth_factor_type);
  if (iter != driver_map_.end()) {
    return *iter->second;
  }
  return *null_driver_;
}

const AuthFactorDriver& AuthFactorDriverManager::GetDriver(
    AuthFactorType auth_factor_type) const {
  auto iter = driver_map_.find(auth_factor_type);
  if (iter != driver_map_.end()) {
    return *iter->second;
  }
  return *null_driver_;
}

}  // namespace cryptohome
