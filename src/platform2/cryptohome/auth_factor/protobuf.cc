// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/auth_factor/protobuf.h"

namespace cryptohome {

user_data_auth::AuthFactorType AuthFactorTypeToProto(AuthFactorType type) {
  switch (type) {
    case AuthFactorType::kPassword:
      return user_data_auth::AUTH_FACTOR_TYPE_PASSWORD;
    case AuthFactorType::kPin:
      return user_data_auth::AUTH_FACTOR_TYPE_PIN;
    case AuthFactorType::kCryptohomeRecovery:
      return user_data_auth::AUTH_FACTOR_TYPE_CRYPTOHOME_RECOVERY;
    case AuthFactorType::kKiosk:
      return user_data_auth::AUTH_FACTOR_TYPE_KIOSK;
    case AuthFactorType::kSmartCard:
      return user_data_auth::AUTH_FACTOR_TYPE_SMART_CARD;
    case AuthFactorType::kLegacyFingerprint:
      return user_data_auth::AUTH_FACTOR_TYPE_LEGACY_FINGERPRINT;
    case AuthFactorType::kFingerprint:
      return user_data_auth::AUTH_FACTOR_TYPE_FINGERPRINT;
    case AuthFactorType::kUnspecified:
      return user_data_auth::AUTH_FACTOR_TYPE_UNSPECIFIED;
  }
}

std::optional<AuthFactorType> AuthFactorTypeFromProto(
    user_data_auth::AuthFactorType type) {
  switch (type) {
    case user_data_auth::AUTH_FACTOR_TYPE_UNSPECIFIED:
      return AuthFactorType::kUnspecified;
    case user_data_auth::AUTH_FACTOR_TYPE_PASSWORD:
      return AuthFactorType::kPassword;
    case user_data_auth::AUTH_FACTOR_TYPE_PIN:
      return AuthFactorType::kPin;
    case user_data_auth::AUTH_FACTOR_TYPE_CRYPTOHOME_RECOVERY:
      return AuthFactorType::kCryptohomeRecovery;
    case user_data_auth::AUTH_FACTOR_TYPE_KIOSK:
      return AuthFactorType::kKiosk;
    case user_data_auth::AUTH_FACTOR_TYPE_SMART_CARD:
      return AuthFactorType::kSmartCard;
    case user_data_auth::AUTH_FACTOR_TYPE_LEGACY_FINGERPRINT:
      return AuthFactorType::kLegacyFingerprint;
    case user_data_auth::AUTH_FACTOR_TYPE_FINGERPRINT:
      return AuthFactorType::kFingerprint;
    default:
      return std::nullopt;
  }
}

}  // namespace cryptohome
