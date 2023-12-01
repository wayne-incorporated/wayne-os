// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/auth_factor/flatbuffer.h"

#include "cryptohome/auth_factor/auth_factor_type.h"
#include "cryptohome/flatbuffer_schemas/enumerations.h"

namespace cryptohome {

std::optional<enumeration::SerializedAuthFactorType> SerializeAuthFactorType(
    AuthFactorType type) {
  switch (type) {
    case AuthFactorType::kPassword:
      return enumeration::SerializedAuthFactorType::kPassword;
    case AuthFactorType::kPin:
      return enumeration::SerializedAuthFactorType::kPin;
    case AuthFactorType::kCryptohomeRecovery:
      return enumeration::SerializedAuthFactorType::kCryptohomeRecovery;
    case AuthFactorType::kKiosk:
      return enumeration::SerializedAuthFactorType::kKiosk;
    case AuthFactorType::kSmartCard:
      return enumeration::SerializedAuthFactorType::kSmartCard;
    case AuthFactorType::kLegacyFingerprint:
      return enumeration::SerializedAuthFactorType::kLegacyFingerprint;
    case AuthFactorType::kFingerprint:
      return enumeration::SerializedAuthFactorType::kFingerprint;
    case AuthFactorType::kUnspecified:
      return std::nullopt;
  }
}

AuthFactorType DeserializeAuthFactorType(
    enumeration::SerializedAuthFactorType type) {
  switch (type) {
    case enumeration::SerializedAuthFactorType::kPassword:
      return AuthFactorType::kPassword;
    case enumeration::SerializedAuthFactorType::kPin:
      return AuthFactorType::kPin;
    case enumeration::SerializedAuthFactorType::kCryptohomeRecovery:
      return AuthFactorType::kCryptohomeRecovery;
    case enumeration::SerializedAuthFactorType::kKiosk:
      return AuthFactorType::kKiosk;
    case enumeration::SerializedAuthFactorType::kSmartCard:
      return AuthFactorType::kSmartCard;
    case enumeration::SerializedAuthFactorType::kLegacyFingerprint:
      return AuthFactorType::kLegacyFingerprint;
    case enumeration::SerializedAuthFactorType::kFingerprint:
      return AuthFactorType::kFingerprint;
  }
}

}  // namespace cryptohome
