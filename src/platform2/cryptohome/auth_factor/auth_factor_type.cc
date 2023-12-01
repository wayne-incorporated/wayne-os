// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#include "cryptohome/auth_factor/auth_factor_type.h"

#include <optional>
#include <string>
#include <utility>

namespace cryptohome {

struct CaseRepresentation {
  const char* snake_case;
  const char* camel_case;
};

// Note: The string values in this constant must stay stable, as they're used in
// file names.
constexpr std::pair<AuthFactorType, CaseRepresentation>
    kAuthFactorTypeStrings[] = {
        {AuthFactorType::kPassword, {"password", "Password"}},
        {AuthFactorType::kPin, {"pin", "Pin"}},
        {AuthFactorType::kSmartCard, {"smart_card", "SmardCard"}},
        {AuthFactorType::kCryptohomeRecovery,
         {"cryptohome_recovery", "CryptohomeRecovery"}},
        {AuthFactorType::kLegacyFingerprint,
         {"legacy_fingerprint", "LegacyFingerprint"}},
        {AuthFactorType::kKiosk, {"kiosk", "Kiosk"}},
        {AuthFactorType::kFingerprint, {"fingerprint", "Fingerprint"}},
};

// Converts the auth factor type enum into a string.
std::string AuthFactorTypeToString(AuthFactorType type) {
  for (const auto& type_and_string : kAuthFactorTypeStrings) {
    if (type_and_string.first == type) {
      return type_and_string.second.snake_case;
    }
  }
  return std::string();
}

// Converts the auth factor type enum into a camel case string.
std::string AuthFactorTypeToCamelCaseString(AuthFactorType type) {
  for (const auto& type_and_string : kAuthFactorTypeStrings) {
    if (type_and_string.first == type) {
      return type_and_string.second.camel_case;
    }
  }
  return std::string();
}

std::optional<AuthFactorType> AuthFactorTypeFromString(
    const std::string& type_string) {
  for (const auto& type_and_string : kAuthFactorTypeStrings) {
    if (type_and_string.second.snake_case == type_string) {
      return type_and_string.first;
    }
  }
  return std::nullopt;
}

}  // namespace cryptohome
