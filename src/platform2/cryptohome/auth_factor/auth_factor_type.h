// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_AUTH_FACTOR_AUTH_FACTOR_TYPE_H_
#define CRYPTOHOME_AUTH_FACTOR_AUTH_FACTOR_TYPE_H_

#include <optional>
#include <string>

namespace cryptohome {

enum class AuthFactorType {
  kPassword,
  kPin,
  kCryptohomeRecovery,
  kKiosk,
  kSmartCard,
  kLegacyFingerprint,
  kFingerprint,
  kUnspecified,
};

// Converts the auth factor type enum to a string into an enum. Returns an empty
// string if the type is unknown.
std::string AuthFactorTypeToString(AuthFactorType type);

// Converts the auth factor type enum to a string into an enum. Returns an empty
// string if the type is unknown.
std::string AuthFactorTypeToCamelCaseString(AuthFactorType type);

// Converts the auth factor type string into an enum. Returns a null optional
// if the string is unknown.
std::optional<AuthFactorType> AuthFactorTypeFromString(
    const std::string& type_string);

}  // namespace cryptohome

#endif  // CRYPTOHOME_AUTH_FACTOR_AUTH_FACTOR_TYPE_H_
