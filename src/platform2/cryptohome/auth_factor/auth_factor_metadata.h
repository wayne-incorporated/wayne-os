// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_AUTH_FACTOR_AUTH_FACTOR_METADATA_H_
#define CRYPTOHOME_AUTH_FACTOR_AUTH_FACTOR_METADATA_H_

#include <optional>
#include <string>
#include <variant>

#include <brillo/cryptohome.h>
#include <libhwsec/structures/explicit_init.h>

#include "cryptohome/flatbuffer_schemas/auth_factor.h"

namespace cryptohome {

struct AuthFactorMetadata {
  auth_factor::CommonMetadata common;

  // Use `std::monostate` as the first alternative, in order to make the
  // default constructor create an empty metadata.
  std::variant<std::monostate,
               auth_factor::PasswordMetadata,
               auth_factor::PinMetadata,
               auth_factor::CryptohomeRecoveryMetadata,
               auth_factor::KioskMetadata,
               auth_factor::SmartCardMetadata,
               auth_factor::FingerprintMetadata>
      metadata;
};

}  // namespace cryptohome

#endif  // CRYPTOHOME_AUTH_FACTOR_AUTH_FACTOR_METADATA_H_
