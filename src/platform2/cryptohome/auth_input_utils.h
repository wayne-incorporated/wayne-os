// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_AUTH_INPUT_UTILS_H_
#define CRYPTOHOME_AUTH_INPUT_UTILS_H_

#include <optional>
#include <string>

#include <brillo/secure_blob.h>
#include <cryptohome/proto_bindings/auth_factor.pb.h>

#include "cryptohome/auth_factor/auth_factor_metadata.h"
#include "cryptohome/auth_factor/auth_factor_type.h"
#include "cryptohome/key_objects.h"
#include "cryptohome/platform.h"
#include "cryptohome/username.h"

namespace cryptohome {

// Converts the AuthInput D-Bus proto into the cryptohome struct.
std::optional<AuthInput> CreateAuthInput(
    Platform* platform,
    const user_data_auth::AuthInput& auth_input_proto,
    const Username& username,
    const ObfuscatedUsername& obfuscated_username,
    bool locked_to_single_user,
    const std::optional<brillo::SecureBlob>&
        cryptohome_recovery_ephemeral_pub_key,
    const AuthFactorMetadata& auth_factor_metadata);

// Infers the `AuthFactorType` that the given `AuthInput` should be used with.
// Returns `nullopt` un unexpected inputs.
std::optional<AuthFactorType> DetermineFactorTypeFromAuthInput(
    const user_data_auth::AuthInput& auth_input_proto);

}  // namespace cryptohome

#endif  // CRYPTOHOME_AUTH_INPUT_UTILS_H_
