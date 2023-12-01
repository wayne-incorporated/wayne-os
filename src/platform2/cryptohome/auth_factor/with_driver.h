// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This library provides common utility operations that operate on a combination
// of an AuthFactor using the driver for that factor. All of the functions in
// here generally take as parameters and AuthFactor and an AuthFactorManager and
// then use the driver to perform some complex operation.
//
// These functions should not have any type-specific logic in them; such
// behavior should go into the drivers themselves. These functions are for
// reusing common generic patterns of composing existing driver functions.

#ifndef CRYPTOHOME_AUTH_FACTOR_WITH_DRIVER_H_
#define CRYPTOHOME_AUTH_FACTOR_WITH_DRIVER_H_

#include "base/containers/flat_set.h"
#include "cryptohome/auth_factor/auth_factor.h"
#include "cryptohome/auth_factor/types/manager.h"
#include "cryptohome/auth_intent.h"

namespace cryptohome {

// Compute the set of auth intents supported by the given AuthFactor.
base::flat_set<AuthIntent> GetSupportedIntents(
    const ObfuscatedUsername& username,
    const AuthFactor& auth_factor,
    AuthFactorDriverManager& driver_manager);

}  // namespace cryptohome

#endif  // CRYPTOHOME_AUTH_FACTOR_WITH_DRIVER_H_
