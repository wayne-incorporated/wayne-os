// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_USERNAME_H_
#define CRYPTOHOME_USERNAME_H_

#include <brillo/cryptohome.h>

namespace cryptohome {

// These libbrillo types are used extensively in cryptohome class definitions
// and function signatures. For brevity we define our own typenames in the
// cryptohome namespace. Code in cryptohome should favor using these aliases
// over fully qualifying the libbrillo names.
using Username = ::brillo::cryptohome::home::Username;
using ObfuscatedUsername = ::brillo::cryptohome::home::ObfuscatedUsername;

}  // namespace cryptohome

#endif  // CRYPTOHOME_USERNAME_H_
