// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_AUTH_FACTOR_AUTH_FACTOR_STORAGE_TYPE_H_
#define CRYPTOHOME_AUTH_FACTOR_AUTH_FACTOR_STORAGE_TYPE_H_

namespace cryptohome {

enum class AuthFactorStorageType {
  kVaultKeyset,
  kUserSecretStash,
};

const char* AuthFactorStorageTypeToDebugString(
    AuthFactorStorageType storage_type);

}  // namespace cryptohome

#endif  // CRYPTOHOME_AUTH_FACTOR_AUTH_FACTOR_STORAGE_TYPE_H_
