// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/auth_factor/auth_factor_storage_type.h"

namespace cryptohome {

const char* AuthFactorStorageTypeToDebugString(
    AuthFactorStorageType storage_type) {
  switch (storage_type) {
    case AuthFactorStorageType::kVaultKeyset:
      return "vk";
    case AuthFactorStorageType::kUserSecretStash:
      return "uss";
  }
}

}  // namespace cryptohome
