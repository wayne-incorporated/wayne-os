// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/auth_factor/auth_factor_map.h"

#include <optional>
#include <string>
#include <utility>

#include "cryptohome/auth_factor/auth_factor.h"
#include "cryptohome/auth_factor/auth_factor_storage_type.h"
#include "cryptohome/cryptohome_metrics.h"

namespace cryptohome {

void AuthFactorMap::Add(std::unique_ptr<AuthFactor> auth_factor,
                        AuthFactorStorageType storage_type) {
  std::string label = auth_factor->label();
  storage_[std::move(label)] = {.auth_factor = std::move(auth_factor),
                                .storage_type = storage_type};
}

void AuthFactorMap::Remove(const std::string& label) {
  storage_.erase(label);
}

bool AuthFactorMap::HasFactorWithStorage(
    AuthFactorStorageType storage_type) const {
  for (const auto& [unused, value] : storage_) {
    if (value.storage_type == storage_type) {
      return true;
    }
  }
  return false;
}

std::optional<AuthFactorMap::ValueView> AuthFactorMap::Find(
    const std::string& label) const {
  auto iter = storage_.find(label);
  if (iter == storage_.end()) {
    return std::nullopt;
  }
  return ValueView(&iter->second);
}

void AuthFactorMap::ReportAuthFactorBackingStoreMetrics() const {
  bool using_vk = false, using_uss = false;
  for (const auto& [unused, stored_auth_factor] : storage_) {
    switch (stored_auth_factor.storage_type) {
      case AuthFactorStorageType::kVaultKeyset:
        using_vk = true;
        break;
      case AuthFactorStorageType::kUserSecretStash:
        using_uss = true;
        break;
    }
  }
  if (using_vk && using_uss) {
    ReportAuthFactorBackingStoreConfig(AuthFactorBackingStoreConfig::kMixed);
  } else if (using_uss) {
    ReportAuthFactorBackingStoreConfig(
        AuthFactorBackingStoreConfig::kUserSecretStash);
  } else if (using_vk) {
    ReportAuthFactorBackingStoreConfig(
        AuthFactorBackingStoreConfig::kVaultKeyset);
  } else {
    ReportAuthFactorBackingStoreConfig(AuthFactorBackingStoreConfig::kEmpty);
  }
}

}  // namespace cryptohome
