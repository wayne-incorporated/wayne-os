// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/storage/ephemeral_policy_util.h"

#include <string>

#include <base/containers/contains.h>
#include <brillo/cryptohome.h>

namespace cryptohome {

// Convert all users, both ephemeral and non-ephemeral, from ephemeral settings
// to obfuscated usernames.
EphemeralPolicyUtil::EphemeralPolicyUtil(
    const policy::DevicePolicy::EphemeralSettings& settings)
    : global_ephemeral_users_enabled_(settings.global_ephemeral_users_enabled) {
  for (const std::string& user : settings.specific_ephemeral_users) {
    specific_ephemeral_obfuscated_usernames_.insert(
        SanitizeUserName(Username(user)));
  }

  for (const std::string& user : settings.specific_nonephemeral_users) {
    specific_nonephemeral_obfuscated_usernames_.insert(
        SanitizeUserName(Username(user)));
  }
}

bool EphemeralPolicyUtil::ShouldRemoveBasedOnPolicy(
    const ObfuscatedUsername& username) const {
  // If global ephemeral users policy is enabled, every username that is
  // not specifically non-ephemeral should be removed.
  if (global_ephemeral_users_enabled_) {
    return !base::Contains(specific_nonephemeral_obfuscated_usernames_,
                           username);
  }

  // If global ephemeral users policy is not enabled, every username that is
  // specifically ephemeral should be removed.
  return base::Contains(specific_ephemeral_obfuscated_usernames_, username);
}

}  // namespace cryptohome
