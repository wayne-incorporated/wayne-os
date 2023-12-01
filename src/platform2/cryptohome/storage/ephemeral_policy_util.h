// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_STORAGE_EPHEMERAL_POLICY_UTIL_H_
#define CRYPTOHOME_STORAGE_EPHEMERAL_POLICY_UTIL_H_

#include <set>

#include <policy/device_policy.h>

#include "cryptohome/username.h"

namespace cryptohome {

// This utility class is constructed using device policy ephemeral settings.
// It can be used to check if a username should be removed based on the
// ephemeral policies.
class EphemeralPolicyUtil {
 public:
  EphemeralPolicyUtil() = delete;
  explicit EphemeralPolicyUtil(
      const policy::DevicePolicy::EphemeralSettings& settings);
  EphemeralPolicyUtil(const EphemeralPolicyUtil&) = delete;
  EphemeralPolicyUtil& operator=(const EphemeralPolicyUtil&) = delete;
  ~EphemeralPolicyUtil() = default;

  // Returns true when the global ephemeral users policy is true and the
  // username is not specifically non-ephemeral, or if the global ephemeral
  // users policy is false and the username is specifically ephemeral.
  bool ShouldRemoveBasedOnPolicy(const ObfuscatedUsername& username) const;

 private:
  bool global_ephemeral_users_enabled_ = false;

  // The set contains usernames that are always ephemeral, regardless of the
  // global ephemeral users policy.
  std::set<ObfuscatedUsername> specific_ephemeral_obfuscated_usernames_;

  // The set contains usernames that are not ephemeral and override the global
  // ephemeral users policy.
  std::set<ObfuscatedUsername> specific_nonephemeral_obfuscated_usernames_;
};
}  // namespace cryptohome

#endif  // CRYPTOHOME_STORAGE_EPHEMERAL_POLICY_UTIL_H_
