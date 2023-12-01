// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/storage/ephemeral_policy_util.h"

#include <brillo/cryptohome.h>
#include <gtest/gtest.h>

#include <string>

namespace cryptohome {

// When the global ephemeral user policy is not set, and there are no ephemeral
// or non-ephemeral users, we should never remove users based on policy.
TEST(EphemeralPolicyUtilTest,
     ShouldRemoveBasedOnPolicy_Global_Ephemeral_User_Settings_False) {
  std::string user = "6b696f736b5f617070@kiosk-apps.device-local.localhost";
  Username username(user);
  ObfuscatedUsername obfuscated =
      brillo::cryptohome::home::SanitizeUserName(username);
  policy::DevicePolicy::EphemeralSettings settings;
  settings.global_ephemeral_users_enabled = false;
  EphemeralPolicyUtil util(settings);

  EXPECT_FALSE(util.ShouldRemoveBasedOnPolicy(obfuscated));
}

// When the global ephemeral user policy is set, and there are no ephemeral
// or non-ephemeral users, we should always remove users based on policy.
TEST(EphemeralPolicyUtilTest,
     ShouldRemoveBasedOnPolicy_Global_Ephemeral_User_Settings_True) {
  std::string user = "6b696f736b5f617070@kiosk-apps.device-local.localhost";
  Username username(user);
  ObfuscatedUsername obfuscated =
      brillo::cryptohome::home::SanitizeUserName(username);
  policy::DevicePolicy::EphemeralSettings settings;
  settings.global_ephemeral_users_enabled = true;
  EphemeralPolicyUtil util(settings);

  EXPECT_TRUE(util.ShouldRemoveBasedOnPolicy(obfuscated));
}

// When the global ephemeral user policy is not set, but ephemeral users exist,
// these users should be removed in accordance with the policy.
TEST(EphemeralPolicyUtilTest,
     ShouldRemoveBasedOnPolicy_Specific_Ephemeral_User) {
  std::string user = "6b696f736b5f617070@kiosk-apps.device-local.localhost";
  Username username(user);
  ObfuscatedUsername obfuscated =
      brillo::cryptohome::home::SanitizeUserName(username);
  policy::DevicePolicy::EphemeralSettings settings;
  settings.global_ephemeral_users_enabled = false;
  settings.specific_ephemeral_users.push_back(user);
  EphemeralPolicyUtil util(settings);

  EXPECT_TRUE(util.ShouldRemoveBasedOnPolicy(obfuscated));
}

// When the global ephemeral user policy is set, but non-ephemeral users exist,
// these users shouldn't be removed in accordance with the policy.
TEST(EphemeralPolicyUtilTest,
     ShouldRemoveBasedOnPolicy_Specific_NonEphemeral_User) {
  std::string user = "6b696f736b5f617070@kiosk-apps.device-local.localhost";
  Username username(user);
  ObfuscatedUsername obfuscated =
      brillo::cryptohome::home::SanitizeUserName(username);
  policy::DevicePolicy::EphemeralSettings settings;
  settings.global_ephemeral_users_enabled = true;
  settings.specific_nonephemeral_users.push_back(user);
  EphemeralPolicyUtil util(settings);

  EXPECT_FALSE(util.ShouldRemoveBasedOnPolicy(obfuscated));
}

}  // namespace cryptohome
