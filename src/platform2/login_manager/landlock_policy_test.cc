// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "login_manager/landlock_policy.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <base/containers/contains.h>

#include <libminijail.h>
#include <scoped_minijail.h>

namespace login_manager {
namespace {

TEST(LandlockPolicyTest, BasicPathsAllowlisted) {
  login_manager::LandlockPolicy fs_policy;
  auto policy_snapshot = fs_policy.GetPolicySnapshotForTesting();

  // Test that we have paths vital to Chrome's operations.
  EXPECT_TRUE(base::Contains(policy_snapshot, "/home/chronos"));
  EXPECT_TRUE(base::Contains(policy_snapshot, "/home/user"));
  EXPECT_TRUE(base::Contains(policy_snapshot, "/tmp"));
  // Test that we do not include overly broad paths.
  EXPECT_FALSE(base::Contains(policy_snapshot, "/"));
  EXPECT_FALSE(base::Contains(policy_snapshot, "/home"));
  EXPECT_FALSE(base::Contains(policy_snapshot, "/home/root"));
}

TEST(LandlockPolicyTest, MinijailConfigured) {
  login_manager::LandlockPolicy fs_policy;
  const ScopedMinijail j(minijail_new());
  EXPECT_FALSE(minijail_is_fs_restriction_ruleset_initialized(j.get()));

  fs_policy.SetupPolicy(j.get());

  if (minijail_is_fs_restriction_available()) {
    EXPECT_TRUE(minijail_is_fs_restriction_ruleset_initialized(j.get()));
  }
}

}  // namespace
}  // namespace login_manager
