// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "debugd/src/dev_mode_no_owner_restriction.h"

#include <gtest/gtest.h>

namespace debugd {

namespace {

// Test class to fake different system state conditions.
class FakeDevModeNoOwnerRestriction : public DevModeNoOwnerRestriction {
 public:
  FakeDevModeNoOwnerRestriction()
      : DevModeNoOwnerRestriction(nullptr),
        fake_boot_lockbox_finalized_(false),
        fake_cryptohome_access_(false),
        fake_in_dev_mode_(false),
        fake_owner_user_exists_(false) {}

  ~FakeDevModeNoOwnerRestriction() override = default;

  // Functions to set the fake system state.
  void set_fake_boot_lockbox_finalized(bool fake_boot_lockbox_finalized) {
    fake_boot_lockbox_finalized_ = fake_boot_lockbox_finalized;
  }
  void set_fake_cryptohome_access(bool fake_cryptohome_access) {
    fake_cryptohome_access_ = fake_cryptohome_access;
  }
  void set_fake_in_dev_mode_(bool fake_in_dev_mode) {
    fake_in_dev_mode_ = fake_in_dev_mode;
  }
  void set_fake_owner_user_exists(bool fake_owner_user_exists) {
    fake_owner_user_exists_ = fake_owner_user_exists;
  }

 private:
  bool fake_boot_lockbox_finalized_;
  bool fake_cryptohome_access_;
  bool fake_in_dev_mode_;
  bool fake_owner_user_exists_;

  // Reports the fake dev mode state.
  bool InDevMode(brillo::ErrorPtr* error) const override {
    return fake_in_dev_mode_;
  }

  // Reports the fake owner and lockbox states.
  bool GetOwnerAndLockboxStatus(bool* owner_user_exists,
                                bool* boot_lockbox_finalized) override {
    if (fake_cryptohome_access_) {
      *owner_user_exists = fake_owner_user_exists_;
      *boot_lockbox_finalized = fake_boot_lockbox_finalized_;
    }
    return fake_cryptohome_access_;
  }
};

}  // namespace

class DevModeNoOwnerRestrictionTest : public ::testing::Test {
 public:
  DevModeNoOwnerRestrictionTest() {
    // By default configure FakeDevModeNoOwnerRestriction to allow access.
    restriction_.set_fake_in_dev_mode_(true);
    restriction_.set_fake_cryptohome_access(true);
    restriction_.set_fake_boot_lockbox_finalized(false);
    restriction_.set_fake_owner_user_exists(false);
  }

  ~DevModeNoOwnerRestrictionTest() override = default;

 protected:
  FakeDevModeNoOwnerRestriction restriction_;
};

TEST_F(DevModeNoOwnerRestrictionTest, AllowUse) {
  EXPECT_TRUE(restriction_.AllowToolUse(nullptr));
}

TEST_F(DevModeNoOwnerRestrictionTest, DisallowUseNonDevmode) {
  restriction_.set_fake_in_dev_mode_(false);
  EXPECT_FALSE(restriction_.AllowToolUse(nullptr));
}

TEST_F(DevModeNoOwnerRestrictionTest, DisallowUseNoCryptohome) {
  restriction_.set_fake_cryptohome_access(false);
  EXPECT_FALSE(restriction_.AllowToolUse(nullptr));
}

TEST_F(DevModeNoOwnerRestrictionTest, DisallowUseBootLockboxFinalized) {
  restriction_.set_fake_boot_lockbox_finalized(true);
  EXPECT_FALSE(restriction_.AllowToolUse(nullptr));
}

TEST_F(DevModeNoOwnerRestrictionTest, DisallowUseOwnerExists) {
  restriction_.set_fake_owner_user_exists(true);
  EXPECT_FALSE(restriction_.AllowToolUse(nullptr));
}

}  // namespace debugd
