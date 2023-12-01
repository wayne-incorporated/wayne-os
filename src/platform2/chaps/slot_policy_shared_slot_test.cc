// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chaps/slot_policy_shared_slot.h"

#include <memory>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "pkcs11/cryptoki.h"

namespace chaps {
namespace {

using SlotPolicySharedSlotTest = testing::Test;

TEST_F(SlotPolicySharedSlotTest, AcceptsRegularObjects) {
  SlotPolicySharedSlot slot_policy_shared_slot;
  EXPECT_TRUE(slot_policy_shared_slot.IsObjectClassAllowedForNewObject(
      CKO_CERTIFICATE));
  EXPECT_TRUE(slot_policy_shared_slot.IsObjectClassAllowedForImportedObject(
      CKO_CERTIFICATE));
}

TEST_F(SlotPolicySharedSlotTest, RejectsNssTrustObjects) {
  SlotPolicySharedSlot slot_policy_shared_slot;
  EXPECT_FALSE(
      slot_policy_shared_slot.IsObjectClassAllowedForNewObject(CKO_NSS_TRUST));
  EXPECT_FALSE(slot_policy_shared_slot.IsObjectClassAllowedForImportedObject(
      CKO_NSS_TRUST));
}

}  // namespace
}  // namespace chaps
