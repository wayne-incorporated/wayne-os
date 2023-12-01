// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chaps/slot_policy_shared_slot.h"

namespace chaps {

SlotPolicySharedSlot::SlotPolicySharedSlot() = default;

SlotPolicySharedSlot::~SlotPolicySharedSlot() = default;

bool SlotPolicySharedSlot::IsObjectClassAllowedForNewObject(
    CK_OBJECT_CLASS object_class) {
  // Disallow creating new NSS trust objects in shared slots
  // (https://crbug.com/1132030).
  if (object_class == CKO_NSS_TRUST) {
    return false;
  }
  return true;
}

bool SlotPolicySharedSlot::IsObjectClassAllowedForImportedObject(
    CK_OBJECT_CLASS object_class) {
  // Disallow importing existing NSS trust objects in shared slots
  // (https://crbug.com/1132030).
  if (object_class == CKO_NSS_TRUST) {
    return false;
  }
  return true;
}

}  // namespace chaps
