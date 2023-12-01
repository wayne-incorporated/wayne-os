// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chaps/slot_policy_default.h"

namespace chaps {

SlotPolicyDefault::SlotPolicyDefault() = default;

SlotPolicyDefault::~SlotPolicyDefault() = default;

bool SlotPolicyDefault::IsObjectClassAllowedForNewObject(
    CK_OBJECT_CLASS object_class) {
  // Disallow creating new NSS trust objects in shared slots
  // (https://crbug.com/1132030).
  if (object_class == CKO_NSS_TRUST) {
    return false;
  }
  return true;
}

bool SlotPolicyDefault::IsObjectClassAllowedForImportedObject(
    CK_OBJECT_CLASS object_class) {
  return true;
}

}  // namespace chaps
