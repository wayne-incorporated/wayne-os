// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHAPS_SLOT_POLICY_DEFAULT_H_
#define CHAPS_SLOT_POLICY_DEFAULT_H_

#include "chaps/slot_policy.h"

namespace chaps {

class SlotPolicyDefault : public SlotPolicy {
 public:
  SlotPolicyDefault();
  ~SlotPolicyDefault() override;

  bool IsObjectClassAllowedForNewObject(CK_OBJECT_CLASS object_class) override;
  bool IsObjectClassAllowedForImportedObject(
      CK_OBJECT_CLASS object_class) override;
};

}  // namespace chaps

#endif  // CHAPS_SLOT_POLICY_DEFAULT_H_
