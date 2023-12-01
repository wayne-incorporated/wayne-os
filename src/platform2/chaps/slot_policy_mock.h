// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHAPS_SLOT_POLICY_MOCK_H_
#define CHAPS_SLOT_POLICY_MOCK_H_

#include "chaps/slot_policy.h"

#include <string>

#include <gmock/gmock.h>

namespace chaps {

class SlotPolicyMock : public SlotPolicy {
 public:
  SlotPolicyMock();
  ~SlotPolicyMock() override;
  MOCK_METHOD1(IsObjectClassAllowedForNewObject, bool(CK_OBJECT_CLASS));
  MOCK_METHOD1(IsObjectClassAllowedForImportedObject, bool(CK_OBJECT_CLASS));
};

}  // namespace chaps

#endif  // CHAPS_SLOT_POLICY_MOCK_H_
