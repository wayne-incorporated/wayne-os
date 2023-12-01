// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHAPS_OBJECT_POLICY_KEY_H_
#define CHAPS_OBJECT_POLICY_KEY_H_

#include "chaps/object_policy_common.h"

namespace chaps {

// Enforces common policies for key objects.
class ObjectPolicyKey : public ObjectPolicyCommon {
 public:
  ObjectPolicyKey();
  ~ObjectPolicyKey() override;
  void SetDefaultAttributes() override;
};

}  // namespace chaps

#endif  // CHAPS_OBJECT_POLICY_KEY_H_
