// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHAPS_OBJECT_POLICY_PUBLIC_KEY_H_
#define CHAPS_OBJECT_POLICY_PUBLIC_KEY_H_

#include "chaps/object_policy_key.h"

namespace chaps {

// Enforces common policies for public key objects (CKO_PUBLIC_KEY).
class ObjectPolicyPublicKey : public ObjectPolicyKey {
 public:
  ObjectPolicyPublicKey();
  ~ObjectPolicyPublicKey() override;
  bool IsObjectComplete() override;
  void SetDefaultAttributes() override;
};

}  // namespace chaps

#endif  // CHAPS_OBJECT_POLICY_PUBLIC_KEY_H_
