// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHAPS_OBJECT_POLICY_SECRET_KEY_H_
#define CHAPS_OBJECT_POLICY_SECRET_KEY_H_

#include "chaps/object_policy_key.h"

namespace chaps {

// Enforces common policies for private key objects (CKO_SECRET_KEY).
class ObjectPolicySecretKey : public ObjectPolicyKey {
 public:
  ObjectPolicySecretKey();
  ~ObjectPolicySecretKey() override;
  void SetDefaultAttributes() override;
};

}  // namespace chaps

#endif  // CHAPS_OBJECT_POLICY_SECRET_KEY_H_
