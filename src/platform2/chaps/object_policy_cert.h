// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHAPS_OBJECT_POLICY_CERT_H_
#define CHAPS_OBJECT_POLICY_CERT_H_

#include "chaps/object_policy_common.h"

namespace chaps {

// Enforces policies for certificate objects (CKO_CERTIFICATE).
class ObjectPolicyCert : public ObjectPolicyCommon {
 public:
  ObjectPolicyCert();
  ~ObjectPolicyCert() override;
  bool IsObjectComplete() override;
  void SetDefaultAttributes() override;
};

}  // namespace chaps

#endif  // CHAPS_OBJECT_POLICY_CERT_H_
