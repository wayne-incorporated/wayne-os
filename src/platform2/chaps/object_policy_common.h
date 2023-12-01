// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHAPS_OBJECT_POLICY_COMMON_H_
#define CHAPS_OBJECT_POLICY_COMMON_H_

#include "chaps/object_policy.h"

#include <map>
#include <string>

#include "chaps/object.h"

namespace chaps {

struct AttributePolicy {
  CK_ATTRIBUTE_TYPE type_;
  bool is_sensitive_;
  bool is_readonly_[kNumObjectStages];
  bool is_required_;
};

// Enforces policies that are common to all object types.
class ObjectPolicyCommon : public ObjectPolicy {
 public:
  ObjectPolicyCommon();
  ~ObjectPolicyCommon() override;
  void Init(Object* object) override;
  bool IsReadAllowed(CK_ATTRIBUTE_TYPE type) override;
  bool IsModifyAllowed(CK_ATTRIBUTE_TYPE type,
                       const std::string& value) override;
  bool IsObjectComplete() override;
  void SetDefaultAttributes() override;

 protected:
  Object* object_;  // The object this policy is associated with.
  std::map<CK_ATTRIBUTE_TYPE, AttributePolicy> policies_;
  // Helps sub-classes add more policies.
  void AddPolicies(const AttributePolicy* policies, int size);
  // Determines whether the object is private based on object class.
  bool IsPrivateClass();
};

}  // namespace chaps

#endif  // CHAPS_OBJECT_POLICY_COMMON_H_
