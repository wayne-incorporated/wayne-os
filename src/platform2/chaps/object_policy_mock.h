// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHAPS_OBJECT_POLICY_MOCK_H_
#define CHAPS_OBJECT_POLICY_MOCK_H_

#include "chaps/object_policy.h"

#include <string>

#include <gmock/gmock.h>

namespace chaps {

class ObjectPolicyMock : public ObjectPolicy {
 public:
  ObjectPolicyMock();
  ~ObjectPolicyMock() override;
  MOCK_METHOD1(Init, void(Object* object));
  MOCK_METHOD1(IsReadAllowed, bool(CK_ATTRIBUTE_TYPE type));
  MOCK_METHOD2(IsModifyAllowed,
               bool(CK_ATTRIBUTE_TYPE type, const std::string& value));
  MOCK_METHOD0(IsObjectComplete, bool());
  MOCK_METHOD0(SetDefaultAttributes, void());
};

}  // namespace chaps

#endif  // CHAPS_OBJECT_POLICY_MOCK_H_
