// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHAPS_OBJECT_POLICY_H_
#define CHAPS_OBJECT_POLICY_H_

#include <string>

#include "pkcs11/cryptoki.h"

namespace chaps {

class Object;

// ObjectPolicy encapsulates policies for a PKCS #11 object.
class ObjectPolicy {
 public:
  virtual ~ObjectPolicy() {}
  virtual void Init(Object* object) = 0;
  virtual bool IsReadAllowed(CK_ATTRIBUTE_TYPE type) = 0;
  virtual bool IsModifyAllowed(CK_ATTRIBUTE_TYPE type,
                               const std::string& value) = 0;
  virtual bool IsObjectComplete() = 0;
  virtual void SetDefaultAttributes() = 0;
};

}  // namespace chaps

#endif  // CHAPS_OBJECT_POLICY_H_
