// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHAPS_SLOT_POLICY_H_
#define CHAPS_SLOT_POLICY_H_

#include <string>

#include "pkcs11/cryptoki.h"

namespace chaps {

class Object;

// SlotPolicy encapsulates policies for a PKCS #11 token.
class SlotPolicy {
 public:
  virtual ~SlotPolicy() = default;
  virtual bool IsObjectClassAllowedForNewObject(
      CK_OBJECT_CLASS object_class) = 0;
  virtual bool IsObjectClassAllowedForImportedObject(
      CK_OBJECT_CLASS object_class) = 0;
};

}  // namespace chaps

#endif  // CHAPS_SLOT_POLICY_H_
