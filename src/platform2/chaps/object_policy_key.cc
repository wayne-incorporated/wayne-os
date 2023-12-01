// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chaps/object_policy_key.h"

#include <iterator>

namespace chaps {

// Read policy list as follows:
//   {attribute, sensitive, read-only {create, copy, modify}, required}
// sensitive - True if attribute cannot be read.
// read-only.create - True if attribute cannot be set with C_CreateObject.
// read-only.copy - True if attribute cannot be set with C_CopyObject.
// read-only.modify - True if attribute cannot be set with C_SetAttributeValue.
// required - True if attribute is required for a valid object.
static const AttributePolicy kKeyPolicies[] = {
    {CKA_KEY_TYPE, false, {false, false, true}, true},
    {CKA_LOCAL, false, {true, true, true}, false},
    {CKA_KEY_GEN_MECHANISM, false, {true, true, true}, false},
    {CKA_ALLOWED_MECHANISMS, false, {false, false, true}, false},
};

ObjectPolicyKey::ObjectPolicyKey() {
  AddPolicies(kKeyPolicies, std::size(kKeyPolicies));
}

ObjectPolicyKey::~ObjectPolicyKey() {}

void ObjectPolicyKey::SetDefaultAttributes() {
  ObjectPolicyCommon::SetDefaultAttributes();
  CK_ATTRIBUTE_TYPE empty[] = {CKA_ID, CKA_START_DATE, CKA_END_DATE};
  for (size_t i = 0; i < std::size(empty); ++i) {
    if (!object_->IsAttributePresent(empty[i]))
      object_->SetAttributeString(empty[i], "");
  }
  if (!object_->IsAttributePresent(CKA_DERIVE))
    object_->SetAttributeBool(CKA_DERIVE, false);
  if (!object_->IsAttributePresent(CKA_LOCAL))
    object_->SetAttributeBool(CKA_LOCAL, false);
  if (!object_->IsAttributePresent(CKA_KEY_GEN_MECHANISM))
    object_->SetAttributeInt(CKA_KEY_GEN_MECHANISM,
                             static_cast<int>(CK_UNAVAILABLE_INFORMATION));
}

}  // namespace chaps
