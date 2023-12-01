// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chaps/object_policy_data.h"

#include <iterator>

namespace chaps {

// Read policy list as follows:
//   {attribute, sensitive, read-only {create, copy, modify}, required}
// sensitive - True if attribute cannot be read.
// read-only.create - True if attribute cannot be set with C_CreateObject.
// read-only.copy - True if attribute cannot be set with C_CopyObject.
// read-only.modify - True if attribute cannot be set with C_SetAttributeValue.
// required - True if attribute is required for a valid object.
static const AttributePolicy kDataPolicies[] = {
    {CKA_APPLICATION, false, {false, false, true}, false},
    {CKA_OBJECT_ID, false, {false, false, true}, false},
    {CKA_VALUE, false, {false, false, true}, false},
};

ObjectPolicyData::ObjectPolicyData() {
  AddPolicies(kDataPolicies, std::size(kDataPolicies));
}

ObjectPolicyData::~ObjectPolicyData() {}

void ObjectPolicyData::SetDefaultAttributes() {
  ObjectPolicyCommon::SetDefaultAttributes();
  if (!object_->IsAttributePresent(CKA_APPLICATION))
    object_->SetAttributeBool(CKA_APPLICATION, "");
  if (!object_->IsAttributePresent(CKA_OBJECT_ID))
    object_->SetAttributeBool(CKA_OBJECT_ID, "");
  if (!object_->IsAttributePresent(CKA_VALUE))
    object_->SetAttributeBool(CKA_VALUE, "");
}

}  // namespace chaps
