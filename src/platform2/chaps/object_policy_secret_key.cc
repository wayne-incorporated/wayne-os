// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chaps/object_policy_secret_key.h"

#include <iterator>

#include "chaps/chaps_utility.h"

namespace chaps {

// Read policy list as follows:
//   {attribute, sensitive, read-only {create, copy, modify}, required}
// sensitive - True if attribute cannot be read.
// read-only.create - True if attribute cannot be set with C_CreateObject.
// read-only.copy - True if attribute cannot be set with C_CopyObject.
// read-only.modify - True if attribute cannot be set with C_SetAttributeValue.
// required - True if attribute is required for a valid object.
static const AttributePolicy kSecretKeyPolicies[] = {
    {CKA_ALWAYS_SENSITIVE, false, {true, true, true}, false},
    {CKA_NEVER_EXTRACTABLE, false, {true, true, true}, false},
    {CKA_WRAP_TEMPLATE, false, {false, false, true}, false},
    {CKA_UNWRAP_TEMPLATE, false, {false, false, true}, false},
    {CKA_CHECK_VALUE, false, {false, false, true}, false},
    {CKA_TRUSTED, false, {true, true, true}, false},
    {CKA_VALUE, true, {false, false, true}, true}};

ObjectPolicySecretKey::ObjectPolicySecretKey() {
  AddPolicies(kSecretKeyPolicies, std::size(kSecretKeyPolicies));
}

ObjectPolicySecretKey::~ObjectPolicySecretKey() {}

void ObjectPolicySecretKey::SetDefaultAttributes() {
  ObjectPolicyKey::SetDefaultAttributes();
  if (!object_->IsAttributePresent(CKA_SENSITIVE))
    object_->SetAttributeBool(CKA_SENSITIVE, true);
  if (!object_->IsAttributePresent(CKA_ENCRYPT))
    object_->SetAttributeBool(CKA_ENCRYPT, false);
  if (!object_->IsAttributePresent(CKA_DECRYPT))
    object_->SetAttributeBool(CKA_DECRYPT, false);
  if (!object_->IsAttributePresent(CKA_SIGN))
    object_->SetAttributeBool(CKA_SIGN, false);
  if (!object_->IsAttributePresent(CKA_VERIFY))
    object_->SetAttributeBool(CKA_VERIFY, false);
  if (!object_->IsAttributePresent(CKA_WRAP))
    object_->SetAttributeBool(CKA_WRAP, false);
  if (!object_->IsAttributePresent(CKA_UNWRAP))
    object_->SetAttributeBool(CKA_UNWRAP, false);
  if (!object_->IsAttributePresent(CKA_EXTRACTABLE))
    object_->SetAttributeBool(CKA_EXTRACTABLE, false);
  if (!object_->IsAttributePresent(CKA_WRAP_WITH_TRUSTED))
    object_->SetAttributeBool(CKA_WRAP_WITH_TRUSTED, false);
  if (object_->GetStage() == kCreate) {
    CK_ULONG keygen_mechanism = object_->GetAttributeInt(
        CKA_KEY_GEN_MECHANISM, static_cast<int>(CK_UNAVAILABLE_INFORMATION));
    bool keygen_known = (keygen_mechanism != CK_UNAVAILABLE_INFORMATION);
    if (keygen_known && object_->GetAttributeBool(CKA_SENSITIVE, false))
      object_->SetAttributeBool(CKA_ALWAYS_SENSITIVE, true);
    else
      object_->SetAttributeBool(CKA_ALWAYS_SENSITIVE, false);
    if (keygen_known && !object_->GetAttributeBool(CKA_EXTRACTABLE, true))
      object_->SetAttributeBool(CKA_NEVER_EXTRACTABLE, true);
    else
      object_->SetAttributeBool(CKA_NEVER_EXTRACTABLE, false);
  }
}

}  // namespace chaps
