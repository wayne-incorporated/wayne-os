// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chaps/object_policy_public_key.h"

#include <iterator>

#include <base/logging.h>

namespace chaps {

// Read policy list as follows:
//   {attribute, sensitive, read-only {create, copy, modify}, required}
// sensitive - True if attribute cannot be read.
// read-only.create - True if attribute cannot be set with C_CreateObject.
// read-only.copy - True if attribute cannot be set with C_CopyObject.
// read-only.modify - True if attribute cannot be set with C_SetAttributeValue.
// required - True if attribute is required for a valid object.
static const AttributePolicy kPublicKeyPolicies[] = {
    {CKA_TRUSTED, false, {true, true, true}, false},
    {CKA_WRAP_TEMPLATE, false, {false, false, true}, false},
    // RSA-specific attributes.
    {CKA_MODULUS, false, {false, false, true}, false},
    {CKA_PUBLIC_EXPONENT, false, {false, false, true}, false},
    // ECC-specific attributes.
    {CKA_EC_PARAMS, false, {false, false, true}, false},
    {CKA_EC_POINT, false, {false, false, true}, false},
};

ObjectPolicyPublicKey::ObjectPolicyPublicKey() {
  AddPolicies(kPublicKeyPolicies, std::size(kPublicKeyPolicies));
}

ObjectPolicyPublicKey::~ObjectPolicyPublicKey() {}

bool ObjectPolicyPublicKey::IsObjectComplete() {
  if (!ObjectPolicyCommon::IsObjectComplete())
    return false;

  // TODO(crbug/916955): create classes that inherit this class instead of
  // putting the key specific checking here.
  auto key_type = object_->GetAttributeInt(CKA_KEY_TYPE, -1);
  if (key_type == CKK_RSA) {
    if (!object_->IsAttributePresent(CKA_MODULUS) ||
        !object_->IsAttributePresent(CKA_PUBLIC_EXPONENT)) {
      LOG(ERROR) << "RSA Public key attributes are required.";
      return false;
    }
  } else if (key_type == CKK_EC) {
    if (!object_->IsAttributePresent(CKA_EC_PARAMS) ||
        !object_->IsAttributePresent(CKA_EC_POINT)) {
      LOG(ERROR) << "ECC Public key attributes are required.";
      return false;
    }
  } else {
    LOG(ERROR) << "Unknown CKA_KEY_TYPE for public key";
    return false;
  }
  return true;
}
void ObjectPolicyPublicKey::SetDefaultAttributes() {
  ObjectPolicyKey::SetDefaultAttributes();
  CK_ATTRIBUTE_TYPE false_values[] = {
      CKA_ENCRYPT, CKA_VERIFY, CKA_VERIFY_RECOVER, CKA_WRAP, CKA_TRUSTED};
  for (size_t i = 0; i < std::size(false_values); ++i) {
    if (!object_->IsAttributePresent(false_values[i]))
      object_->SetAttributeBool(false_values[i], false);
  }
  if (!object_->IsAttributePresent(CKA_SUBJECT))
    object_->SetAttributeString(CKA_SUBJECT, "");
}

}  // namespace chaps
