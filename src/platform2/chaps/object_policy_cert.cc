// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chaps/object_policy_cert.h"

#include <iterator>

#include <base/logging.h>

#include "chaps/chaps_utility.h"

namespace chaps {

// Read policy list as follows:
//   {attribute, sensitive, read-only {create, copy, modify}, required}
// sensitive - True if attribute cannot be read.
// read-only.create - True if attribute cannot be set with C_CreateObject.
// read-only.copy - True if attribute cannot be set with C_CopyObject.
// read-only.modify - True if attribute cannot be set with C_SetAttributeValue.
// required - True if attribute is required for a valid object.
static const AttributePolicy kCertPolicies[] = {
    {CKA_CERTIFICATE_TYPE, false, {false, false, true}, true},
    {CKA_TRUSTED, false, {true, true, true}, false},
    {CKA_CERTIFICATE_CATEGORY, false, {false, false, true}, false},
    {CKA_CHECK_VALUE, false, {false, false, true}, false},
    {CKA_START_DATE, false, {false, false, true}, false},
    {CKA_END_DATE, false, {false, false, true}, false},
    {CKA_SUBJECT, false, {false, false, true}, false},
    {CKA_VALUE, false, {false, false, true}, true},
    {CKA_URL, false, {false, false, true}, false},
    {CKA_HASH_OF_SUBJECT_PUBLIC_KEY, false, {false, false, true}, false},
    {CKA_HASH_OF_ISSUER_PUBLIC_KEY, false, {false, false, true}, false},
    {CKA_JAVA_MIDP_SECURITY_DOMAIN, false, {false, false, true}, false},
    {CKA_OWNER, false, {false, false, true}, false}};

ObjectPolicyCert::ObjectPolicyCert() {
  AddPolicies(kCertPolicies, std::size(kCertPolicies));
}

ObjectPolicyCert::~ObjectPolicyCert() {}

bool ObjectPolicyCert::IsObjectComplete() {
  if (!ObjectPolicyCommon::IsObjectComplete())
    return false;
  // The following logic is based on requirements for the different types of
  // certificates described in PKCS #11 v2.20: 10.6.
  CK_CERTIFICATE_TYPE type = object_->GetAttributeInt(CKA_CERTIFICATE_TYPE, 0);
  if (type == CKC_X_509_ATTR_CERT) {
    if (!object_->IsAttributePresent(CKA_OWNER)) {
      LOG(ERROR) << "Attribute is required: CKA_OWNER";
      return false;
    }
  } else {
    if (!object_->IsAttributePresent(CKA_SUBJECT)) {
      LOG(ERROR) << "Attribute is required: CKA_SUBJECT";
      return false;
    }
    bool has_url = !object_->GetAttributeString(CKA_URL).empty();
    if (!has_url && object_->GetAttributeString(CKA_VALUE).empty()) {
      LOG(ERROR) << "Both CKA_VALUE and CKA_URL are empty.";
      return false;
    }
    if (has_url &&
        (object_->GetAttributeString(CKA_HASH_OF_SUBJECT_PUBLIC_KEY).empty() ||
         object_->GetAttributeString(CKA_HASH_OF_ISSUER_PUBLIC_KEY).empty())) {
      LOG(ERROR) << "Public key hash is missing.";
      return false;
    }
  }
  return true;
}

void ObjectPolicyCert::SetDefaultAttributes() {
  ObjectPolicyCommon::SetDefaultAttributes();
  if (!object_->IsAttributePresent(CKA_CERTIFICATE_CATEGORY))
    object_->SetAttributeInt(CKA_CERTIFICATE_CATEGORY, 0);
  if (!object_->IsAttributePresent(CKA_START_DATE))
    object_->SetAttributeBool(CKA_START_DATE, "");
  if (!object_->IsAttributePresent(CKA_END_DATE))
    object_->SetAttributeBool(CKA_END_DATE, "");
  if (object_->IsAttributePresent(CKA_CERTIFICATE_TYPE)) {
    CK_CERTIFICATE_TYPE type =
        object_->GetAttributeInt(CKA_CERTIFICATE_TYPE, 0);
    if (type == CKC_X_509) {
      CK_ATTRIBUTE_TYPE empty[] = {CKA_ID,
                                   CKA_ISSUER,
                                   CKA_SERIAL_NUMBER,
                                   CKA_URL,
                                   CKA_HASH_OF_SUBJECT_PUBLIC_KEY,
                                   CKA_HASH_OF_ISSUER_PUBLIC_KEY};
      for (size_t i = 0; i < std::size(empty); ++i) {
        if (!object_->IsAttributePresent(empty[i]))
          object_->SetAttributeString(empty[i], "");
      }
      if (!object_->IsAttributePresent(CKA_JAVA_MIDP_SECURITY_DOMAIN))
        object_->SetAttributeInt(CKA_JAVA_MIDP_SECURITY_DOMAIN, 0);
    } else if (type == CKC_WTLS) {
      CK_ATTRIBUTE_TYPE empty[] = {CKA_ISSUER, CKA_URL,
                                   CKA_HASH_OF_SUBJECT_PUBLIC_KEY,
                                   CKA_HASH_OF_ISSUER_PUBLIC_KEY};
      for (size_t i = 0; i < std::size(empty); ++i) {
        if (!object_->IsAttributePresent(empty[i]))
          object_->SetAttributeString(empty[i], "");
      }
    } else if (type == CKC_X_509_ATTR_CERT) {
      CK_ATTRIBUTE_TYPE empty[] = {CKA_AC_ISSUER, CKA_SERIAL_NUMBER,
                                   CKA_ATTR_TYPES};
      for (size_t i = 0; i < std::size(empty); ++i) {
        if (!object_->IsAttributePresent(empty[i]))
          object_->SetAttributeString(empty[i], "");
      }
    }
  }
}

}  // namespace chaps
