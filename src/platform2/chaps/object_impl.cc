// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chaps/object_impl.h"

#include <string>

#include <base/check.h>
#include <base/logging.h>

#include "chaps/chaps_factory.h"
#include "chaps/chaps_utility.h"
#include "chaps/object_policy.h"
#include "pkcs11/cryptoki.h"

using std::string;

namespace chaps {

ObjectImpl::ObjectImpl(ChapsFactory* factory)
    : factory_(factory), stage_(kCreate), handle_(0), store_id_(0) {}
ObjectImpl::~ObjectImpl() {}

ObjectStage ObjectImpl::GetStage() const {
  return stage_;
}

int ObjectImpl::GetSize() const {
  AttributeMap::const_iterator it;
  int size = 0;
  for (it = attributes_.begin(); it != attributes_.end(); ++it) {
    // Estimate 12 bytes of overhead per attribute.  This should allow storage
    // of type and length info and some alignment bytes.  Depending on the
    // persistence model, this may not be accurate.
    size += (12 + it->second.length());
  }
  return size;
}

CK_OBJECT_CLASS ObjectImpl::GetObjectClass() const {
  return GetAttributeInt(CKA_CLASS, CK_UNAVAILABLE_INFORMATION);
}

bool ObjectImpl::IsTokenObject() const {
  return GetAttributeBool(CKA_TOKEN, false);
}

bool ObjectImpl::IsModifiable() const {
  return GetAttributeBool(CKA_MODIFIABLE, false);
}

bool ObjectImpl::IsPrivate() const {
  return GetAttributeBool(CKA_PRIVATE, true);
}

CK_RV ObjectImpl::FinalizeNewObject() {
  if (!SetPolicyByClass())
    return CKR_TEMPLATE_INCOMPLETE;
  AttributeMap::iterator it;
  for (it = attributes_.begin(); it != attributes_.end(); ++it) {
    // Only external attributes have this policy enforced.  Internally, we need
    // to be able to set attributes like CKA_LOCAL which the user cannot.
    if (external_attributes_.find(it->first) != external_attributes_.end()) {
      if (!policy_->IsModifyAllowed(it->first, it->second)) {
        return CKR_ATTRIBUTE_READ_ONLY;
      }
    }
  }
  policy_->SetDefaultAttributes();
  if (!policy_->IsObjectComplete())
    return CKR_TEMPLATE_INCOMPLETE;

  if (GetObjectClass() == CKO_PRIVATE_KEY) {
    // Set the kKeyInSoftware attribute to let the user know if it's stored in
    // software or secure elements such as TPM.
    SetAttributeBool(kKeyInSoftware, !IsAttributePresent(kKeyBlobAttribute));
  }

  stage_ = kModify;
  return CKR_OK;
}

CK_RV ObjectImpl::FinalizeCopyObject() {
  if (GetObjectClass() == CKO_PRIVATE_KEY) {
    // Set the kKeyInSoftware attribute to let the user know if it's stored in
    // software or secure elements such as TPM.
    SetAttributeBool(kKeyInSoftware, !IsAttributePresent(kKeyBlobAttribute));
  }
  stage_ = kModify;
  return CKR_OK;
}

CK_RV ObjectImpl::Copy(const Object* original) {
  stage_ = kCopy;
  attributes_ = *original->GetAttributeMap();
  policy_.reset();
  if (!SetPolicyByClass())
    return CKR_TEMPLATE_INCOMPLETE;
  return CKR_OK;
}

CK_RV ObjectImpl::GetAttributes(CK_ATTRIBUTE_PTR attributes,
                                int num_attributes) const {
  CK_RV result = CKR_OK;
  AttributeMap::const_iterator it;
  for (int i = 0; i < num_attributes; ++i) {
    it = attributes_.find(attributes[i].type);
    if (it == attributes_.end()) {
      VLOG(1) << "Attribute does not exist: "
              << AttributeToString(attributes[i].type);
      result = CKR_ATTRIBUTE_TYPE_INVALID;
      attributes[i].ulValueLen = -1;
    } else if (policy_.get() && !policy_->IsReadAllowed(attributes[i].type)) {
      result = CKR_ATTRIBUTE_SENSITIVE;
      attributes[i].ulValueLen = -1;
    } else if (attributes[i].pValue == NULL) {
      attributes[i].ulValueLen = it->second.length();
    } else if (attributes[i].ulValueLen < it->second.length()) {
      result = CKR_BUFFER_TOO_SMALL;
      attributes[i].ulValueLen = -1;
    } else {
      attributes[i].ulValueLen = it->second.length();
      memcpy(attributes[i].pValue, it->second.data(), it->second.length());
    }
  }
  return result;
}

CK_RV ObjectImpl::SetAttributes(const CK_ATTRIBUTE_PTR attributes,
                                int num_attributes) {
  for (int i = 0; i < num_attributes; ++i) {
    // Watch out for -1 in the length; this survives serialization (because
    // it is used as an error indicator for C_GetAttributeValue) but isn't
    // valid when setting attributes.
    if (attributes[i].ulValueLen == static_cast<CK_ULONG>(-1) ||
        !attributes[i].pValue)
      return CKR_ATTRIBUTE_VALUE_INVALID;
    string value(reinterpret_cast<const char*>(attributes[i].pValue),
                 attributes[i].ulValueLen);
    if (policy_.get()) {
      if (!policy_->IsModifyAllowed(attributes[i].type, value))
        return CKR_ATTRIBUTE_READ_ONLY;
    }
    external_attributes_.insert(attributes[i].type);
    attributes_[attributes[i].type] = value;
  }
  if (policy_.get()) {
    if (!policy_->IsObjectComplete())
      return CKR_TEMPLATE_INCOMPLETE;
  }
  return CKR_OK;
}

bool ObjectImpl::IsAttributePresent(CK_ATTRIBUTE_TYPE type) const {
  return (attributes_.find(type) != attributes_.end());
}

bool ObjectImpl::GetAttributeBool(CK_ATTRIBUTE_TYPE type,
                                  bool default_value) const {
  AttributeMap::const_iterator it = attributes_.find(type);
  if (it == attributes_.end())
    return default_value;
  if (it->second.empty())
    return default_value;
  return (it->second[0] != 0);
}

void ObjectImpl::SetAttributeBool(CK_ATTRIBUTE_TYPE type, bool value) {
  attributes_[type] = string(1, value ? 1 : 0);
}

CK_ULONG ObjectImpl::GetAttributeInt(CK_ATTRIBUTE_TYPE type,
                                     CK_ULONG default_value) const {
  AttributeMap::const_iterator it = attributes_.find(type);
  if (it == attributes_.end())
    return default_value;
  switch (it->second.length()) {
    case 1:
      return ExtractFromByteString<uint8_t>(it->second);
    case 2:
      return ExtractFromByteString<uint16_t>(it->second);
    case 4:
      return ExtractFromByteString<uint32_t>(it->second);
    case 8:
      return ExtractFromByteString<uint64_t>(it->second);
    default:
      LOG(WARNING) << "GetAttributeInt: invalid length: "
                   << it->second.length();
  }
  return default_value;
}

void ObjectImpl::SetAttributeInt(CK_ATTRIBUTE_TYPE type, CK_ULONG value) {
  attributes_[type] =
      string(reinterpret_cast<const char*>(&value), sizeof(value));
}

string ObjectImpl::GetAttributeString(CK_ATTRIBUTE_TYPE type) const {
  AttributeMap::const_iterator it = attributes_.find(type);
  if (it != attributes_.end())
    return it->second;
  return string();
}

void ObjectImpl::SetAttributeString(CK_ATTRIBUTE_TYPE type,
                                    const string& value) {
  attributes_[type] = value;
}

void ObjectImpl::RemoveAttribute(CK_ATTRIBUTE_TYPE type) {
  attributes_.erase(type);
}

const AttributeMap* ObjectImpl::GetAttributeMap() const {
  return &attributes_;
}

bool ObjectImpl::OnLoad() {
  if (!SetPolicyByClass()) {
    LOG(ERROR) << "Failed to set attribute access policy.";
    return false;
  }
  if (GetObjectClass() == CKO_PRIVATE_KEY) {
    // Set the kKeyInSoftware attribute for private keys so that users knows
    // whether the key is software backed or hardware backed.
    SetAttributeBool(kKeyInSoftware, !IsAttributePresent(kKeyBlobAttribute));
  }
  stage_ = kModify;
  return true;
}

bool ObjectImpl::SetPolicyByClass() {
  if (!IsAttributePresent(CKA_CLASS)) {
    LOG(ERROR) << "Missing object class attribute.";
    return false;
  }
  policy_.reset(factory_->CreateObjectPolicy(GetObjectClass()));
  CHECK(policy_.get());
  policy_->Init(this);
  return true;
}

}  // namespace chaps
