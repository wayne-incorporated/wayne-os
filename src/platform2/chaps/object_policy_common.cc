// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chaps/object_policy_common.h"

#include <iterator>
#include <map>

#include <base/check.h>
#include <base/logging.h>

#include "chaps/chaps_utility.h"
#include "chaps/object.h"

using std::map;

namespace chaps {

// Read policy list as follows:
//   {attribute, sensitive, read-only {create, copy, modify}, required}
// sensitive - True if attribute cannot be read.
// read-only.create - True if attribute cannot be set with C_CreateObject.
// read-only.copy - True if attribute cannot be set with C_CopyObject.
// read-only.modify - True if attribute cannot be set with C_SetAttributeValue.
// required - True if attribute is required for a valid object.
static const AttributePolicy kCommonPolicies[] = {
    {CKA_CLASS, false, {false, true, true}, true},
    {CKA_TOKEN, false, {false, true, true}, false},
    {CKA_PRIVATE, false, {false, false, true}, false},
    {CKA_MODIFIABLE, false, {false, false, true}, false},
    {CKA_LABEL, false, {false, false, false}, false}};

ObjectPolicyCommon::ObjectPolicyCommon() : object_(NULL) {
  AddPolicies(kCommonPolicies, std::size(kCommonPolicies));
}

ObjectPolicyCommon::~ObjectPolicyCommon() {}

void ObjectPolicyCommon::Init(Object* object) {
  object_ = object;
}

bool ObjectPolicyCommon::IsReadAllowed(CK_ATTRIBUTE_TYPE type) {
  CHECK(object_);
  if (object_->GetAttributeBool(CKA_SENSITIVE, true) ||
      !object_->GetAttributeBool(CKA_EXTRACTABLE, false)) {
    map<CK_ATTRIBUTE_TYPE, AttributePolicy>::iterator it = policies_.find(type);
    if (it != policies_.end() && it->second.is_sensitive_) {
      LOG(WARNING) << "Attribute is sensitive: " << AttributeToString(type);
      return false;
    }
  }
  return true;
}

bool ObjectPolicyCommon::IsModifyAllowed(CK_ATTRIBUTE_TYPE type,
                                         const std::string& value) {
  CHECK(object_);
  map<CK_ATTRIBUTE_TYPE, AttributePolicy>::iterator it = policies_.find(type);
  if (it != policies_.end()) {
    ObjectStage stage = object_->GetStage();
    CHECK(stage < kNumObjectStages);
    if (it->second.is_readonly_[stage]) {
      LOG(WARNING) << "Attribute is read-only: " << AttributeToString(type);
      return false;
    }
  }
  if (type == CKA_SENSITIVE ||          // Read-only when true.
      type == CKA_EXTRACTABLE ||        // Read-only when false.
      type == CKA_WRAP_WITH_TRUSTED) {  // Read-only when true.
    bool new_value = (value[0] != 0);
    bool readonly_value = (type != CKA_EXTRACTABLE);
    if (readonly_value == object_->GetAttributeBool(type, !readonly_value) &&
        new_value != readonly_value) {
      LOG(WARNING) << "Attribute is read-only: " << AttributeToString(type);
      return false;
    }
  }
  return true;
}

bool ObjectPolicyCommon::IsObjectComplete() {
  CHECK(object_);
  map<CK_ATTRIBUTE_TYPE, AttributePolicy>::iterator it;
  for (it = policies_.begin(); it != policies_.end(); ++it) {
    if (it->second.is_required_ && !object_->IsAttributePresent(it->first)) {
      LOG(ERROR) << "Attribute is required: " << AttributeToString(it->first);
      return false;
    }
  }
  return true;
}

void ObjectPolicyCommon::SetDefaultAttributes() {
  CHECK(object_);
  if (!object_->IsAttributePresent(CKA_TOKEN))
    object_->SetAttributeBool(CKA_TOKEN, false);
  if (!object_->IsAttributePresent(CKA_PRIVATE))
    object_->SetAttributeBool(CKA_PRIVATE, IsPrivateClass());
  if (!object_->IsAttributePresent(CKA_MODIFIABLE))
    object_->SetAttributeBool(CKA_MODIFIABLE, true);
  if (!object_->IsAttributePresent(CKA_LABEL))
    object_->SetAttributeString(CKA_LABEL, "");
}

void ObjectPolicyCommon::AddPolicies(const AttributePolicy* policies,
                                     int num_policies) {
  for (int i = 0; i < num_policies; ++i) {
    policies_[policies[i].type_] = policies[i];
  }
}

bool ObjectPolicyCommon::IsPrivateClass() {
  switch (object_->GetObjectClass()) {
    case CKO_PUBLIC_KEY:
    case CKO_CERTIFICATE:
      return false;
  }
  return true;
}

}  // namespace chaps
