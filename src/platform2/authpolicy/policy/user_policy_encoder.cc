// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "authpolicy/policy/user_policy_encoder.h"

#include <limits>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/functional/bind.h>
#include <base/functional/callback.h>
#include <base/functional/callback_helpers.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/values.h>
#include <components/policy/core/common/registry_dict.h>

#include "authpolicy/policy/policy_encoder_helper.h"
#include "bindings/cloud_policy.pb.h"
#include "bindings/policy_constants.h"

namespace em = enterprise_management;

namespace policy {

UserPolicyEncoder::UserPolicyEncoder(const RegistryDict* dict,
                                     PolicyLevel level)
    : dict_(dict), level_(level) {}

void UserPolicyEncoder::EncodePolicy(em::CloudPolicySettings* policy) const {
  LOG_IF(INFO, log_policy_values_)
      << authpolicy::kColorPolicy << "User policy ("
      << (level_ == POLICY_LEVEL_RECOMMENDED ? "recommended" : "mandatory")
      << ")" << authpolicy::kColorReset;

  for (const BooleanPolicyAccess& access : kBooleanPolicyAccess) {
    EncodeBoolean(policy, access);
  }

  for (const IntegerPolicyAccess& access : kIntegerPolicyAccess) {
    EncodeInteger(policy, access);
  }

  for (const StringPolicyAccess& access : kStringPolicyAccess) {
    EncodeString(policy, access);
  }

  for (const StringListPolicyAccess& access : kStringListPolicyAccess) {
    EncodeStringList(policy, access);
  }
}

void UserPolicyEncoder::EncodeBoolean(em::CloudPolicySettings* policy,
                                      const BooleanPolicyAccess& access) const {
  const char* policy_name = access.policy_key;

  std::optional<bool> bool_value = EncodeBooleanPolicy(
      policy_name, GetValueFromDictCallback(dict_), log_policy_values_);
  if (bool_value) {
    // Create proto and set value.
    em::BooleanPolicyProto* proto = access.mutable_proto_ptr(policy);
    DCHECK(proto);
    proto->set_value(bool_value.value());
    SetPolicyOptions(proto->mutable_policy_options(), level_);
  }
}

void UserPolicyEncoder::EncodeInteger(em::CloudPolicySettings* policy,
                                      const IntegerPolicyAccess& access) const {
  const char* policy_name = access.policy_key;

  std::optional<int> int_value = EncodeIntegerInRangePolicy(
      policy_name, GetValueFromDictCallback(dict_),
      std::numeric_limits<int>::min(), std::numeric_limits<int>::max(),
      log_policy_values_);
  if (int_value) {
    // Create proto and set value.
    em::IntegerPolicyProto* proto = access.mutable_proto_ptr(policy);
    DCHECK(proto);
    proto->set_value(int_value.value());
    SetPolicyOptions(proto->mutable_policy_options(), level_);
  }
}

void UserPolicyEncoder::EncodeString(em::CloudPolicySettings* policy,
                                     const StringPolicyAccess& access) const {
  const char* policy_name = access.policy_key;

  std::optional<std::string> string_value = EncodeStringPolicy(
      policy_name, GetValueFromDictCallback(dict_), log_policy_values_);
  if (string_value) {
    // Create proto and set value.
    em::StringPolicyProto* proto = access.mutable_proto_ptr(policy);
    DCHECK(proto);
    *proto->mutable_value() = string_value.value();
    SetPolicyOptions(proto->mutable_policy_options(), level_);
  }
}

void UserPolicyEncoder::EncodeStringList(
    em::CloudPolicySettings* policy,
    const StringListPolicyAccess& access) const {
  // Try to get policy key from dict.
  const char* policy_name = access.policy_key;
  const RegistryDict* key = dict_->GetKey(policy_name);
  if (!key)
    return;

  std::optional<std::vector<std::string>> string_values =
      EncodeStringListPolicy(policy_name, GetValueFromDictCallback(key),
                             log_policy_values_);
  if (string_values) {
    // Create proto and set value.
    em::StringListPolicyProto* proto = access.mutable_proto_ptr(policy);
    DCHECK(proto);
    em::StringList* proto_list = proto->mutable_value();
    DCHECK(proto_list);
    proto_list->clear_entries();
    for (const std::string& value : string_values.value())
      *proto_list->add_entries() = value;
    SetPolicyOptions(proto->mutable_policy_options(), level_);
  }
}

}  // namespace policy
