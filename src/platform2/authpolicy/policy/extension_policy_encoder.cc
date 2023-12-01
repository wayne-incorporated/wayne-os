// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "authpolicy/policy/extension_policy_encoder.h"

#include <utility>

#include <base/check.h>
#include <base/json/json_string_value_serializer.h>
#include <base/logging.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <base/values.h>
#include <components/policy/core/common/registry_dict.h>

#include "authpolicy/log_colors.h"
#include "bindings/authpolicy_containers.pb.h"

namespace policy {
namespace {

const char* kColorPolicy = authpolicy::kColorPolicy;
const char* kColorReset = authpolicy::kColorReset;

// Converts a RegistryDict to a base::Value::Dict by converting all keys() to
// Values. In case of name collisions, keys win over values. Similar to
// RegistryDict::ConvertToJSON, just without schema validation.
base::Value::Dict ConvertToValue(const RegistryDict& dict) {
  base::Value::Dict value;
  for (const auto& entry : dict.values())
    value.Set(entry.first, entry.second.Clone());
  for (const auto& entry : dict.keys())
    value.Set(entry.first, ConvertToValue(*entry.second));
  return value;
}

// Verifies that id is a Chrome extension id. Pretty much copied from
// components/crx_file/id_util.cc.
bool IsValidExtensionId(const std::string& id) {
  if (id.size() != 32)
    return false;

  std::string temp = base::ToLowerASCII(id);
  for (size_t n = 0; n < id.size(); n++) {
    char ch = base::ToLowerASCII(id[n]);
    if (ch < 'a' || ch > 'p')
      return false;
  }

  return true;
}

}  // namespace

ExtensionPolicyEncoder::ExtensionPolicyEncoder(const RegistryDict* dict)
    : dict_(dict) {}

void ExtensionPolicyEncoder::EncodePolicy(ExtensionPolicies* policies) const {
  policies->clear();
  for (const auto& id_and_dict : dict_->keys()) {
    const std::string& extension_id = id_and_dict.first;
    const RegistryDict* dict = id_and_dict.second.get();
    DCHECK(dict);
    if (!IsValidExtensionId(extension_id)) {
      LOG(ERROR) << "Failed to convert policy for extension: Invalid ID '"
                 << extension_id << "'. Ignoring.";
      continue;
    }

    // Convert dict to a JSON string.
    std::string json_data;
    base::Value::Dict value = ConvertToValue(*dict);
    JSONStringValueSerializer serializer(&json_data);
    if (!serializer.Serialize(value)) {
      LOG(ERROR) << "Failed to convert policy for extension '" << extension_id
                 << "' to JSON. Ignoring.";
      continue;
    }

    authpolicy::protos::ExtensionPolicy policy;
    policy.set_id(extension_id);
    policy.set_json_data(std::move(json_data));
    policies->push_back(std::move(policy));

    if (log_policy_values_) {
      // Serialize again, but with pretty printing. This is debug only and
      // usually disabled in production.
      std::string pretty_json;
      JSONStringValueSerializer pretty_serializer(&pretty_json);
      pretty_serializer.set_pretty_print(true);
      pretty_serializer.Serialize(value);
      LOG(INFO) << kColorPolicy << "Extension policy (id '" << extension_id
                << "')" << kColorReset;
      std::vector<std::string> lines = base::SplitString(
          pretty_json, "\n", base::KEEP_WHITESPACE, base::SPLIT_WANT_ALL);
      for (const std::string& line : lines)
        LOG(INFO) << kColorPolicy << line << kColorReset;
    }
  }
}

}  // namespace policy
