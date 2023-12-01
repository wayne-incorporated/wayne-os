// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "authpolicy/policy/preg_policy_encoder.h"

#include <memory>
#include <vector>

#include <base/check.h>
#include <base/files/file_path.h>
#include <components/policy/core/common/registry_dict.h>

#include "authpolicy/policy/extension_policy_encoder.h"
#include "authpolicy/policy/policy_encoder_helper.h"
#include "authpolicy/policy/user_policy_encoder.h"

namespace em = enterprise_management;

namespace policy {

bool ParsePRegFilesIntoUserPolicy(const std::vector<base::FilePath>& preg_files,
                                  em::CloudPolicySettings* policy,
                                  bool log_policy_values) {
  DCHECK(policy);

  RegistryDict mandatory_dict;

  if (!LoadPRegFilesIntoDict(preg_files, kKeyUserDevice, &mandatory_dict))
    return false;

  // Recommended policies are stored in their own registry key. This can be
  // nullptr if there is no recommended policy.
  std::unique_ptr<RegistryDict> recommended_dict =
      mandatory_dict.RemoveKey(kKeyRecommended);

  // Convert recommended policies first. If a policy is both recommended and
  // mandatory, it will be overwritten to be mandatory below.
  if (recommended_dict) {
    UserPolicyEncoder enc(recommended_dict.get(), POLICY_LEVEL_RECOMMENDED);
    enc.LogPolicyValues(log_policy_values);
    enc.EncodePolicy(policy);
  }

  UserPolicyEncoder enc(&mandatory_dict, POLICY_LEVEL_MANDATORY);
  enc.LogPolicyValues(log_policy_values);
  enc.EncodePolicy(policy);

  return true;
}

bool ParsePRegFilesIntoDevicePolicy(
    const std::vector<base::FilePath>& preg_files,
    em::ChromeDeviceSettingsProto* policy,
    bool log_policy_values) {
  DCHECK(policy);

  RegistryDict mandatory_dict;

  if (!LoadPRegFilesIntoDict(preg_files, kKeyUserDevice, &mandatory_dict))
    return false;

  // Recommended policies are stored in their own registry key. This can be
  // nullptr if there is no recommended policy.
  std::unique_ptr<RegistryDict> recommended_dict =
      mandatory_dict.RemoveKey(kKeyRecommended);

  return true;
}

bool ParsePRegFilesIntoExtensionPolicy(
    const std::vector<base::FilePath>& preg_files,
    ExtensionPolicies* policy,
    bool log_policy_values) {
  DCHECK(policy);

  RegistryDict policy_dict;

  if (!LoadPRegFilesIntoDict(preg_files, kKeyExtensions, &policy_dict))
    return false;

  ExtensionPolicyEncoder enc(&policy_dict);
  enc.LogPolicyValues(log_policy_values);
  enc.EncodePolicy(policy);

  return true;
}

}  // namespace policy
