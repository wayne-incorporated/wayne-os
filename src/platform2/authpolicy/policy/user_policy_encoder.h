// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef AUTHPOLICY_POLICY_USER_POLICY_ENCODER_H_
#define AUTHPOLICY_POLICY_USER_POLICY_ENCODER_H_

#include <vector>

#include <base/functional/bind.h>
#include <components/policy/core/common/policy_types.h>

#include "authpolicy/policy/policy_encoder_helper.h"

namespace enterprise_management {
class CloudPolicySettings;
}  // namespace enterprise_management

namespace policy {

class RegistryDict;
// Private helper class used to convert a RegistryDict into a user policy
// protobuf. Don't include directly, use |preg_policy_encoder.h| instead.
class UserPolicyEncoder {
 public:
  UserPolicyEncoder(const RegistryDict* dict, PolicyLevel level);

  // Toggles logging of policy values.
  void LogPolicyValues(bool enabled) { log_policy_values_ = enabled; }

  // Extracts all user policies from |dict_| and puts them into |policy|.
  void EncodePolicy(enterprise_management::CloudPolicySettings* policy) const;

 private:
  // Gets a PolicyLevel as string.
  const char* GetLevelStr() const;

  // Boolean policies.
  void EncodeBoolean(enterprise_management::CloudPolicySettings* policy,
                     const BooleanPolicyAccess& access) const;

  // Integer policies.
  void EncodeInteger(enterprise_management::CloudPolicySettings* policy,
                     const IntegerPolicyAccess& access) const;

  // String policies.
  void EncodeString(enterprise_management::CloudPolicySettings* policy,
                    const StringPolicyAccess& access) const;

  // String list policies are a little different. Unlike the basic types they
  // are not stored as registry value, but as registry key with values 1, 2, ...
  // for the entries.
  void EncodeStringList(enterprise_management::CloudPolicySettings* policy,
                        const StringListPolicyAccess& access) const;

  const RegistryDict* dict_ = nullptr;
  PolicyLevel level_ = POLICY_LEVEL_MANDATORY;
  bool log_policy_values_ = false;
};

}  // namespace policy

#endif  // AUTHPOLICY_POLICY_USER_POLICY_ENCODER_H_
