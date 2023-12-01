// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef AUTHPOLICY_POLICY_PREG_POLICY_ENCODER_H_
#define AUTHPOLICY_POLICY_PREG_POLICY_ENCODER_H_

#include <memory>
#include <string>
#include <vector>

namespace base {
class FilePath;
}  // namespace base

namespace enterprise_management {
class CloudPolicySettings;
class ChromeDeviceSettingsProto;
}  // namespace enterprise_management

namespace authpolicy {
namespace protos {
class ExtensionPolicy;
}  // namespace protos
}  // namespace authpolicy

namespace policy {

using ExtensionPolicies = std::vector<authpolicy::protos::ExtensionPolicy>;

// Loads the given set of |preg_files| and encodes all user policies into the
// given |policy| protobuf. Note that user policy can contain mandatory and
// recommended policies. If multiple files f1,...,fN are passed in, policies
// are merged with following rules:
// - Mandatory policies in fn overwrite mandatory policies in fm if n > m.
// - Recommended policies in fn overwrite recommended policies in fm if n > m.
// - Mandatory policies always overwrite recommended policies.
// Thus, a mandatory policy in f1 will overwrite a recommended policy in f3,
// even though f3 has the higher index.
// |log_policy_values| toggles debug logging of policy values.
bool ParsePRegFilesIntoUserPolicy(
    const std::vector<base::FilePath>& preg_files,
    enterprise_management::CloudPolicySettings* policy,
    bool log_policy_values);

// Loads the given set of |preg_files| and encodes all device policies into the
// given |policy| protobuf. If multiple files f1,...,fN are passed in, policies
// are merged with following rule:
// - Policies in fn overwrite policies in fm if n > m.
// |log_policy_values| toggles debug logging of policy values.
bool ParsePRegFilesIntoDevicePolicy(
    const std::vector<base::FilePath>& preg_files,
    enterprise_management::ChromeDeviceSettingsProto* policy,
    bool log_policy_values);

// Loads the given set of |preg_files| and encodes all extension policies into
// the given |policies| vector. If multiple files f1,...,fN are passed in,
// policies are merged with following rule:
// - Policies in fn overwrite policies in fm if n > m.
// |log_policy_values| toggles debug logging of policy values.
bool ParsePRegFilesIntoExtensionPolicy(
    const std::vector<base::FilePath>& preg_files,
    ExtensionPolicies* policies,
    bool log_policy_values);

}  // namespace policy

#endif  // AUTHPOLICY_POLICY_PREG_POLICY_ENCODER_H_
