// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef AUTHPOLICY_POLICY_POLICY_ENCODER_HELPER_H_
#define AUTHPOLICY_POLICY_POLICY_ENCODER_HELPER_H_

#include <optional>
#include <string>
#include <vector>

#include <base/functional/callback.h>
#include <base/values.h>

#include <components/policy/core/common/policy_types.h>

#include "authpolicy/log_colors.h"
#include "authpolicy/policy/policy_encoder_helper.h"

namespace base {
class FilePath;
}  // namespace base

namespace enterprise_management {
class PolicyOptions;
class BooleanPolicyProto;
class IntegerPolicyProto;
class StringPolicyProto;
class StringListPolicyProto;
class CloudPolicySettings;
}  // namespace enterprise_management

namespace policy {

struct BooleanPolicyAccess;
struct IntegerPolicyAccess;
struct StringPolicyAccess;
struct StringListPolicyAccess;

// Callback to get the value of the policy.
using PolicyValueCallback =
    base::RepeatingCallback<const base::Value*(const std::string&)>;

class RegistryDict;

// Registry key path for user/device policy.
extern const char kKeyUserDevice[];

// Registry key path for Chrome extension policy.
extern const char kKeyExtensions[];

// Registry key path for Windows policy we're interested in.
extern const char kKeyWindows[];

// Registry key for recommended user and extension policy.
extern const char kKeyRecommended[];

// Registry key for mandatory extension policy. Note that mandatory user
// policy doesn't get any extension.
extern const char kKeyMandatoryExtension[];

// Checks a PReg file for existence and loads all entries in the branch with
// root |registry_key| into |dict|.
bool LoadPRegFileIntoDict(const base::FilePath& preg_file,
                          const char* registry_key,
                          RegistryDict* dict);

// Loads the |preg_files| into a the |policy_dict| and returns true if it
// succeeded, or false otherwise.
bool LoadPRegFilesIntoDict(const std::vector<base::FilePath>& preg_files,
                           const char* registry_key,
                           RegistryDict* policy_dict);

// Similar to base::Value::GetAsBoolean(), but in addition it converts int
// values of 0 or 1 to bool. Returns true on success and stores the output in
// bool_value.
std::optional<bool> GetAsBoolean(const base::Value* value, bool* bool_value);

// Prints an error log. Used if value cannot be converted to a target type.
void PrintConversionError(const base::Value* value,
                          const char* target_type,
                          const char* policy_name,
                          const std::string* index_str = nullptr);

// Gets value as integer, checks that it's in [range_min, range_max] and returns
// it in |int_value|. Prints errors and returns false if there's a conversion
// error or the value is not in range.
bool GetAsIntegerInRangeAndPrintError(const base::Value* value,
                                      int range_min,
                                      int range_max,
                                      const char* policy_name,
                                      int* int_value);

PolicyValueCallback GetValueFromDictCallback(const RegistryDict* policy_dict);

// Sets the PolicyOptions for a policy whether it will applied as mandatory or
// recommended.
void SetPolicyOptions(enterprise_management::PolicyOptions* options,
                      PolicyLevel level);

// Boolean policies.
std::optional<bool> EncodeBooleanPolicy(const char* policy_name,
                                        PolicyValueCallback get_policy_value,
                                        bool log_policy_value);

// Integer in range policies.
std::optional<int> EncodeIntegerInRangePolicy(
    const char* policy_name,
    PolicyValueCallback get_policy_value,
    int range_min,
    int range_max,
    bool log_policy_value);

// String policies.
std::optional<std::string> EncodeStringPolicy(
    const char* policy_name,
    PolicyValueCallback get_policy_value,
    bool log_policy_value);

// String list policies are a little different. Unlike the basic types they
// are not stored as registry value, but as registry key with values 1, 2, ...
// for the entries.
std::optional<std::vector<std::string>> EncodeStringListPolicy(
    const char* policy_name,
    PolicyValueCallback get_policy_value,
    bool log_policy_value);
}  // namespace policy

#endif  // AUTHPOLICY_POLICY_POLICY_ENCODER_HELPER_H_
