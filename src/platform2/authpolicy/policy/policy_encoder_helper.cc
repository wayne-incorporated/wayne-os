// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "authpolicy/policy/policy_encoder_helper.h"

#include <optional>
#include <string>
#include <utility>

#include <base/check.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/functional/bind.h>
#include <base/functional/callback.h>
#include <base/functional/callback_helpers.h>
#include <base/logging.h>
#include <base/run_loop.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/utf_string_conversions.h>
#include <base/system/sys_info.h>
#include <components/policy/core/common/policy_load_status.h>
#include <components/policy/core/common/registry_dict.h>

#include "authpolicy/log_colors.h"
#include "authpolicy/policy/preg_parser.h"
#include "bindings/policy_common_definitions.pb.h"
#include "bindings/policy_constants.h"

namespace em = enterprise_management;

namespace policy {

constexpr char kKeyUserDevice[] = "Software\\Policies\\Google\\ChromeOS";
constexpr char kKeyExtensions[] =
    "Software\\Policies\\Google\\Chrome\\3rdparty\\Extensions";
constexpr char kKeyRecommended[] = "Recommended";
constexpr char kKeyMandatoryExtension[] = "Policy";

bool LoadPRegFileIntoDict(const base::FilePath& preg_file,
                          const char* registry_key,
                          RegistryDict* dict) {
  if (!base::PathExists(preg_file)) {
    LOG(ERROR) << "PReg file '" << preg_file.value() << "' does not exist";
    return false;
  }

  // Note: Don't use PolicyLoadStatusUmaReporter here, it leaks, see
  // crbug.com/717888. Simply eat the status and report a less fine-grained
  // ERROR_PARSE_PREG_FAILED error in authpolicy. It would be possible to get
  // the load status into authpolicy, but that would require a lot of plumbing
  // since this code usually runs in a sandboxed process.
  PolicyLoadStatusSampler status;
  const std::u16string registry_key_utf16 = base::ASCIIToUTF16(registry_key);
  if (!preg_parser::ReadFile(preg_file, registry_key_utf16, dict, &status)) {
    LOG(ERROR) << "Failed to parse preg file '" << preg_file.value() << "'";
    return false;
  }

  return true;
}

bool LoadPRegFilesIntoDict(const std::vector<base::FilePath>& preg_files,
                           const char* registry_key,
                           RegistryDict* policy_dict) {
  for (const base::FilePath& preg_file : preg_files) {
    if (!LoadPRegFileIntoDict(preg_file, registry_key, policy_dict))
      return false;
  }
  return true;
}

std::optional<bool> GetAsBoolean(const base::Value* value) {
  if (value->is_bool())
    return value->GetBool();

  if (value->is_int()) {
    // Boolean policies are represented as integer 0/1 in the registry.
    int int_value = value->GetInt();
    if (int_value == 0 || int_value == 1)
      return int_value != 0;
  }

  return std::nullopt;
}

void PrintConversionError(const base::Value* value,
                          const char* target_type,
                          const char* policy_name,
                          const std::string* index_str) {
  LOG(ERROR) << "Failed to convert value '" << *value << " of type '"
             << base::Value::GetTypeName(value->type()) << "'"
             << " to " << target_type << " for policy '" << policy_name << "'"
             << (index_str ? " at index " + *index_str : "");
}

bool GetAsIntegerInRangeAndPrintError(const base::Value* value,
                                      int range_min,
                                      int range_max,
                                      const char* policy_name,
                                      int* int_value) {
  if (!value->is_int()) {
    *int_value = 0;
    PrintConversionError(value, "integer", policy_name);
    return false;
  }
  *int_value = value->GetInt();

  if (*int_value < range_min || *int_value > range_max) {
    LOG(ERROR) << "Value of policy '" << policy_name << "' is " << *int_value
               << ", outside of expected range [" << range_min << ","
               << range_max << "]";
    *int_value = 0;
    return false;
  }

  return true;
}

PolicyValueCallback GetValueFromDictCallback(const RegistryDict* policy_dict) {
  return base::BindRepeating(
      [](const RegistryDict* dict, const std::string& policy_name) {
        return dict->GetValue(policy_name);
      },
      policy_dict);
}

void SetPolicyOptions(em::PolicyOptions* options, PolicyLevel level) {
  DCHECK(options);
  options->set_mode(level == POLICY_LEVEL_RECOMMENDED
                        ? em::PolicyOptions_PolicyMode_RECOMMENDED
                        : em::PolicyOptions_PolicyMode_MANDATORY);
}

std::optional<bool> EncodeBooleanPolicy(const char* policy_name,
                                        PolicyValueCallback get_policy_value,
                                        bool log_policy_value) {
  const base::Value* value = get_policy_value.Run(policy_name);

  if (!value)
    return std::nullopt;

  // Get actual value, doing type conversion if necessary.
  std::optional<bool> bool_value = GetAsBoolean(value);
  if (!bool_value.has_value()) {
    PrintConversionError(value, "boolean", policy_name);
    return std::nullopt;
  }

  LOG_IF(INFO, log_policy_value)
      << authpolicy::kColorPolicy << "  " << policy_name << " = "
      << (*bool_value ? "true" : "false") << authpolicy::kColorReset;

  return bool_value;
}

std::optional<int> EncodeIntegerInRangePolicy(
    const char* policy_name,
    PolicyValueCallback get_policy_value,
    int range_min,
    int range_max,
    bool log_policy_value) {
  const base::Value* value = get_policy_value.Run(policy_name);
  if (!value)
    return std::nullopt;

  // Get actual value, doing type conversion if necessary.
  int int_value;
  if (!GetAsIntegerInRangeAndPrintError(value, range_min, range_max,
                                        policy_name, &int_value)) {
    return std::nullopt;
  }

  LOG_IF(INFO, log_policy_value)
      << authpolicy::kColorPolicy << "  " << policy_name << " = " << int_value
      << authpolicy::kColorReset;

  return std::make_optional(int_value);
}

std::optional<std::string> EncodeStringPolicy(
    const char* policy_name,
    PolicyValueCallback get_policy_value,
    bool log_policy_value) {
  // Try to get policy value from dict.
  const base::Value* value = get_policy_value.Run(policy_name);
  if (!value)
    return std::nullopt;

  // Get actual value, doing type conversion if necessary.
  if (!value->is_string()) {
    PrintConversionError(value, "string", policy_name);
    return std::nullopt;
  }

  const std::string& string_value = value->GetString();
  LOG_IF(INFO, log_policy_value)
      << authpolicy::kColorPolicy << "  " << policy_name << " = "
      << string_value << authpolicy::kColorReset;

  return string_value;
}

std::optional<std::vector<std::string>> EncodeStringListPolicy(
    const char* policy_name,
    PolicyValueCallback get_policy_value,
    bool log_policy_value) {
  // Get and check all values. Do this in advance to prevent partial writes.
  std::vector<std::string> string_values;
  for (int index = 0; /* empty */; ++index) {
    std::string index_str = base::NumberToString(index + 1);
    const base::Value* value = get_policy_value.Run(index_str);
    if (!value)
      break;

    if (!value->is_string()) {
      PrintConversionError(value, "string", policy_name, &index_str);
      return std::nullopt;
    }
    string_values.push_back(value->GetString());
  }

  if (log_policy_value && LOG_IS_ON(INFO)) {
    LOG(INFO) << authpolicy::kColorPolicy << "  " << policy_name
              << authpolicy::kColorReset;
    for (const std::string& value : string_values)
      LOG(INFO) << authpolicy::kColorPolicy << "    " << value
                << authpolicy::kColorReset;
  }

  return std::make_optional(string_values);
}

}  // namespace policy
