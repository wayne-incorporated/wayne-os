// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "mojo_service_manager/daemon/service_policy_loader.h"

#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <base/containers/contains.h>
#include <base/files/file_enumerator.h>
#include <base/files/file_util.h>
#include <base/json/json_reader.h>
#include <base/logging.h>

namespace chromeos {
namespace mojo_service_manager {
namespace {

// Keys of the policy files.
constexpr char kKeyIdentity[] = "identity";
constexpr char kKeyOwn[] = "own";
constexpr char kKeyRequest[] = "request";
constexpr std::array<const char*, 3> kExpectedKeys = {kKeyIdentity, kKeyOwn,
                                                      kKeyRequest};
// The json option for parsing policy files.
constexpr int kJSONOption =
    base::JSON_ALLOW_TRAILING_COMMAS | base::JSON_ALLOW_COMMENTS;

bool ValidateDictKeys(const base::Value::Dict& value) {
  for (const auto& [key, _] : value) {
    if (!base::Contains(kExpectedKeys, key)) {
      LOG(ERROR) << "Got an unexpected field: " << key;
      return false;
    }
  }
  return true;
}

bool ParseOptionalStringListByKey(const base::Value::Dict& value,
                                  base::StringPiece key,
                                  std::vector<std::string>* out) {
  const auto* list = value.Find(key);
  // Returns true if not found because this is an optional field.
  if (!list)
    return true;

  if (!list->is_list()) {
    LOG(ERROR) << "Expected \"" << key << "\" to be a list, but got: " << *list;
    return false;
  }
  std::vector<std::string> result;
  for (const auto& item : list->GetList()) {
    if (!item.is_string()) {
      LOG(ERROR) << "Expected \"" << key
                 << "\" to contain string, but got: " << item;
      return false;
    }
    result.push_back(item.GetString());
  }
  *out = std::move(result);
  return true;
}

bool GetStringByKey(const base::Value::Dict& value,
                    const std::string& key,
                    std::string* out) {
  const auto* str = value.Find(key);
  if (!str) {
    LOG(ERROR) << "Cannot find \"" << key << "\" in policy.";
    return false;
  }
  if (!str->is_string()) {
    LOG(ERROR) << "Expected \"" << key
               << "\" to be a string, but got: " << *str;
    return false;
  }
  *out = str->GetString();
  return true;
}

}  // namespace

bool LoadAllServicePolicyFileFromDirectory(const base::FilePath& dir,
                                           ServicePolicyMap* policy_map) {
  VLOG(1) << "Searching dir: " << dir;
  base::FileEnumerator e(dir, /*recursive=*/false, base::FileEnumerator::FILES);
  bool res = true;
  for (base::FilePath file = e.Next(); !file.empty(); file = e.Next()) {
    VLOG(1) << "Load: " << file;
    std::optional<ServicePolicyMap> file_policy_map =
        LoadServicePolicyFile(file);
    if (file_policy_map.has_value()) {
      if (!MergeServicePolicyMaps(&file_policy_map.value(), policy_map)) {
        res = false;
        LOG(ERROR) << "Error occurred when loading file: " << file;
      }
    } else {
      res = false;
      LOG(WARNING) << "Ignore file: " << file;
    }
  }
  return res;
}

bool LoadAllServicePolicyFileFromDirectories(
    const std::vector<base::FilePath>& dirs, ServicePolicyMap* policy_map) {
  bool res = true;
  for (const base::FilePath& dir : dirs) {
    if (!LoadAllServicePolicyFileFromDirectory(dir, policy_map))
      res = false;
  }
  return res;
}

std::optional<ServicePolicyMap> LoadServicePolicyFile(
    const base::FilePath& file) {
  std::string str;
  if (!base::ReadFileToString(file, &str)) {
    LOG(ERROR) << "Failed to read policy file: " << file;
    return std::nullopt;
  }

  std::optional<ServicePolicyMap> policy_map =
      ParseServicePolicyFromString(str);
  LOG_IF(ERROR, !policy_map.has_value())
      << "Failed to parse policy file: " << file;
  return policy_map;
}

std::optional<ServicePolicyMap> ParseServicePolicyFromString(
    const std::string& str) {
  auto value_with_error =
      base::JSONReader::ReadAndReturnValueWithError(str, kJSONOption);
  if (!value_with_error.has_value()) {
    LOG(ERROR) << "Cannot parse json: " << value_with_error.error().message
               << " (line: " << value_with_error.error().line
               << ", column: " << value_with_error.error().column << ")";
    return std::nullopt;
  }
  if (!value_with_error->is_list()) {
    LOG(ERROR) << "Expected policy to be a list, got: " << *value_with_error;
    return std::nullopt;
  }
  return ParseServicePolicyFromValue(value_with_error->GetList());
}

std::optional<ServicePolicyMap> ParseServicePolicyFromValue(
    const base::Value::List& value) {
  ServicePolicyMap result;
  for (const auto& item : value) {
    if (!item.is_dict()) {
      LOG(ERROR) << "Expected dict, got: " << item;
      return std::nullopt;
    }
    const auto& policy = item.GetDict();
    if (!ValidateDictKeys(policy))
      return std::nullopt;

    std::string identity;
    if (!GetStringByKey(policy, kKeyIdentity, &identity))
      return std::nullopt;
    if (!ValidateSecurityContext(identity)) {
      LOG(ERROR) << "\"" << identity
                 << "\" is not a valid SELinux security context.";
      return std::nullopt;
    }

    std::vector<std::string> owns;
    if (!ParseOptionalStringListByKey(policy, kKeyOwn, &owns)) {
      return std::nullopt;
    }
    for (const auto& service : owns) {
      if (!ValidateServiceName(service)) {
        LOG(ERROR) << "\"" << service << "\" is not a valid service name.";
        return std::nullopt;
      }
      if (!result[service].owner().empty()) {
        LOG(ERROR) << "\"" << service << "\" can have only one owner.";
        return std::nullopt;
      }
      result[service].SetOwner(identity);
    }

    std::vector<std::string> requests;
    if (!ParseOptionalStringListByKey(policy, kKeyRequest, &requests)) {
      return std::nullopt;
    }
    for (const auto& service : requests) {
      if (!ValidateServiceName(service)) {
        LOG(ERROR) << "\"" << service << "\" is not a valid service name.";
        return std::nullopt;
      }
      result[service].AddRequester(identity);
    }

    LOG_IF(WARNING, owns.empty() && requests.empty())
        << "A policy should contain at least one of \"" << kKeyOwn << "\" or \""
        << kKeyRequest << "\".";
  }
  return result;
}

}  // namespace mojo_service_manager
}  // namespace chromeos
