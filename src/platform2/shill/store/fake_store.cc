// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/store/fake_store.h"

#include <set>
#include <string>
#include <typeinfo>
#include <vector>

#include "shill/logging.h"

#include <base/logging.h>

namespace shill {

namespace Logging {
static auto kModuleLogScope = ScopeLogger::kStorage;
}  // namespace Logging

namespace {

bool DoesGroupContainProperties(
    const brillo::VariantDictionary& group,
    const brillo::VariantDictionary& required_properties) {
  for (const auto& required_property_name_and_value : required_properties) {
    const auto& required_key = required_property_name_and_value.first;
    const auto& required_value = required_property_name_and_value.second;
    const auto& group_it = group.find(required_key);
    if (group_it == group.end() || group_it->second != required_value) {
      return false;
    }
  }
  return true;
}

}  // namespace

FakeStore::FakeStore() = default;

bool FakeStore::IsEmpty() const {
  // For now, the choice for return value is arbitrary. Revisit if we
  // find tests depend on this behaving correctly. (i.e., if any tests
  // require this to return true after a Close().)
  return true;
}

bool FakeStore::Open() {
  return true;
}

bool FakeStore::Close() {
  return true;
}

bool FakeStore::Flush() {
  return true;
}

bool FakeStore::MarkAsCorrupted() {
  return true;
}

std::set<std::string> FakeStore::GetGroups() const {
  std::set<std::string> matching_groups;
  for (const auto& group_name_and_settings : group_name_to_settings_) {
    matching_groups.insert(group_name_and_settings.first);
  }
  return matching_groups;
}

// Returns a set so that caller can easily test whether a particular group
// is contained within this collection.
std::set<std::string> FakeStore::GetGroupsWithKey(
    const std::string& key) const {
  std::set<std::string> matching_groups;
  // iterate over groups, find ones with matching key
  for (const auto& group_name_and_settings : group_name_to_settings_) {
    const auto& group_name = group_name_and_settings.first;
    const auto& group_settings = group_name_and_settings.second;
    if (group_settings.find(key) != group_settings.end()) {
      matching_groups.insert(group_name);
    }
  }
  return matching_groups;
}

std::set<std::string> FakeStore::GetGroupsWithProperties(
    const KeyValueStore& properties) const {
  std::set<std::string> matching_groups;
  const brillo::VariantDictionary& properties_dict(properties.properties());
  for (const auto& group_name_and_settings : group_name_to_settings_) {
    const auto& group_name = group_name_and_settings.first;
    const auto& group_settings = group_name_and_settings.second;
    if (DoesGroupContainProperties(group_settings, properties_dict)) {
      matching_groups.insert(group_name);
    }
  }
  return matching_groups;
}

bool FakeStore::ContainsGroup(const std::string& group) const {
  const auto& it = group_name_to_settings_.find(group);
  return it != group_name_to_settings_.end();
}

bool FakeStore::DeleteKey(const std::string& group, const std::string& key) {
  const auto& group_name_and_settings = group_name_to_settings_.find(group);
  if (group_name_and_settings == group_name_to_settings_.end()) {
    LOG(ERROR) << "Could not find group |" << group << "|.";
    return false;
  }

  auto& group_settings = group_name_and_settings->second;
  auto property_it = group_settings.find(key);
  if (property_it != group_settings.end()) {
    group_settings.erase(property_it);
  }

  return true;
}

bool FakeStore::DeleteGroup(const std::string& group) {
  auto group_name_and_settings = group_name_to_settings_.find(group);
  if (group_name_and_settings != group_name_to_settings_.end()) {
    group_name_to_settings_.erase(group_name_and_settings);
  }
  return true;
}

bool FakeStore::SetHeader(const std::string& header) {
  return true;
}

bool FakeStore::GetString(const std::string& group,
                          const std::string& key,
                          std::string* value) const {
  return ReadSetting(group, key, value);
}

bool FakeStore::SetString(const std::string& group,
                          const std::string& key,
                          const std::string& value) {
  return WriteSetting(group, key, value);
}

bool FakeStore::GetBool(const std::string& group,
                        const std::string& key,
                        bool* value) const {
  return ReadSetting(group, key, value);
}

bool FakeStore::SetBool(const std::string& group,
                        const std::string& key,
                        bool value) {
  return WriteSetting(group, key, value);
}

bool FakeStore::GetInt(const std::string& group,
                       const std::string& key,
                       int* value) const {
  return ReadSetting(group, key, value);
}

bool FakeStore::SetInt(const std::string& group,
                       const std::string& key,
                       int value) {
  return WriteSetting(group, key, value);
}

bool FakeStore::GetUint64(const std::string& group,
                          const std::string& key,
                          uint64_t* value) const {
  return ReadSetting(group, key, value);
}

bool FakeStore::SetUint64(const std::string& group,
                          const std::string& key,
                          uint64_t value) {
  return WriteSetting(group, key, value);
}

bool FakeStore::GetInt64(const std::string& group,
                         const std::string& key,
                         int64_t* value) const {
  return ReadSetting(group, key, value);
}

bool FakeStore::SetInt64(const std::string& group,
                         const std::string& key,
                         int64_t value) {
  return WriteSetting(group, key, value);
}
bool FakeStore::GetStringList(const std::string& group,
                              const std::string& key,
                              std::vector<std::string>* value) const {
  return ReadSetting(group, key, value);
}

bool FakeStore::SetStringList(const std::string& group,
                              const std::string& key,
                              const std::vector<std::string>& value) {
  return WriteSetting(group, key, value);
}

bool FakeStore::GetCryptedString(const std::string& group,
                                 const std::string& deprecated_key,
                                 const std::string& plaintext_key,
                                 std::string* value) const {
  return GetString(group, plaintext_key, value);
}

bool FakeStore::SetCryptedString(const std::string& group,
                                 const std::string& deprecated_key,
                                 const std::string& plaintext_key,
                                 const std::string& value) {
  return SetString(group, plaintext_key, value);
}

bool FakeStore::GetStringmaps(
    const std::string& group,
    const std::string& key,
    std::vector<std::map<std::string, std::string>>* value) const {
  return ReadSetting(group, key, value);
}

bool FakeStore::SetStringmaps(
    const std::string& group,
    const std::string& key,
    const std::vector<std::map<std::string, std::string>>& value) {
  return WriteSetting(group, key, value);
}

bool FakeStore::GetUint64List(const std::string& group,
                              const std::string& key,
                              std::vector<uint64_t>* value) const {
  return ReadSetting(group, key, value);
}

bool FakeStore::SetUint64List(const std::string& group,
                              const std::string& key,
                              const std::vector<uint64_t>& value) {
  return WriteSetting(group, key, value);
}

bool FakeStore::PKCS11SetString(const std::string& group,
                                const std::string& key,
                                const std::string& value) {
  pkcs11_strings_[group][key] = value;
  return true;
}

bool FakeStore::PKCS11GetString(const std::string& group,
                                const std::string& key,
                                std::string* value) const {
  if (pkcs11_strings_.find(group) == pkcs11_strings_.end()) {
    return false;
  }
  auto& group_submap = pkcs11_strings_.at(group);
  if (group_submap.find(key) == group_submap.end()) {
    return false;
  }
  *value = group_submap.at(key);
  return true;
}

bool FakeStore::PKCS11DeleteGroup(const std::string& group) {
  pkcs11_strings_.erase(group);
  return true;
}

// Private methods.
template <typename T>
bool FakeStore::ReadSetting(const std::string& group,
                            const std::string& key,
                            T* out) const {
  const auto& group_name_and_settings = group_name_to_settings_.find(group);
  if (group_name_and_settings == group_name_to_settings_.end()) {
    SLOG(10) << "Could not find group |" << group << "|.";
    return false;
  }

  const auto& group_settings = group_name_and_settings->second;
  const auto& property_name_and_value = group_settings.find(key);
  if (property_name_and_value == group_settings.end()) {
    SLOG(10) << "Could not find property |" << key << "|.";
    return false;
  }

  if (!property_name_and_value->second.IsTypeCompatible<T>()) {
    // We assume that the reader and the writer agree on the exact
    // type. So we do not allow implicit conversion.
    LOG(ERROR) << "Can not read |" << brillo::GetUndecoratedTypeName<T>()
               << "| from |"
               << property_name_and_value->second.GetUndecoratedTypeName()
               << "|.";
    return false;
  }

  if (out) {
    return property_name_and_value->second.GetValue(out);
  } else {
    return true;
  }
}

template <typename T>
bool FakeStore::WriteSetting(const std::string& group,
                             const std::string& key,
                             const T& new_value) {
  if (writes_fail_)
    return false;
  auto group_name_and_settings = group_name_to_settings_.find(group);
  if (group_name_and_settings == group_name_to_settings_.end()) {
    group_name_to_settings_[group][key] = new_value;
    return true;
  }

  auto& group_settings = group_name_and_settings->second;
  auto property_name_and_value = group_settings.find(key);
  if (property_name_and_value == group_settings.end()) {
    group_settings[key] = new_value;
    return true;
  }

  if (!property_name_and_value->second.IsTypeCompatible<T>()) {
    SLOG(10) << "New type |" << brillo::GetUndecoratedTypeName<T>()
             << "| differs from current type |"
             << property_name_and_value->second.GetUndecoratedTypeName()
             << "|.";
    return false;
  } else {
    property_name_and_value->second = new_value;
    return true;
  }
}

}  // namespace shill
