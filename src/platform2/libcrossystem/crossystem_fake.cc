// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <libcrossystem/crossystem_fake.h>

#include <optional>

namespace crossystem {

namespace fake {

std::optional<int> CrossystemFake::VbGetSystemPropertyInt(
    const std::string& name) const {
  const auto it = system_int_properties_.find(name);
  if (it == system_int_properties_.end())
    return std::nullopt;
  return it->second;
}

std::optional<std::string> CrossystemFake::VbGetSystemPropertyString(
    const std::string& name) const {
  const auto it = system_str_properties_.find(name);
  if (it == system_str_properties_.end())
    return std::nullopt;
  return it->second;
}

bool CrossystemFake::VbSetSystemPropertyInt(const std::string& name,
                                            int value) {
  if (readonly_system_peroperty_names_.count(name) > 0)
    return false;
  system_int_properties_[name] = value;
  return true;
}

bool CrossystemFake::VbSetSystemPropertyString(const std::string& name,
                                               const std::string& value) {
  if (readonly_system_peroperty_names_.count(name) > 0)
    return false;
  system_str_properties_[name] = value;
  return true;
}

void CrossystemFake::UnsetSystemPropertyValue(const std::string& name) {
  system_int_properties_.erase(name);
  system_str_properties_.erase(name);
}

void CrossystemFake::SetSystemPropertyReadOnlyStatus(const std::string& name,
                                                     bool is_readonly) {
  if (is_readonly) {
    readonly_system_peroperty_names_.insert(name);
  } else {
    readonly_system_peroperty_names_.erase(name);
  }
}

}  // namespace fake

}  // namespace crossystem
