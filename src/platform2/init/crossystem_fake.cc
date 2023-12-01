// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "init/crossystem_fake.h"

bool CrosSystemFake::GetInt(const std::string& name, int* value_out) {
  if (int_map_.count(name) == 0)
    return false;

  *value_out = int_map_[name];
  return true;
}

bool CrosSystemFake::SetInt(const std::string& name, int value) {
  int_map_[name] = value;
  return true;
}

bool CrosSystemFake::GetString(const std::string& name,
                               std::string* value_out) {
  if (string_map_.count(name) == 0)
    return false;

  *value_out = string_map_[name];
  return true;
}

bool CrosSystemFake::SetString(const std::string& name,
                               const std::string& value) {
  string_map_[name] = value;
  return true;
}
