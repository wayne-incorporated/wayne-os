// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "login_manager/fake_crossystem.h"

int FakeCrossystem::VbGetSystemPropertyInt(const char* name) {
  if (int_map_.find(name) == int_map_.end())
    return -1;

  return int_map_[name];
}

int FakeCrossystem::VbSetSystemPropertyInt(const char* name, int value) {
  int_map_[name] = value;
  return 0;
}

int FakeCrossystem::VbGetSystemPropertyString(const char* name,
                                              char* dest,
                                              std::size_t size) {
  if (string_map_.find(name) == string_map_.end())
    return -1;

  // Max length of data to copy is size - 1 so we reserve a char for null
  // termination. This matches the behavior we are faking from
  // `platform/vboot_reference/host/include/crossystem.h`.
  auto len = string_map_[name].copy(dest, size - 1);
  dest[len] = '\0';
  return 0;
}

int FakeCrossystem::VbSetSystemPropertyString(const char* name,
                                              const char* value) {
  string_map_[name] = std::string(value);
  return 0;
}
