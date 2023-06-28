// Copyright 2016 The Chromium OS Authors. All rights reserved.
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

const char* FakeCrossystem::VbGetSystemPropertyString(const char* name,
                                                      char* dest,
                                                      std::size_t size) {
  if (string_map_.find(name) == string_map_.end())
    return nullptr;

  string_map_[name].copy(dest, size);
  return dest;
}

int FakeCrossystem::VbSetSystemPropertyString(const char* name,
                                              const char* value) {
  string_map_[name] = std::string(value);
  return 0;
}
