// Copyright 2016 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LOGIN_MANAGER_FAKE_CROSSYSTEM_H_
#define LOGIN_MANAGER_FAKE_CROSSYSTEM_H_

#include <map>
#include <string>

#include "login_manager/crossystem.h"

class FakeCrossystem : public Crossystem {
 public:
  int VbGetSystemPropertyInt(const char* name);
  int VbSetSystemPropertyInt(const char* name, int value);
  const char* VbGetSystemPropertyString(const char* name,
                                        char* dest,
                                        std::size_t size);
  int VbSetSystemPropertyString(const char* name, const char* value);

 private:
  std::map<std::string, int> int_map_;
  std::map<std::string, std::string> string_map_;
};

#endif  // LOGIN_MANAGER_FAKE_CROSSYSTEM_H_
