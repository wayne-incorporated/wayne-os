// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef INIT_CROSSYSTEM_FAKE_H_
#define INIT_CROSSYSTEM_FAKE_H_

#include <string>
#include <unordered_map>

#include "init/crossystem.h"

class CrosSystemFake : public CrosSystem {
 public:
  bool GetInt(const std::string& name, int* value_out);
  bool SetInt(const std::string& name, int value);
  bool GetString(const std::string& name, std::string* value_out);
  bool SetString(const std::string& name, const std::string& value);

 private:
  std::unordered_map<std::string, int> int_map_;
  std::unordered_map<std::string, std::string> string_map_;
};

#endif  // INIT_CROSSYSTEM_FAKE_H_
