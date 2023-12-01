// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef INIT_CROSSYSTEM_IMPL_H_
#define INIT_CROSSYSTEM_IMPL_H_

#include "init/crossystem.h"

#include <string>

class CrosSystemImpl : public CrosSystem {
 public:
  bool GetInt(const std::string& name, int* value_out);
  bool SetInt(const std::string& name, int value);
  bool GetString(const std::string& name, std::string* value_out);
  bool SetString(const std::string& name, const std::string& value);
};

#endif  // INIT_CROSSYSTEM_IMPL_H_
