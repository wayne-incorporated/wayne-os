// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "permission_broker/rule.h"

namespace permission_broker {

const char* Rule::ResultToString(const Result& result) {
  switch (result) {
    case ALLOW:
      return "ALLOW";
    case ALLOW_WITH_DETACH:
      return "ALLOW_WITH_DETACH";
    case ALLOW_WITH_LOCKDOWN:
      return "ALLOW_WITH_LOCKDOWN";
    case DENY:
      return "DENY";
    case IGNORE:
      return "IGNORE";
    default:
      return "INVALID";
  }
}

Rule::Rule(const std::string& name) : name_(name) {}

const std::string& Rule::name() const {
  return name_;
}

}  // namespace permission_broker
