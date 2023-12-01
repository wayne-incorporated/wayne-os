// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "croslog/relative_time_util.h"

#include <string>

namespace croslog {

bool isNumber(const std::string& s) {
  if (s.size() < 2 || (s[0] != '+' && s[0] != '-')) {
    return false;
  }
  for (int i = 1; i < s.size(); i++) {
    if (!std::isdigit(s[i])) {
      return false;
    }
  }
  return true;
}

bool ParseRelativeTime(const std::string& relative_time_str,
                       base::Time* output) {
  if (!isNumber(relative_time_str)) {
    return false;
  }
  const int64_t relative_time{std::stol(relative_time_str)};
  *output = base::Time::Now() + base::Seconds(relative_time);
  return true;
}

}  // namespace croslog
