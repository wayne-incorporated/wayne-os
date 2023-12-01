// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CROSLOG_SEVERITY_H_
#define CROSLOG_SEVERITY_H_

#include <string>

namespace croslog {

enum class Severity {
  UNSPECIFIED = -1,
  EMERGE = 0,
  ALERT,
  CRIT,
  ERROR,
  WARNING,
  NOTICE,
  INFO,
  DEBUG
};

Severity SeverityFromString(const std::string& str);

}  // namespace croslog

#endif  // CROSLOG_SEVERITY_H_
