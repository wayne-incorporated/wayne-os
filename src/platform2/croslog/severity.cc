// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "croslog/severity.h"

#include <algorithm>

#include <base/logging.h>
#include <base/strings/string_util.h>

namespace croslog {

namespace {
bool StartsWithCaseInsensitive(const base::StringPiece& s,
                               const base::StringPiece& prefix) {
  return (s.length() >= prefix.length()) &&
         (base::CompareCaseInsensitiveASCII(s.substr(0, prefix.length()),
                                            prefix) == 0);
}
}  // anonymous namespace

Severity SeverityFromString(const std::string& severity_str) {
  if (severity_str == "0" ||
      base::CompareCaseInsensitiveASCII(severity_str, "emerg") == 0) {
    return Severity::EMERGE;
  } else if (severity_str == "1" ||
             base::CompareCaseInsensitiveASCII(severity_str, "alert") == 0) {
    return Severity::ALERT;
  } else if (severity_str == "2" ||
             base::CompareCaseInsensitiveASCII(severity_str, "critical") == 0 ||
             base::CompareCaseInsensitiveASCII(severity_str, "crit") == 0) {
    return Severity::CRIT;
  } else if (severity_str == "3" ||
             base::CompareCaseInsensitiveASCII(severity_str, "err") == 0 ||
             base::CompareCaseInsensitiveASCII(severity_str, "error") == 0) {
    return Severity::ERROR;
  } else if (severity_str == "4" ||
             base::CompareCaseInsensitiveASCII(severity_str, "warn") == 0 ||
             base::CompareCaseInsensitiveASCII(severity_str, "warning") == 0) {
    return Severity::WARNING;
  } else if (severity_str == "5" ||
             base::CompareCaseInsensitiveASCII(severity_str, "notice") == 0) {
    return Severity::NOTICE;
  } else if (severity_str == "6" ||
             base::CompareCaseInsensitiveASCII(severity_str, "info") == 0) {
    return Severity::INFO;
  } else if (severity_str == "7" ||
             base::CompareCaseInsensitiveASCII(severity_str, "debug") == 0 ||
             // In Chrome log, "verbose" severity is followed by a number like
             // verbose[0-9] (eg. "verbose1").
             StartsWithCaseInsensitive(severity_str, "verbose")) {
    return Severity::DEBUG;
  } else {
    LOG(ERROR) << "Unknown value in 'priority' argument: " << severity_str
               << ".";
    return Severity::UNSPECIFIED;
  }
}

}  // namespace croslog
