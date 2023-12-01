// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DEBUGD_SRC_HELPERS_AUDIT_LOG_UTILS_H_
#define DEBUGD_SRC_HELPERS_AUDIT_LOG_UTILS_H_

#include <string>

namespace debugd {

// Takes in a single line of audig.log (or ausearch output) and filters out
// tokens that shouldn't be included in a feedback report. (b/209618299)
// Delimiter line ("----") included in ausearch output will be replaced with an
// empty string.
std::string FilterAuditLine(const std::string& line);

}  // namespace debugd

#endif  // DEBUGD_SRC_HELPERS_AUDIT_LOG_UTILS_H_
