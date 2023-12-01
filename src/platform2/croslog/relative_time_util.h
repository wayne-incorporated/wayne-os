// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CROSLOG_RELATIVE_TIME_UTIL_H_
#define CROSLOG_RELATIVE_TIME_UTIL_H_

#include <string>

#include <base/time/time.h>

namespace croslog {

bool ParseRelativeTime(const std::string& duration_str, base::Time* output);

}  // namespace croslog

#endif  // CROSLOG_RELATIVE_TIME_UTIL_H_
