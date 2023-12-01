// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CROSLOG_CURSOR_UTIL_H_
#define CROSLOG_CURSOR_UTIL_H_

#include <string>

#include <base/time/time.h>

namespace croslog {

std::string GenerateCursor(const base::Time& time);

bool ParseCursor(const std::string& cursor_str, base::Time* output);

}  // namespace croslog

#endif  // CROSLOG_CURSOR_UTIL_H_
