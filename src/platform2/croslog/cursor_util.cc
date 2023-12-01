// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "croslog/cursor_util.h"

#include <string>
#include <inttypes.h>

#include <base/strings/string_number_conversions.h>
#include <base/strings/stringprintf.h>

namespace croslog {

std::string GenerateCursor(const base::Time& time) {
  int64_t time_value = time.ToDeltaSinceWindowsEpoch().InMicroseconds();
  return "time=" + base::StringPrintf("%016" PRIX64, time_value);
}

bool ParseCursor(const std::string& cursor_str, base::Time* output) {
  if (cursor_str.size() != (sizeof(int64_t) * 2 + 5))
    return false;

  if (cursor_str.rfind("time=", 0) != 0)
    return false;

  int64_t time_value;
  if (!base::HexStringToInt64(
          base::StringPiece(cursor_str).substr(5, sizeof(int64_t) * 2),
          &time_value))
    return false;

  *output =
      base::Time::FromDeltaSinceWindowsEpoch(base::Microseconds(time_value));
  return true;
}

}  // namespace croslog
