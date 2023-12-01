// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TIMBERSLIDE_STRING_TRANSFORMER_H_
#define TIMBERSLIDE_STRING_TRANSFORMER_H_

#include <string>

#include <base/time/time.h>
#include <re2/re2.h>

namespace timberslide {
//
// Has a member function which adds the host timestamp
// to the beginning of each line passed to it.
//
class StringTransformer {
 public:
  StringTransformer()
      : timestamp_(base::Time::UnixEpoch()),
        logline_tm_(base::Time::UnixEpoch()),
        ec_timestamp_pattern_(R"(\[(\d+\.\d+))") {}

  std::string AddHostTs(const std::string& s);
  void UpdateTimestamps(int64_t ec_uptime_ms, const base::Time& now);

 private:
  std::string FormatTime(const base::Time& time);
  base::Time GetLineTimestamp(const std::string& s);

  int64_t ec_current_uptime_ms_ = -1;
  base::Time timestamp_;
  base::Time logline_tm_;
  RE2 ec_timestamp_pattern_;
};

}  // namespace timberslide

#endif  // TIMBERSLIDE_STRING_TRANSFORMER_H_
