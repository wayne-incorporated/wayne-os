// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <string>

#include <base/logging.h>
#include <base/strings/stringprintf.h>

#include "timberslide/string_transformer.h"

namespace timberslide {

// Matching lines look like: [1234.5678 EC message goes here] .
std::string StringTransformer::AddHostTs(const std::string& s) {
  const base::Time logline_ts = GetLineTimestamp(s);
  return FormatTime(logline_ts).append(" ").append(s);
}

void StringTransformer::UpdateTimestamps(int64_t ec_uptime_ms,
                                         const base::Time& now) {
  ec_current_uptime_ms_ = ec_uptime_ms;
  timestamp_ = now;
}

std::string StringTransformer::FormatTime(const base::Time& time) {
  base::Time::Exploded e;

  // This format matches the syslog format used by default in ChromeOS logs
  time.UTCExplode(&e);
  return base::StringPrintf("%04d-%02d-%02dT%02d:%02d:%02d.%06dZ", e.year,
                            e.month, e.day_of_month, e.hour, e.minute, e.second,
                            e.millisecond * 1000);
}

// Some lines doesn't contain EC timestamp. In this case we just add
// timestamp from previous line in block. When first line in block
// doesn't contain timestamp, we add current time which is better than
// adding nothing
base::Time StringTransformer::GetLineTimestamp(const std::string& s) {
  // Check if EC uptime is initialized, if not use current time
  if (ec_current_uptime_ms_ < 0) {
    LOG(WARNING) << "Cannot obtain precise line timestamp - EC uptime is "
                    "not initialized";
    return base::Time::UnixEpoch();
  }

  double ec_ts;

  if (!RE2::PartialMatch(s, ec_timestamp_pattern_, &ec_ts))
    return logline_tm_;

  // Calculate delta from EC's uptime.
  const base::TimeDelta ec_sync(base::Milliseconds(ec_current_uptime_ms_));
  const base::TimeDelta logline_tm(base::Seconds(ec_ts));
  const base::TimeDelta logline_delta(ec_sync - logline_tm);
  logline_tm_ = timestamp_ - logline_delta;

  return logline_tm_;
}

}  // namespace timberslide
