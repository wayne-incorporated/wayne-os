// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libec/fingerprint/fp_stats_command.h"

namespace ec {

std::optional<base::TimeDelta> FpStatsCommand::CaptureTime() const {
  if (Resp()->timestamps_invalid & FPSTATS_CAPTURE_INV) {
    return std::nullopt;
  }

  return base::Microseconds(Resp()->capture_time_us);
}

std::optional<base::TimeDelta> FpStatsCommand::MatchingTime() const {
  if (Resp()->timestamps_invalid & FPSTATS_MATCHING_INV) {
    return std::nullopt;
  }

  return base::Microseconds(Resp()->matching_time_us);
}

base::TimeDelta FpStatsCommand::OverallTime() const {
  return base::Microseconds(Resp()->overall_time_us);
}

}  // namespace ec
