// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "p2p/common/clock.h"

#include <time.h>
#include <unistd.h>

namespace p2p {

namespace common {

void Clock::Sleep(const base::TimeDelta& duration) {
  int64_t duration_usec = duration.InMicroseconds();
  int64_t duration_sec = duration_usec / base::Time::kMicrosecondsPerSecond;
  int64_t fractional_usec =
      duration_usec - duration_sec * base::Time::kMicrosecondsPerSecond;
  struct timespec req;
  req.tv_sec = duration_sec;
  req.tv_nsec = fractional_usec * base::Time::kNanosecondsPerMicrosecond;
  nanosleep(&req, NULL);
}

base::Time Clock::GetMonotonicTime() {
  struct timespec now_ts;
  if (clock_gettime(CLOCK_MONOTONIC_RAW, &now_ts) != 0) {
    // Avoid logging this as an error as call-sites may call this very
    // often and we don't want to fill up the disk...
    return base::Time();
  }
  struct timeval now_tv;
  now_tv.tv_sec = now_ts.tv_sec;
  now_tv.tv_usec = now_ts.tv_nsec / base::Time::kNanosecondsPerMicrosecond;
  return base::Time::FromTimeVal(now_tv);
}

}  // namespace common

}  // namespace p2p
