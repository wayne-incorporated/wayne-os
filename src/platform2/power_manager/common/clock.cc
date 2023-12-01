// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/common/clock.h"

#include <time.h>

#include <base/notreached.h>

namespace power_manager {
namespace {

// TODO(abhishekbh): Copied from Chrome's //base/time/time_now_posix.cc. Make
// upstream code available via libchrome and use it here:
// http://crbug.com/166153.
int64_t ConvertTimespecToMicros(const struct timespec& ts) {
  // On 32-bit systems, the calculation cannot overflow int64_t.
  // 2**32 * 1000000 + 2**64 / 1000 < 2**63
  if (sizeof(ts.tv_sec) <= 4 && sizeof(ts.tv_nsec) <= 8) {
    int64_t result = ts.tv_sec;
    result *= base::Time::kMicrosecondsPerSecond;
    result += (ts.tv_nsec / base::Time::kNanosecondsPerMicrosecond);
    return result;
  } else {
    base::CheckedNumeric<int64_t> result(ts.tv_sec);
    result *= base::Time::kMicrosecondsPerSecond;
    result += (ts.tv_nsec / base::Time::kNanosecondsPerMicrosecond);
    return result.ValueOrDie();
  }
}

// TODO(abhishekbh): Copied from Chrome's //base/time/time_now_posix.cc. Make
// upstream code available via libchrome and use it here:
// http://crbug.com/166153.
// Returns count of |clk_id|. Returns 0 if |clk_id| isn't present on the system.
int64_t ClockNow(clockid_t clk_id) {
  struct timespec ts;
  if (clock_gettime(clk_id, &ts) != 0) {
    NOTREACHED() << "clock_gettime(" << clk_id << ") failed.";
    return 0;
  }
  return ConvertTimespecToMicros(ts);
}

}  // namespace

base::TimeTicks Clock::GetCurrentTime() {
  if (!current_time_for_testing_.is_null()) {
    current_time_for_testing_ += time_step_for_testing_;
    return current_time_for_testing_;
  }
  return base::TimeTicks::Now();
}

base::TimeTicks Clock::GetCurrentBootTime() {
  if (!current_boot_time_for_testing_.is_null()) {
    current_boot_time_for_testing_ += time_step_for_testing_;
    return current_boot_time_for_testing_;
  }
  return base::TimeTicks() + base::Microseconds(ClockNow(CLOCK_BOOTTIME));
}

base::Time Clock::GetCurrentWallTime() {
  if (!current_wall_time_for_testing_.is_null()) {
    current_wall_time_for_testing_ += time_step_for_testing_;
    return current_wall_time_for_testing_;
  }
  return base::Time::Now();
}

}  // namespace power_manager
