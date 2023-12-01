// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef POWER_MANAGER_COMMON_CLOCK_H_
#define POWER_MANAGER_COMMON_CLOCK_H_

#include <base/time/time.h>

namespace power_manager {

// Simple class that allows tests to control the time.
//
// Classes should create a Clock member, provide a getter method that
// returns a pointer to it or some other means to call the
// set_current_*time_for_testing() setters, and then call GetCurrentTime()
// instead of base::TimeTicks::Now() and GetCurrentWallTime() instead of
// base::Time::Now().
//
// TODO(chromeos-power): Consider replacing this class with base::Clock and
// base::TickClock.
class Clock {
 public:
  Clock() = default;
  Clock(const Clock&) = delete;
  Clock& operator=(const Clock&) = delete;

  ~Clock() = default;

  void set_current_time_for_testing(base::TimeTicks now) {
    current_time_for_testing_ = now;
  }
  void set_current_boot_time_for_testing(base::TimeTicks now) {
    current_boot_time_for_testing_ = now;
  }
  void set_current_wall_time_for_testing(base::Time now) {
    current_wall_time_for_testing_ = now;
  }
  void advance_current_boot_time_for_testing(base::TimeDelta delta) {
    current_boot_time_for_testing_ += delta;
  }
  void set_time_step_for_testing(base::TimeDelta step) {
    time_step_for_testing_ = step;
  }

  // Returns the last-set monotonically-increasing time, or the actual time
  // (i.e. CLOCK_MONOTONIC) if |current_time_for_testing_| is unset. Time does
  // not advance while the system is suspended.
  base::TimeTicks GetCurrentTime();

  // Similar to GetCurrentTime(), except time also advances while the system is
  // suspended (i.e. CLOCK_BOOTTIME).
  base::TimeTicks GetCurrentBootTime();

  // Returns the last-set wall time, or the actual time (i.e. gettimeofday()) if
  // |current_wall_time_for_testing_| is unset.
  base::Time GetCurrentWallTime();

 private:
  base::TimeTicks current_time_for_testing_;
  base::TimeTicks current_boot_time_for_testing_;
  base::Time current_wall_time_for_testing_;

  // Amount of time that |current_*time_for_testing_| should be advanced by each
  // successive call to GetCurrent*Time().
  base::TimeDelta time_step_for_testing_;
};

}  // namespace power_manager

#endif  // POWER_MANAGER_COMMON_CLOCK_H_
