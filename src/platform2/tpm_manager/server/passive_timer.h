// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TPM_MANAGER_SERVER_PASSIVE_TIMER_H_
#define TPM_MANAGER_SERVER_PASSIVE_TIMER_H_

#include <base/time/time.h>

// This simple class is a a configurable and resettable
// timer. By "passive" it means the timer itself doesn't actively fire any
// event; the user has to check if the time is up by calling
// |TimeRemaining|.
// Note that initially the timer is up by design. One can call |Reset| if
// they wants the timer to count down from the beginning.
class PassiveTimer {
 public:
  // Constructor that initialize its period.
  explicit PassiveTimer(const base::TimeDelta& period) : period_(period) {}
  ~PassiveTimer() = default;

  // Returns the time remaining since last reset. The returned value is
  // saturated to 0.; that is, the return value never goes negative.
  base::TimeDelta TimeRemaining() const {
    if (last_tick_.is_null()) {
      return base::TimeDelta();
    }
    auto now = base::TimeTicks::Now();
    base::TimeTicks uptime = last_tick_ + period_;
    return now < uptime ? uptime - now : base::TimeDelta();
  }
  // Restarts the timer so it starts to count down from the specified |period_|
  // again.
  void Reset() { last_tick_ = base::TimeTicks::Now(); }

 private:
  // The period of the timer.
  base::TimeDelta period_;
  // Records the time when the most recent call of |Reset|.
  base::TimeTicks last_tick_;
};

#endif  // TPM_MANAGER_SERVER_PASSIVE_TIMER_H_
