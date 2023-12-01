// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef POWER_MANAGER_POWERD_SYSTEM_WAKEUP_TIMER_H_
#define POWER_MANAGER_POWERD_SYSTEM_WAKEUP_TIMER_H_

#include <memory>

#include <base/pending_task.h>
#include <base/time/time.h>
#include <base/timer/timer.h>

#include <brillo/timers/alarm_timer.h>

namespace power_manager::system {

// A timer capable of waking up the system from suspend.
//
// This is a thin wrapper around `brillo::timers::SimpleAlarmTimer`, but behind
// an interface to facilitate testing and mock time.
class WakeupTimer {
 public:
  virtual ~WakeupTimer() = default;

  // Start a timer that will expire after |delay|.
  //
  // Cancels any existing timer.
  virtual void Start(
      base::TimeDelta delay,
      base::RepeatingClosure on_complete,
      const base::Location& location = base::Location::Current()) = 0;

  // Returns true if a timer is currently running.
  virtual bool IsRunning() const = 0;

  // Restart the count down.
  virtual void Reset() = 0;

  // Stop any existing timer.
  virtual void Stop() = 0;
};

// A real wakeup timer, capable of waking the system from suspend.
//
// The implementation is backed by `brillo::timers::SimpleAlarmTimer`.
//
// The calling process will typically need the `CAP_WAKE_ALARM` capability.
class RealWakeupTimer : public WakeupTimer {
 public:
  ~RealWakeupTimer() override = default;

  // Create a RealWakeupTimer using the given clock_id, typically
  // |CLOCK_BOOTTIME_ALARM|.
  //
  // Returns nullptr on creation failure.
  static std::unique_ptr<RealWakeupTimer> Create(clockid_t clock_id);

  // |WakeupTimer| implementation.
  void Start(
      base::TimeDelta delay,
      base::RepeatingClosure on_complete,
      const base::Location& location = base::Location::Current()) override;
  bool IsRunning() const override;
  void Reset() override;
  void Stop() override;

 private:
  explicit RealWakeupTimer(std::unique_ptr<brillo::timers::SimpleAlarmTimer>);

  std::unique_ptr<brillo::timers::SimpleAlarmTimer> timer_;
};

// A test wakeup timer, using only standard libchrome timing mechanisms.
//
// Supports TaskEnvironment's MOCK_TIME mechanism, and does not require the
// process to have any special privileges.
class TestWakeupTimer : public WakeupTimer {
 public:
  TestWakeupTimer() = default;

  // |WakeupTimer| implementation.
  void Start(
      base::TimeDelta delay,
      base::RepeatingClosure on_complete,
      const base::Location& location = base::Location::Current()) override;
  bool IsRunning() const override;
  void Reset() override;
  void Stop() override;

 private:
  base::OneShotTimer timer_;
};

}  // namespace power_manager::system

#endif  // POWER_MANAGER_POWERD_SYSTEM_WAKEUP_TIMER_H_
