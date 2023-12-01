// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef POWER_MANAGER_COMMON_ACTIVITY_LOGGER_H_
#define POWER_MANAGER_COMMON_ACTIVITY_LOGGER_H_

#include <memory>
#include <string>

#include <base/functional/callback.h>
#include <base/time/time.h>
#include <base/timer/timer.h>

namespace power_manager {

class Clock;

// Non-instantiatable base class for logging activity. This contains members and
// testing code shared by all implementations.
class BaseActivityLogger {
 public:
  BaseActivityLogger(const BaseActivityLogger&) = delete;
  BaseActivityLogger& operator=(const BaseActivityLogger&) = delete;

  // Logging callback that can be replaced for testing.
  using LogCallback = base::RepeatingCallback<void(const std::string&)>;

  Clock* clock_for_test() { return clock_.get(); }

  // Sets an alternate callback to be run to log messages.
  void SetLogCallbackForTest(const LogCallback& callback);

  // Returns the current delays of timers or empty deltas if they're stopped.
  base::TimeDelta GetStoppedTimerDelayForTest() const;
  base::TimeDelta GetOngoingTimerDelayForTest() const;

  // Triggers timers and returns true if they're running. Returns false if they
  // aren't.
  [[nodiscard]] bool TriggerStoppedTimerForTest();
  [[nodiscard]] bool TriggerOngoingTimerForTest();

 protected:
  BaseActivityLogger(const std::string& activity_name,
                     base::TimeDelta stopped_delay,
                     base::TimeDelta ongoing_interval);

  virtual ~BaseActivityLogger() = default;

  // Returns a string of the format "0.5 sec ago" describing how long ago
  // |timestamp| occurred (compared to |clock_|'s idea of "now").
  std::string GetDelaySuffix(base::TimeTicks timestamp) const;

  // Callback used to log messages.
  LogCallback log_callback_;

  const std::unique_ptr<Clock> clock_;

  // String describing the type of activity being tracked.
  const std::string activity_name_;

  // Delay after the cessation of activity before logging that it's stopped.
  const base::TimeDelta stopped_delay_;

  // Interval for logging activity periodically.
  base::TimeDelta ongoing_interval_;

  // Used to log the cessation of activity and ongoing activity, respectively.
  base::OneShotTimer stopped_timer_;
  base::RepeatingTimer ongoing_timer_;
};

// PeriodicActivityLogger should be used for activity that is reported to powerd
// periodically, e.g. user or video activity (each reported every five seconds
// by Chrome while ongoing).
//
// It allows setting a "stopped delay" describing how long after the last report
// activity should be considered active (typically slightly longer than the
// interval with which reports are received) and an "ongoing interval" to log
// periodic messages while activity remains active.
//
// For example, with 5-second reporting interval, a stopped delay of 7 seconds,
// and an ongoing interval of 22 seconds:
//
// :00 reported -> "activity reported"
// :05 reported
// :10 reported
// :15 reported
// :20 reported
// :22          -> "activity ongoing; last reported 2 sec ago"
// :25 reported
// :32          -> "activity stopped; last reported 7 sec ago"
// :40 reported -> "activity reported"
class PeriodicActivityLogger : public BaseActivityLogger {
 public:
  // |activity_name| appears at the beginning of messages and describes the
  // activity, e.g. "User activity" or "Hovering".
  //
  // |stopped_delay| contains the duration after a report for which activity
  // will be considered ongoing. It should be longer than the interval between
  // reports.
  //
  // If |ongoing_interval| is nonzero, a message will be logged periodically
  // while activity is considered to be ongoing. If provided, it must be greater
  // than |stopped_delay|.
  PeriodicActivityLogger(const std::string& activity_name,
                         base::TimeDelta stopped_delay,
                         base::TimeDelta ongoing_interval);
  PeriodicActivityLogger(const PeriodicActivityLogger&) = delete;
  PeriodicActivityLogger& operator=(const PeriodicActivityLogger&) = delete;

  ~PeriodicActivityLogger() override = default;

  // Should be called when a periodic report of activity is received.
  void OnActivityReported();

 private:
  void LogStopped();
  void LogOngoing();

  // The time at which activity was last reported. Zero if activity hasn't yet
  // been reported.
  base::TimeTicks last_report_time_;
};

// StartStopActivityLogger should be used for activity that is reported to
// powerd via separate "start" and "stop" events, e.g. audio activity (reported
// by CRAS as changes to the number of active audio streams).
//
// It allows setting a "stopped delay" to suppress excess logging for activity
// that frequently starts and stops and an "ongoing interval" to log periodic
// messages while activity remains active.
//
// For example, with a stopped delay of 5 seconds and an ongoing interval of 10
// seconds:
//
// :00 started -> "activity started"
// :07 stopped
// :10 started
// :20         -> "activity ongoing"
// :30         -> "activity ongoing"
// :35 stopped
// :40         -> "activity stopped 5 sec ago"
// :42 started -> "activity started"
class StartStopActivityLogger : public BaseActivityLogger {
 public:
  // |activity_name| appears at the beginning of messages and describes the
  // activity, e.g. "User activity" or "Hovering".
  //
  // If |stopped_delay| is nonzero, it contains a duration after activity stops
  // during which future state changes will not be logged. If zero, all state
  // changes will be logged.
  //
  // If |ongoing_interval| is nonzero, a message will be logged periodically
  // while activity is considered to be ongoing.
  StartStopActivityLogger(const std::string& activity_name,
                          base::TimeDelta stopped_delay,
                          base::TimeDelta ongoing_interval);
  StartStopActivityLogger(const StartStopActivityLogger&) = delete;
  StartStopActivityLogger& operator=(const StartStopActivityLogger&) = delete;

  ~StartStopActivityLogger() override = default;

  // Should be called when activity starts or stops.
  void OnActivityStarted();
  void OnActivityStopped();

 private:
  void LogStopped();
  void LogOngoing();

  // The time at which activity last stopped. Zero if activity is currently
  // active or never started.
  base::TimeTicks stopped_time_;
};

// OngoingStateActivityLogger periodically logs a caller-provided state.
// The state is logged verbatim and can be changed.
//
// For example, with an ongoing interval of 10 seconds:
//
// :00 state "a"
// :10           -> "a"
// :20           -> "a"
// :26 state "b"
// :30           -> "b"
// :33 state ""
// :45 state "c"
// :55           -> "c"
class OngoingStateActivityLogger : public BaseActivityLogger {
 public:
  // |ongoing_interval| contains the interval between log messages while
  // |state_| is non-empty.
  explicit OngoingStateActivityLogger(base::TimeDelta ongoing_interval);
  OngoingStateActivityLogger(const OngoingStateActivityLogger&) = delete;
  OngoingStateActivityLogger& operator=(const OngoingStateActivityLogger&) =
      delete;

  ~OngoingStateActivityLogger() override = default;

  // Should be called when the state to log has changed.
  // When |state| transitions from empty to non-empty, a message will be logged
  // after |ongoing_interval| and then every |ongoing_interval|.
  // An empty string stops logging.
  void OnStateChanged(const std::string& state);

 private:
  void LogOngoing();

  // Current state message to log.
  std::string state_;
};

}  // namespace power_manager

#endif  // POWER_MANAGER_COMMON_ACTIVITY_LOGGER_H_
