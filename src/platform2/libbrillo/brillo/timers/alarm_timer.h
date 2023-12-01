// Copyright 2014 The Chromium Authors
// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// Adapted from deleted Chromium's components/timers/alarm_timer_chromeos.h

#ifndef LIBBRILLO_BRILLO_TIMERS_ALARM_TIMER_H_
#define LIBBRILLO_BRILLO_TIMERS_ALARM_TIMER_H_

#include <memory>

#include <base/files/file_descriptor_watcher_posix.h>
#include <base/files/scoped_file.h>
#include <base/memory/scoped_refptr.h>
#include <base/memory/weak_ptr.h>
#include <base/pending_task.h>
#include <base/task/sequenced_task_runner.h>
#include <base/time/time.h>

#include "brillo/brillo_export.h"

namespace brillo {
namespace timers {
// The class implements a timer that is capable of waking the system up from a
// suspended state. For example, this is useful for running tasks that are
// needed for maintaining network connectivity, like sending heartbeat messages.
// Currently, this feature is only available on Chrome OS systems running linux
// version 3.11 or higher.
//
// A SimpleAlarmTimer instance can only be used from the sequence on which it
// was instantiated. Start() and Stop() must be called from a thread that
// supports FileDescriptorWatcher.
//
// A SimpleAlarmTimer only fires once but remembers the task that it was given
// even after it has fired.  Useful if you want to run the same task multiple
// times but not at a regular interval.
class BRILLO_EXPORT SimpleAlarmTimer {
 public:
  SimpleAlarmTimer(const SimpleAlarmTimer&) = delete;
  void operator=(const SimpleAlarmTimer&) = delete;

  ~SimpleAlarmTimer();

  // Starts the timer.
  void Start(const base::Location& location,
             base::TimeDelta delay,
             base::RepeatingClosure user_task);

  // Stops the timer.
  void Stop();

  // Resets the timer.
  void Reset();

  // Returns if current timer is running.
  bool IsRunning() const;

  const base::RepeatingClosure& UserTaskForTesting() const {
    return user_task_;
  }

  // Creates the SimpleAlarmTimer instance, or returns null on failure, e.g.,
  // on a platform without timerfd_* system calls support, or missing
  // capability (CAP_WAKE_ALARM).
  //
  // By default returns a timer based on a clock of type CLOCK_REALTIME_ALARM,
  // however, can be invoked with an optional argument specifying one of
  // CLOCK_REALTIME_ALARM or CLOCK_BOOTTIME_ALARM.
  //
  // Returns a nullptr if the timer could not be created.
  static std::unique_ptr<SimpleAlarmTimer> Create(
      clockid_t clock_id = CLOCK_REALTIME_ALARM);

  // Similar to Create(), but for unittests without capability.
  // Specifically, uses CLOCK_REALTIME instead of CLOCK_REALTIME_ALARM.
  static std::unique_ptr<SimpleAlarmTimer> CreateForTesting();

  // Checks if a particular clock_id is valid - presently either
  // CLOCK_REALTIME_ALARM or CLOCK_BOOTTIME_ALARM.
  static bool IsSupportedClock(clockid_t clock_id);

 private:
  // Shared implementation of Create and CreateForTesting.
  static std::unique_ptr<SimpleAlarmTimer> CreateInternal(clockid_t clock_id);

  explicit SimpleAlarmTimer(base::ScopedFD alarm_fd);

  // Called when |alarm_fd_| is readable without blocking. Reads data from
  // |alarm_fd_| and calls OnTimerFired().
  void OnAlarmFdReadableWithoutBlocking();

  // Called when the timer fires. Runs the callback.
  void OnTimerFired();

  // Timer file descriptor.
  const base::ScopedFD alarm_fd_;

  // Watches |alarm_fd_|.
  std::unique_ptr<base::FileDescriptorWatcher::Controller> alarm_fd_watcher_;

  // Posts tasks to the sequence on which this AlarmTimer was instantiated.
  const scoped_refptr<base::SequencedTaskRunner> origin_task_runner_ =
      base::SequencedTaskRunner::GetCurrentDefault();

  // Keeps track of the user task we want to run. A new one is constructed every
  // time Reset() is called.
  std::unique_ptr<base::PendingTask> pending_task_;

  // Keeps track of user task passed in.
  base::RepeatingClosure user_task_;

  // Keeps track if the timer is running.
  bool is_running_ = false;

  // Location in user code.
  base::Location posted_from_;

  // Delay set by user.
  base::TimeDelta delay_;

  // Used to invalidate pending callbacks.
  base::WeakPtrFactory<SimpleAlarmTimer> weak_factory_{this};
};

}  // namespace timers
}  // namespace brillo

#endif  // LIBBRILLO_BRILLO_TIMERS_ALARM_TIMER_H_
