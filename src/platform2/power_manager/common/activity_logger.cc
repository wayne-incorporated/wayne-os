// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/common/activity_logger.h"

#include <cmath>

#include <base/check.h>
#include <base/format_macros.h>
#include <base/logging.h>
#include <base/strings/stringprintf.h>

#include "power_manager/common/clock.h"

namespace power_manager {
namespace {

// Default LogCallback for BaseActivityLogger.
void LogMessage(const std::string& message) {
  LOG(INFO) << message;
}

}  // namespace

void BaseActivityLogger::SetLogCallbackForTest(const LogCallback& callback) {
  log_callback_ = callback;
}

base::TimeDelta BaseActivityLogger::GetStoppedTimerDelayForTest() const {
  return stopped_timer_.IsRunning() ? stopped_timer_.GetCurrentDelay()
                                    : base::TimeDelta();
}

base::TimeDelta BaseActivityLogger::GetOngoingTimerDelayForTest() const {
  return ongoing_timer_.IsRunning() ? ongoing_timer_.GetCurrentDelay()
                                    : base::TimeDelta();
}

bool BaseActivityLogger::TriggerStoppedTimerForTest() {
  if (!stopped_timer_.IsRunning())
    return false;
  stopped_timer_.FireNow();
  return true;
}

bool BaseActivityLogger::TriggerOngoingTimerForTest() {
  if (!ongoing_timer_.IsRunning())
    return false;
  ongoing_timer_.user_task().Run();
  return true;
}

BaseActivityLogger::BaseActivityLogger(const std::string& activity_name,
                                       base::TimeDelta stopped_delay,
                                       base::TimeDelta ongoing_interval)
    : log_callback_(base::BindRepeating(&LogMessage)),
      clock_(new Clock()),
      activity_name_(activity_name),
      stopped_delay_(stopped_delay),
      ongoing_interval_(ongoing_interval) {}

std::string BaseActivityLogger::GetDelaySuffix(
    base::TimeTicks timestamp) const {
  const base::TimeDelta delay = clock_->GetCurrentTime() - timestamp;
  return base::StringPrintf("%0.f sec ago", round(delay.InSecondsF()));
}

PeriodicActivityLogger::PeriodicActivityLogger(const std::string& activity_name,
                                               base::TimeDelta stopped_delay,
                                               base::TimeDelta ongoing_interval)
    : BaseActivityLogger(activity_name, stopped_delay, ongoing_interval) {
  // This class is pointless without a stopped delay -- the caller should just
  // log every report directly themselves.
  CHECK(!stopped_delay.is_zero());
  // An ongoing interval less than or equal to the stopped delay would result in
  // the ongoing message being logged constantly.
  CHECK(ongoing_interval_.is_zero() || ongoing_interval_ > stopped_delay_);
}

void PeriodicActivityLogger::OnActivityReported() {
  last_report_time_ = clock_->GetCurrentTime();

  // Only log that activity started if we weren't waiting to log that it had
  // stopped.
  if (!stopped_timer_.IsRunning())
    log_callback_.Run(activity_name_ + " reported");

  // Extend the "stopped" timeout and start the "ongoing" timer if it isn't
  // already running.
  stopped_timer_.Start(FROM_HERE, stopped_delay_, this,
                       &PeriodicActivityLogger::LogStopped);
  if (!ongoing_interval_.is_zero() && !ongoing_timer_.IsRunning()) {
    ongoing_timer_.Start(FROM_HERE, ongoing_interval_, this,
                         &PeriodicActivityLogger::LogOngoing);
  }
}

void PeriodicActivityLogger::LogStopped() {
  log_callback_.Run(activity_name_ + " stopped; last reported " +
                    GetDelaySuffix(last_report_time_));
  ongoing_timer_.Stop();
}

void PeriodicActivityLogger::LogOngoing() {
  log_callback_.Run(activity_name_ + " ongoing; last reported " +
                    GetDelaySuffix(last_report_time_));
}

StartStopActivityLogger::StartStopActivityLogger(
    const std::string& activity_name,
    base::TimeDelta stopped_delay,
    base::TimeDelta ongoing_interval)
    : BaseActivityLogger(activity_name, stopped_delay, ongoing_interval) {}

void StartStopActivityLogger::OnActivityStarted() {
  stopped_time_ = base::TimeTicks();

  // Only log that activity started if we weren't waiting to log that it had
  // stopped. Otherwise, just stop the timer -- it'll be started again when
  // activity stops.
  if (!stopped_timer_.IsRunning())
    log_callback_.Run(activity_name_ + " started");
  else
    stopped_timer_.Stop();

  if (!ongoing_interval_.is_zero() && !ongoing_timer_.IsRunning()) {
    ongoing_timer_.Start(FROM_HERE, ongoing_interval_, this,
                         &StartStopActivityLogger::LogOngoing);
  }
}

void StartStopActivityLogger::OnActivityStopped() {
  if (stopped_time_ != base::TimeTicks()) {
    LOG(WARNING) << "Ignoring activity-stopped notification for "
                 << "already-stopped " << activity_name_;
    return;
  }

  stopped_time_ = clock_->GetCurrentTime();
  ongoing_timer_.Stop();

  if (stopped_delay_.is_zero()) {
    LogStopped();
  } else {
    stopped_timer_.Start(FROM_HERE, stopped_delay_, this,
                         &StartStopActivityLogger::LogStopped);
  }
}

void StartStopActivityLogger::LogStopped() {
  log_callback_.Run(
      activity_name_ + " stopped" +
      (stopped_delay_.is_zero() ? "" : " " + GetDelaySuffix(stopped_time_)));
}

void StartStopActivityLogger::LogOngoing() {
  log_callback_.Run(activity_name_ + " ongoing");
}

OngoingStateActivityLogger::OngoingStateActivityLogger(
    base::TimeDelta ongoing_interval)
    : BaseActivityLogger(std::string(), base::TimeDelta(), ongoing_interval) {}


void OngoingStateActivityLogger::OnStateChanged(const std::string& state) {
  state_ = state;
  if (state_.empty()) {
    ongoing_timer_.Stop();
  } else if (!ongoing_timer_.IsRunning()) {
    ongoing_timer_.Start(FROM_HERE, ongoing_interval_, this,
                         &OngoingStateActivityLogger::LogOngoing);
  }
}

void OngoingStateActivityLogger::LogOngoing() {
  DCHECK(!state_.empty());
  log_callback_.Run(state_);
}

}  // namespace power_manager
