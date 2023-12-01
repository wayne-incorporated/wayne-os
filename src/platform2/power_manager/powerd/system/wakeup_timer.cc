// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/powerd/system/wakeup_timer.h"

#include <memory>
#include <utility>

#include <base/memory/ptr_util.h>
#include <brillo/timers/alarm_timer.h>

namespace power_manager::system {

using brillo::timers::SimpleAlarmTimer;

std::unique_ptr<RealWakeupTimer> RealWakeupTimer::Create(clockid_t clock_id) {
  // Create the underlying timer.
  std::unique_ptr<SimpleAlarmTimer> timer = SimpleAlarmTimer::Create(clock_id);
  if (timer == nullptr) {
    return nullptr;
  }

  // using `new` to access private constructor.
  return base::WrapUnique(new RealWakeupTimer(std::move(timer)));
}

RealWakeupTimer::RealWakeupTimer(std::unique_ptr<SimpleAlarmTimer> timer)
    : timer_(std::move(timer)) {}

void RealWakeupTimer::Start(base::TimeDelta delay,
                            base::RepeatingClosure on_complete,
                            const base::Location& location) {
  timer_->Start(location, delay, std::move(on_complete));
}

bool RealWakeupTimer::IsRunning() const {
  return timer_->IsRunning();
}

void RealWakeupTimer::Reset() {
  timer_->Reset();
}

void RealWakeupTimer::Stop() {
  timer_->Stop();
}

void TestWakeupTimer::Start(base::TimeDelta delay,
                            base::RepeatingClosure on_complete,
                            const base::Location& location) {
  timer_.Start(location, delay, std::move(on_complete));
}

bool TestWakeupTimer::IsRunning() const {
  return timer_.IsRunning();
}

void TestWakeupTimer::Reset() {
  timer_.Reset();
}

void TestWakeupTimer::Stop() {
  timer_.Stop();
}

}  // namespace power_manager::system
