// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef P2P_COMMON_FAKE_CLOCK_H_
#define P2P_COMMON_FAKE_CLOCK_H_

#include <base/synchronization/waitable_event.h>

#include "p2p/common/clock_interface.h"

namespace p2p {

namespace common {

// Implements a fake version of the system time-related functions.
class FakeClock : public ClockInterface {
 public:
  FakeClock()
      : monotonic_time_(base::Time::Now()),
        sleep_called_(base::WaitableEvent::ResetPolicy::MANUAL,
                      base::WaitableEvent::InitialState::NOT_SIGNALED) {}
  FakeClock(const FakeClock&) = delete;
  FakeClock& operator=(const FakeClock&) = delete;

  void Sleep(const base::TimeDelta& duration) override {
    slept_duration_ += duration;
    monotonic_time_ += duration;
    // Signal that the Sleep() function was called, either if there is a caller
    // blocked or not. Signal() doesn't do anything if it was already signaled.
    sleep_called_.Signal();
  }

  base::Time GetMonotonicTime() override { return monotonic_time_; }

  base::TimeDelta GetSleptTime() { return slept_duration_; }

  void SetMonotonicTime(const base::Time& time) { monotonic_time_ = time; }

  // Blocks the caller thread until a different thread calls Sleep().
  void BlockUntilSleepIsCalled() {
    // Wait() will return only if Signal() is called after this Reset() is
    // executed.
    sleep_called_.Reset();
    sleep_called_.Wait();
  }

 private:
  base::TimeDelta slept_duration_;
  base::Time monotonic_time_;
  base::WaitableEvent sleep_called_;
};

}  // namespace common

}  // namespace p2p

#endif  // P2P_COMMON_FAKE_CLOCK_H_
