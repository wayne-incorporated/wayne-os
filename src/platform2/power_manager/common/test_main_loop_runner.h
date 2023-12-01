// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef POWER_MANAGER_COMMON_TEST_MAIN_LOOP_RUNNER_H_
#define POWER_MANAGER_COMMON_TEST_MAIN_LOOP_RUNNER_H_

#include <memory>

#include <base/run_loop.h>
#include <base/time/time.h>
#include <base/timer/timer.h>

namespace power_manager {

// This class makes it easier to write tests that need to wait for an
// asynchronous event to be run by the event loop.  The typical usage pattern is
// as follows:
//
// 1. Instantiate a TestMainLoopRunner.
// 2. Set up a callback for the asynchronous event that calls StopLoop().
// 3. Call StartLoop() and test that it returns true.
// 4. Test that the asynchronous event included the expected data.
class TestMainLoopRunner {
 public:
  TestMainLoopRunner() = default;
  TestMainLoopRunner(const TestMainLoopRunner&) = delete;
  TestMainLoopRunner& operator=(const TestMainLoopRunner&) = delete;

  ~TestMainLoopRunner() = default;

  // Runs the event loop until StopLoop() is called or |timeout_delay| has
  // elapsed. Returns true if the loop was stopped via StopLoop() or false if
  // the timeout was hit.
  bool StartLoop(base::TimeDelta timeout_delay);

  // Stops the event loop, resulting in control returning to StartLoop() (which
  // will return true).
  void StopLoop();

  // Returns true if StartLoop() was called and neither StopLoop() nor
  // OnTimeout() has been called.
  bool LoopIsRunning() const;

 private:
  // Called when |timeout_delay| elapses without the loop having been stopped.
  void OnTimeout();

  std::unique_ptr<base::RunLoop> runner_;

  // Invokes OnTimeout().
  base::OneShotTimer timeout_timer_;

  // Was the loop stopped as a result of OnTimeout() being called rather than
  // StopLoop()?
  bool timed_out_ = false;
};

}  // namespace power_manager

#endif  // POWER_MANAGER_COMMON_TEST_MAIN_LOOP_RUNNER_H_
