// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/common/test_main_loop_runner.h"

#include <base/check.h>
#include <base/location.h>
#include <base/logging.h>
#include <base/run_loop.h>

#include <memory>

namespace power_manager {

bool TestMainLoopRunner::StartLoop(base::TimeDelta timeout_delay) {
  CHECK(!runner_.get()) << "Loop is already running";
  timed_out_ = false;
  timeout_timer_.Start(FROM_HERE, timeout_delay, this,
                       &TestMainLoopRunner::OnTimeout);
  runner_ = std::make_unique<base::RunLoop>();
  runner_->Run();
  runner_.reset();
  return !timed_out_;
}

void TestMainLoopRunner::StopLoop() {
  CHECK(runner_.get()) << "Loop isn't running";
  timeout_timer_.Stop();
  runner_->Quit();
}

bool TestMainLoopRunner::LoopIsRunning() const {
  return runner_.get();
}

void TestMainLoopRunner::OnTimeout() {
  CHECK(runner_.get());
  timed_out_ = true;
  runner_->Quit();
}

}  // namespace power_manager
