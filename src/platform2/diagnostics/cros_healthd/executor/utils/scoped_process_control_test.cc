// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <utility>

#include <base/functional/callback_helpers.h>
#include <base/functional/callback_forward.h>
#include <base/run_loop.h>
#include <base/test/bind.h>
#include <base/test/task_environment.h>
#include <gmock/gmock-actions.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <mojo/public/cpp/bindings/callback_helpers.h>

#include "diagnostics/cros_healthd/executor/utils/fake_process_control.h"
#include "diagnostics/cros_healthd/executor/utils/process_control.h"
#include "diagnostics/cros_healthd/executor/utils/scoped_process_control.h"
#include "diagnostics/cros_healthd/utils/callback_barrier.h"

namespace diagnostics {
namespace {

using ::testing::_;
using ::testing::Invoke;
using ::testing::Return;

class ScopedProcessControlTest : public testing::Test {
 protected:
  ScopedProcessControlTest() = default;
  ScopedProcessControlTest(const ScopedProcessControlTest&) = delete;
  ScopedProcessControlTest& operator=(const ScopedProcessControlTest&) = delete;

  FakeProcessControl fake_process_control_;

 private:
  base::test::TaskEnvironment task_environment_;
};

TEST_F(ScopedProcessControlTest, RunOneCallbackOnOutOfScope) {
  base::RunLoop run_loop;
  {
    ScopedProcessControl scoped_process_control;
    fake_process_control_.BindReceiver(
        scoped_process_control.BindNewPipeAndPassReceiver());
    scoped_process_control.AddOnTerminateCallback(
        base::ScopedClosureRunner(run_loop.QuitClosure()));
  }
  run_loop.Run();
  EXPECT_EQ(fake_process_control_.return_code(), 143);
  fake_process_control_.receiver().FlushForTesting();
  EXPECT_FALSE(fake_process_control_.IsConnected());
}

TEST_F(ScopedProcessControlTest, RunMultipleCallbacksOnOutOfScope) {
  base::RunLoop run_loop;
  {
    CallbackBarrier barrier(base::BindLambdaForTesting([&](bool success) {
      run_loop.Quit();
      EXPECT_TRUE(success);
    }));
    ScopedProcessControl scoped_process_control;
    fake_process_control_.BindReceiver(
        scoped_process_control.BindNewPipeAndPassReceiver());
    scoped_process_control.AddOnTerminateCallback(
        base::ScopedClosureRunner(barrier.CreateDependencyClosure()));
    scoped_process_control.AddOnTerminateCallback(
        base::ScopedClosureRunner(barrier.CreateDependencyClosure()));
    scoped_process_control.AddOnTerminateCallback(
        base::ScopedClosureRunner(barrier.CreateDependencyClosure()));
  }
  run_loop.Run();
  EXPECT_EQ(fake_process_control_.return_code(), 143);
  fake_process_control_.receiver().FlushForTesting();
  EXPECT_FALSE(fake_process_control_.IsConnected());
}

TEST_F(ScopedProcessControlTest, RunAllCallbacksOnReset) {
  base::RunLoop run_loop;
  ScopedProcessControl scoped_process_control;
  fake_process_control_.BindReceiver(
      scoped_process_control.BindNewPipeAndPassReceiver());
  scoped_process_control.AddOnTerminateCallback(
      base::ScopedClosureRunner(run_loop.QuitClosure()));
  scoped_process_control.Reset();
  run_loop.Run();
  EXPECT_EQ(fake_process_control_.return_code(), 143);
  fake_process_control_.receiver().FlushForTesting();
  EXPECT_FALSE(fake_process_control_.IsConnected());
}

TEST_F(ScopedProcessControlTest, ResetSuccessfullyIfNoRemoteBound) {
  base::RunLoop run_loop;
  ScopedProcessControl scoped_process_control;
  scoped_process_control.AddOnTerminateCallback(
      base::ScopedClosureRunner(run_loop.QuitClosure()));
  scoped_process_control.Reset();
  run_loop.Run();
}

TEST_F(ScopedProcessControlTest, AddCallbackAfterCallbacksCalled) {
  ScopedProcessControl scoped_process_control;
  fake_process_control_.BindReceiver(
      scoped_process_control.BindNewPipeAndPassReceiver());
  {
    base::RunLoop run_loop;
    scoped_process_control.AddOnTerminateCallback(
        base::ScopedClosureRunner(run_loop.QuitClosure()));
    fake_process_control_.SetReturnCode(0);
    run_loop.Run();
  }
  fake_process_control_.receiver().FlushForTesting();
  EXPECT_TRUE(fake_process_control_.IsConnected());
  {
    base::RunLoop run_loop;
    scoped_process_control.AddOnTerminateCallback(
        base::ScopedClosureRunner(run_loop.QuitClosure()));
    run_loop.Run();
  }
  fake_process_control_.receiver().FlushForTesting();
  EXPECT_TRUE(fake_process_control_.IsConnected());
}

}  // namespace
}  // namespace diagnostics
