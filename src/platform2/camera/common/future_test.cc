/*
 * Copyright 2016 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "cros-camera/future.h"

#include <base/at_exit.h>
#include <base/threading/thread.h>
#include <base/time/time.h>
#include <gtest/gtest.h>

#include "cros-camera/common.h"

namespace cros {

class FutureTest : public ::testing::Test {
 public:
  FutureTest() : thread_("Test Thread") {}
  FutureTest(const FutureTest&) = delete;
  FutureTest& operator=(const FutureTest&) = delete;

  void SetUp() override {
    if (!thread_.StartWithOptions(
            base::Thread::Options(base::MessagePumpType::IO, 0))) {
      LOGF(ERROR) << "Test thread failed to start";
      exit(-1);
    }
    thread_.WaitUntilThreadStarted();
  }

  void TearDown() override { thread_.Stop(); }

  void SignalCallback(base::OnceCallback<void()> cb) { std::move(cb).Run(); }

  template <typename T>
  void SignalCallbackWith(base::OnceCallback<void(T)> cb, T val) {
    std::move(cb).Run(std::move(val));
  }

  void CancelCallback() { relay_.CancelAllFutures(); }

 protected:
  base::Thread thread_;

  CancellationRelay relay_;
};

TEST_F(FutureTest, WaitTest) {
  // Normal signal-wait scenario.  The future wait should return true.

  // The future is signalled after being waited on.
  auto future = Future<void>::Create(&relay_);
  thread_.task_runner()->PostDelayedTask(
      FROM_HERE,
      base::BindOnce(&FutureTest::SignalCallback, base::Unretained(this),
                     cros::GetFutureCallback(future)),
      base::Milliseconds(2000));
  ASSERT_TRUE(future->Wait());

  // Subsequent wait to a signalled future should return true.
  ASSERT_TRUE(future->Wait());

  // The future is signalled before being waited on.
  future = Future<void>::Create(&relay_);
  future->Set();
  ASSERT_TRUE(future->Wait());
}

TEST_F(FutureTest, GetTest) {
  auto future = Future<int>::Create(&relay_);
  thread_.task_runner()->PostTask(
      FROM_HERE, base::BindOnce(&FutureTest::SignalCallbackWith<int>,
                                base::Unretained(this),
                                cros::GetFutureCallback(future), 42));
  ASSERT_EQ(future->Get(), 42);
}

TEST_F(FutureTest, GetMoveOnlyTest) {
  auto future = Future<std::unique_ptr<int>>::Create(&relay_);
  auto ptr = std::make_unique<int>(42);
  thread_.task_runner()->PostTask(
      FROM_HERE,
      base::BindOnce(&FutureTest::SignalCallbackWith<std::unique_ptr<int>>,
                     base::Unretained(this), cros::GetFutureCallback(future),
                     std::move(ptr)));
  ptr = future->Get();
  ASSERT_EQ(*ptr, 42);
}

TEST_F(FutureTest, TimeoutTest) {
  // A future wait should return false because of time-out if it's not
  // signalled.
  auto future = Future<void>::Create(&relay_);
  base::TimeTicks start = base::TimeTicks::Now();
  ASSERT_FALSE(future->Wait(1000));
  ASSERT_GE(base::TimeTicks::Now() - start, base::Milliseconds(1000));
  // Subsequent wait to a timed-out future can time out again.
  ASSERT_FALSE(future->Wait(1000));
  // Now we signal the future and the final wait should return true.
  thread_.task_runner()->PostTask(
      FROM_HERE,
      base::BindOnce(&FutureTest::SignalCallback, base::Unretained(this),
                     cros::GetFutureCallback(future)));
  ASSERT_TRUE(future->Wait());
}

TEST_F(FutureTest, CancelTest) {
  // A future wait should return false if it's cancelled.  The future is
  // cancelled before it's being waited on.
  auto future = Future<void>::Create(&relay_);
  relay_.CancelAllFutures();
  ASSERT_FALSE(future->Wait());
  // Subsequent wait to a cancelled future should return false.
  ASSERT_FALSE(future->Wait());

  // A future wait should return false if the relay_.CancelAllFutures() has been
  // called.
  future = Future<void>::Create(&relay_);
  thread_.task_runner()->PostTask(
      FROM_HERE,
      base::BindOnce(&FutureTest::SignalCallback, base::Unretained(this),
                     cros::GetFutureCallback(future)));
  ASSERT_FALSE(future->Wait());
}

TEST_F(FutureTest, DelayedCancelTest) {
  // A future wait should return false if it's cancelled.  The future is
  // cancelled after it's being waited on.
  auto future = Future<void>::Create(&relay_);
  thread_.task_runner()->PostDelayedTask(
      FROM_HERE,
      base::BindOnce(&FutureTest::CancelCallback, base::Unretained(this)),
      base::Milliseconds(2000));
  ASSERT_FALSE(future->Wait());
}

TEST_F(FutureTest, FutureRefcountTest) {
  // Create a future and then immediately cancel it via CancellationRelay.
  // Schedule a SignalCallback on another thread with 2 seconds delay such that
  // the callback will run after the main thread has terminated.
  // The wait on main thread should return false immediately.
  // The SignalCallback should successfully run in another thread even after
  // main thread has terminated.
  auto future = Future<void>::Create(&relay_);
  relay_.CancelAllFutures();
  thread_.task_runner()->PostDelayedTask(
      FROM_HERE,
      base::BindOnce(&FutureTest::SignalCallback, base::Unretained(this),
                     cros::GetFutureCallback(future)),
      base::Milliseconds(2000));
  ASSERT_FALSE(future->Wait());
}

}  // namespace cros

int main(int argc, char** argv) {
  base::AtExitManager exit_manager;
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
