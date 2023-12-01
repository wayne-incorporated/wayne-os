// Copyright 2015 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <brillo/message_loops/fake_message_loop.h>

#include <memory>
#include <vector>

#include <base/functional/bind.h>
#include <base/functional/callback_helpers.h>
#include <base/location.h>
#include <base/test/simple_test_clock.h>
#include <gtest/gtest.h>

#include <brillo/message_loops/message_loop.h>

using base::BindOnce;
using base::Time;
using base::TimeDelta;
using std::vector;

namespace brillo {

using TaskId = MessageLoop::TaskId;

class FakeMessageLoopTest : public ::testing::Test {
 protected:
  void SetUp() override {
    loop_.reset(new FakeMessageLoop(nullptr));
    EXPECT_TRUE(loop_.get());
  }
  void TearDown() override { EXPECT_FALSE(loop_->PendingTasks()); }

  base::SimpleTestClock clock_;
  std::unique_ptr<FakeMessageLoop> loop_;
};

TEST_F(FakeMessageLoopTest, CancelTaskInvalidValuesTest) {
  EXPECT_FALSE(loop_->CancelTask(MessageLoop::kTaskIdNull));
  EXPECT_FALSE(loop_->CancelTask(1234));
}

TEST_F(FakeMessageLoopTest, PostDelayedTaskRunsInOrder) {
  vector<int> order;
  loop_->PostDelayedTask(
      BindOnce([](vector<int>* order) { order->push_back(1); }, &order),
      base::Seconds(1));
  loop_->PostDelayedTask(
      BindOnce([](vector<int>* order) { order->push_back(4); }, &order),
      base::Seconds(4));
  loop_->PostDelayedTask(
      BindOnce([](vector<int>* order) { order->push_back(3); }, &order),
      base::Seconds(3));
  loop_->PostDelayedTask(
      BindOnce([](vector<int>* order) { order->push_back(2); }, &order),
      base::Seconds(2));
  // Run until all the tasks are run.
  loop_->Run();
  EXPECT_EQ((vector<int>{1, 2, 3, 4}), order);
}

TEST_F(FakeMessageLoopTest, PostDelayedTaskAdvancesTheTime) {
  Time start = Time::FromInternalValue(1000000);
  clock_.SetNow(start);
  loop_.reset(new FakeMessageLoop(&clock_));
  loop_->PostDelayedTask(base::DoNothing(), base::Seconds(1));
  loop_->PostDelayedTask(base::DoNothing(), base::Seconds(2));
  EXPECT_FALSE(loop_->RunOnce(false));
  // If the callback didn't run, the time shouldn't change.
  EXPECT_EQ(start, clock_.Now());

  // If we run only one callback, the time should be set to the time that
  // callack ran.
  EXPECT_TRUE(loop_->RunOnce(true));
  EXPECT_EQ(start + base::Seconds(1), clock_.Now());

  // If the clock is advanced manually, we should be able to run the
  // callback without blocking, since the firing time is in the past.
  clock_.SetNow(start + base::Seconds(3));
  EXPECT_TRUE(loop_->RunOnce(false));
  // The time should not change even if the callback is due in the past.
  EXPECT_EQ(start + base::Seconds(3), clock_.Now());
}

TEST_F(FakeMessageLoopTest, PendingTasksTest) {
  loop_->PostDelayedTask(base::DoNothing(), base::Seconds(1));
  EXPECT_TRUE(loop_->PendingTasks());
  loop_->Run();
}

}  // namespace brillo
