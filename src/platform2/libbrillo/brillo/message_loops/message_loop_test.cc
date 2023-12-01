// Copyright 2015 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <brillo/message_loops/message_loop.h>

// These are the common tests for all the brillo::MessageLoop implementations
// that should conform to this interface's contracts. For extra
// implementation-specific tests see the particular implementation unittests in
// the *_test.cc files.

#include <memory>
#include <vector>

#include <base/functional/bind.h>
#include <base/functional/callback_helpers.h>
#include <base/location.h>
#include <base/message_loop/message_pump_type.h>
#include <base/posix/eintr_wrapper.h>
#include <base/task/single_thread_task_executor.h>
#include <gtest/gtest.h>

#include <brillo/message_loops/base_message_loop.h>
#include <brillo/message_loops/message_loop_utils.h>
#include <brillo/unittest_utils.h>

using base::BindOnce;
using base::BindRepeating;
using base::TimeDelta;

namespace {

// Convenience functions for passing to base::Bind{Once,Repeating}.
void SetToTrue(bool* b) {
  *b = true;
}

bool ReturnBool(bool* b) {
  return *b;
}

}  // namespace

namespace brillo {

using TaskId = MessageLoop::TaskId;

template <typename T>
class MessageLoopTest : public ::testing::Test {
 protected:
  void SetUp() override {
    MessageLoopSetUp();
    EXPECT_TRUE(this->loop_.get());
  }

  std::unique_ptr<base::SingleThreadTaskExecutor> base_loop_;

  std::unique_ptr<MessageLoop> loop_;

 private:
  // These MessageLoopSetUp() methods are used to setup each MessageLoop
  // according to its constructor requirements.
  void MessageLoopSetUp();
};

template <>
void MessageLoopTest<BaseMessageLoop>::MessageLoopSetUp() {
  base_loop_.reset(
      new base::SingleThreadTaskExecutor(base::MessagePumpType::IO));
  loop_.reset(new BaseMessageLoop(base_loop_->task_runner()));
  loop_->SetAsCurrent();
}

// This setups gtest to run each one of the following TYPED_TEST test cases on
// on each implementation.
typedef ::testing::Types<BaseMessageLoop> MessageLoopTypes;
TYPED_TEST_SUITE(MessageLoopTest, MessageLoopTypes);

TYPED_TEST(MessageLoopTest, CancelTaskInvalidValuesTest) {
  EXPECT_FALSE(this->loop_->CancelTask(MessageLoop::kTaskIdNull));
  EXPECT_FALSE(this->loop_->CancelTask(1234));
}

TYPED_TEST(MessageLoopTest, PostTaskTest) {
  bool called = false;
  TaskId task_id =
      this->loop_->PostTask(FROM_HERE, BindOnce(&SetToTrue, &called));
  EXPECT_NE(MessageLoop::kTaskIdNull, task_id);
  MessageLoopRunMaxIterations(this->loop_.get(), 100);
  EXPECT_TRUE(called);
}

// Tests that we can cancel tasks right after we schedule them.
TYPED_TEST(MessageLoopTest, PostTaskCancelledTest) {
  bool called = false;
  TaskId task_id =
      this->loop_->PostTask(FROM_HERE, BindOnce(&SetToTrue, &called));
  EXPECT_TRUE(this->loop_->CancelTask(task_id));
  MessageLoopRunMaxIterations(this->loop_.get(), 100);
  EXPECT_FALSE(called);
  // Can't remove a task you already removed.
  EXPECT_FALSE(this->loop_->CancelTask(task_id));
}

TYPED_TEST(MessageLoopTest, PostDelayedTaskRunsEventuallyTest) {
  bool called = false;
  TaskId task_id = this->loop_->PostDelayedTask(
      FROM_HERE, BindOnce(&SetToTrue, &called), base::Milliseconds(50));
  EXPECT_NE(MessageLoop::kTaskIdNull, task_id);
  MessageLoopRunUntil(this->loop_.get(), base::Seconds(10),
                      BindRepeating(&ReturnBool, &called));
  // Check that the main loop finished before the 10 seconds timeout, so it
  // finished due to the callback being called and not due to the timeout.
  EXPECT_TRUE(called);
}

// Test that you can call the overloaded version of PostDelayedTask from
// MessageLoop. This is important because only one of the two methods is
// virtual, so you need to unhide the other when overriding the virtual one.
TYPED_TEST(MessageLoopTest, PostDelayedTaskWithoutLocation) {
  this->loop_->PostDelayedTask(base::DoNothing(), TimeDelta());
  EXPECT_EQ(1, MessageLoopRunMaxIterations(this->loop_.get(), 100));
}

// Test that we can cancel the task we are running, and should just fail.
TYPED_TEST(MessageLoopTest, DeleteTaskFromSelf) {
  bool cancel_result = true;  // We would expect this to be false.
  TaskId task_id;
  task_id = this->loop_->PostTask(
      FROM_HERE,
      BindOnce(
          [](bool* cancel_result, MessageLoop* loop, TaskId* task_id) {
            *cancel_result = loop->CancelTask(*task_id);
          },
          &cancel_result, this->loop_.get(), &task_id));
  EXPECT_EQ(1, MessageLoopRunMaxIterations(this->loop_.get(), 100));
  EXPECT_FALSE(cancel_result);
}

}  // namespace brillo
