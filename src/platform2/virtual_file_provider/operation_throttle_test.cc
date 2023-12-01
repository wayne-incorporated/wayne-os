// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <base/functional/bind.h>
#include <base/location.h>
#include <base/threading/platform_thread.h>
#include <base/threading/thread.h>
#include <gtest/gtest.h>

#include "virtual_file_provider/operation_throttle.h"

namespace virtual_file_provider {

namespace {

constexpr base::TimeDelta kTestTimeout = base::Milliseconds(100);

}  // namespace

TEST(OperationThrottleTest, OnlyOneTask) {
  OperationThrottle throttle(1);
  auto operation1 = throttle.StartOperation();
}

TEST(OperationThrottleTest, TwoTasksUnderLimit) {
  // Start operation #1 on this thread.
  OperationThrottle throttle(2);
  auto operation1 = throttle.StartOperation();

  // Start operation #2 on another thread. This shouldn't get blocked.
  bool done = false;
  base::Thread thread("Test thread");
  ASSERT_TRUE(thread.Start());
  thread.task_runner()->PostTask(
      FROM_HERE, base::BindOnce(
                     [](OperationThrottle* throttle, bool* done) {
                       auto operation2 = throttle->StartOperation();
                       *done = true;
                     },
                     &throttle, &done));

  // Wait for operation #2 to finish.
  thread.Stop();
  EXPECT_TRUE(done);
}

TEST(OperationThrottleTest, TwoTasksOverLimit) {
  // Start operation #1 on this thread.
  OperationThrottle throttle(1);
  auto operation1 = throttle.StartOperation();

  // Start operation #2 on another thread. This should get blocked.
  bool done = false;
  base::Thread thread("Test thread");
  ASSERT_TRUE(thread.Start());
  thread.task_runner()->PostTask(
      FROM_HERE, base::BindOnce(
                     [](OperationThrottle* throttle, bool* done) {
                       auto operation2 = throttle->StartOperation();
                       *done = true;
                     },
                     &throttle, &done));

  // Wait for operation #2 to get blocked.
  base::PlatformThread::Sleep(kTestTimeout);
  EXPECT_FALSE(done);

  // Finish the operation #1 to unblock #2.
  operation1.reset();

  // Wait for operation #2 to finish.
  thread.Stop();
  EXPECT_TRUE(done);
}

}  // namespace virtual_file_provider
