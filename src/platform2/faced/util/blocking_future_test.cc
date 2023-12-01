// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "faced/util/blocking_future.h"

#include <memory>
#include <string>

#include <base/functional/bind.h>
#include <base/task/sequenced_task_runner.h>
#include <base/task/thread_pool.h>
#include <base/test/bind.h>
#include <base/test/task_environment.h>
#include <base/threading/thread.h>
#include <gtest/gtest.h>

#include "faced/util/task.h"

namespace faced {
namespace {

class BlockingFutureTest : public ::testing::Test {
 protected:
  base::test::TaskEnvironment task_environment_{
      base::test::TaskEnvironment::TimeSource::MOCK_TIME};
};

TEST_F(BlockingFutureTest, CreateDestroy) {
  BlockingFuture<int> future;
}

TEST_F(BlockingFutureTest, CreateDestroyVoid) {
  BlockingFuture<void> future;
}

TEST_F(BlockingFutureTest, CallBeforeWait) {
  BlockingFuture<int> future;
  future.PromiseCallback().Run(42);
  EXPECT_EQ(future.Wait(), 42);
}

TEST_F(BlockingFutureTest, CallBeforeWaitVoid) {
  BlockingFuture<void> future;
  future.PromiseCallback().Run();
  future.Wait();
}

TEST_F(BlockingFutureTest, CallAfterWait) {
  BlockingFuture<int> future;
  PostToCurrentSequence(base::BindOnce(future.PromiseCallback(), 17));
  EXPECT_EQ(future.Wait(), 17);
}

TEST_F(BlockingFutureTest, CallAfterWaitVoid) {
  BlockingFuture<void> future;
  PostToCurrentSequence(future.PromiseCallback());
  future.Wait();
}

TEST_F(BlockingFutureTest, MultipleArgs) {
  BlockingFuture<int, std::string, std::unique_ptr<int>> future;
  PostToCurrentSequence(
      base::BindOnce(future.PromiseCallback(), 17, "hello", nullptr));

  EXPECT_EQ(future.Wait(), (std::make_tuple(17, "hello", nullptr)));
  EXPECT_EQ(future.value(), (std::make_tuple(17, "hello", nullptr)));
}

TEST_F(BlockingFutureTest, CallOnOtherThread) {
  BlockingFuture<int> future;

  // Complete the future on another thread.
  base::Thread thread("test_thread");
  thread.StartAndWaitForTesting();
  thread.task_runner()->PostTask(
      FROM_HERE, base::BindOnce(future.PromiseCallback(), 1234));

  EXPECT_EQ(future.Wait(), 1234);
}

TEST_F(BlockingFutureTest, Value) {
  BlockingFuture<int> future;
  future.PromiseCallback().Run(42);
  EXPECT_EQ(future.Wait(), 42);

  // Ensure value (and its const version) return the same value again.
  EXPECT_EQ(future.value(), 42);
  const BlockingFuture<int>& const_future = future;
  EXPECT_EQ(const_future.value(), 42);
}

TEST(BlockingFutureDeathTest, WrongSequenceDetected) {
  // Ensure that calls on the wrong thread are detected.
  //
  // The runtime checks are disabled on release builds, so we only
  // run this test when DCHECK is enabled.
  if (!DCHECK_IS_ON()) {
    return;
  }

  // Try to call Wait() on the wrong sequence, and ensure we get an error.
  ASSERT_DEATH(({
                 base::test::TaskEnvironment task_environment_{
                     base::test::TaskEnvironment::TimeSource::MOCK_TIME};
                 BlockingFuture<int> future;

                 // Create a new sequence, and try and run "Wait" from it.
                 scoped_refptr<base::SequencedTaskRunner> task_runner =
                     base::ThreadPool::CreateSequencedTaskRunner({});
                 task_runner->PostTask(FROM_HERE,
                                       base::BindLambdaForTesting(
                                           [&future]() { future.Wait(); }));

                 // Wait for the new sequence to run. We don't expect to
                 // return from here.
                 base::RunLoop loop;
                 loop.Run();
               }),
               "Check failed:.*CalledOnValidSequence");
}

}  // namespace
}  // namespace faced
