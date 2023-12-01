// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <atomic>
#include <memory>

#include <base/functional/callback.h>
#include <base/rand_util.h>
#include <base/task/sequenced_task_runner.h>
#include <base/task/thread_pool.h>
#include <base/test/task_environment.h>
#include <base/time/time.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "missive/util/refcounted_closure_list.h"
#include "missive/util/test_support_callbacks.h"

using ::testing::Eq;

namespace reporting {
namespace {

class RefCountedClosureListTest : public ::testing::Test {
 protected:
  class Worker {
   public:
    Worker(std::atomic<size_t>* count,
           const scoped_refptr<RefCountedClosureList> callback)
        : count_(count), callback_(callback) {}
    Worker(const Worker&) = delete;
    Worker& operator=(const Worker&) = delete;
    ~Worker() = default;  // Here we drop the reference to closure list!

    void Run() { (*count_)--; }

   private:
    std::atomic<size_t>* const count_;
    const scoped_refptr<RefCountedClosureList> callback_;
  };

  base::test::TaskEnvironment task_environment_{
      base::test::TaskEnvironment::TimeSource::MOCK_TIME};

  scoped_refptr<base::SequencedTaskRunner> task_runner_;
};

TEST_F(RefCountedClosureListTest, BasicUsageTest) {
  static constexpr size_t kNumIterations = 50;
  static constexpr size_t kNumTasksFactor = 3;
  for (size_t i = 0; i < kNumIterations; ++i) {
    const size_t num_tasks = i * kNumTasksFactor + 1;
    std::atomic<size_t> count{num_tasks};
    {
      test::TestCallbackAutoWaiter waiter;

      {
        const auto closure_list = base::MakeRefCounted<RefCountedClosureList>(
            base::SequencedTaskRunner::GetCurrentDefault());
        closure_list->RegisterCompletionCallback(base::BindOnce(
            &test::TestCallbackAutoWaiter::Signal, base::Unretained(&waiter)));
        for (size_t t = 0; t < num_tasks; ++t) {
          auto worker = std::make_unique<Worker>(&count, closure_list);
          base::ThreadPool::PostDelayedTask(
              FROM_HERE, {base::TaskPriority::BEST_EFFORT, base::MayBlock()},
              base::BindOnce(&Worker::Run, std::move(worker)),
              base::Seconds(1.0 + base::RandDouble()));
        }
        ASSERT_THAT(count.load(), Eq(num_tasks));
        // Drop the original reference to `closure_list`.
        // After that only Workers will hold it.
      }

      // Forward time to trigger workers to run.
      task_environment_.FastForwardBy(base::Seconds(2));
      // Wait for the signal.
    }
    ASSERT_THAT(count.load(), Eq(0u));
  }
}

}  // namespace
}  // namespace reporting
