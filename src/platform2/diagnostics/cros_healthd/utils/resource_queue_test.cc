// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <string>
#include <utility>

#include <base/functional/bind.h>
#include <base/functional/callback_forward.h>
#include <base/functional/callback_helpers.h>
#include <base/task/thread_pool.h>
#include <base/test/test_timeouts.h>
#include <base/test/task_environment.h>
#include <gtest/gtest.h>
#include <mojo/public/cpp/bindings/callback_helpers.h>

#include "diagnostics/cros_healthd/utils/resource_queue.h"

namespace diagnostics {
namespace {

class Job {
 public:
  Job() = default;
  Job(const Job&) = delete;
  const Job& operator=(const Job&) = delete;
  ~Job() = default;

  // static variables used to track the job order.
  static inline int started;
  static inline int finished;

  // Add a job into the queue.
  void Request(int index, ResourceQueue* queue) {
    queue->Enqueue(
        base::BindOnce(&Job::Run, weak_ptr_factory_.GetWeakPtr(), index));
  }

  // Finish running the job and release the resource.
  void Release() {
    finished += 1;
    std::move(release_resource_cb_).RunAndReset();
  }

 private:
  // Run the job and check that no other job is currently running and the job is
  // ran at the expected order.
  void Run(int index, base::ScopedClosureRunner release_resource_cb) {
    // Ensure no other jobs are running and the job is ran in the correct order.
    EXPECT_EQ(started, finished);
    EXPECT_EQ(started, index);
    started += 1;
    release_resource_cb_ = std::move(release_resource_cb);
  }

  // Callback to be ran when the resource can be released.
  base::ScopedClosureRunner release_resource_cb_;

  // Must be the last class member.
  base::WeakPtrFactory<Job> weak_ptr_factory_{this};
};

class ResourceQueueTest : public testing::Test {
 protected:
  ResourceQueue resource_queue_;

 private:
  base::test::TaskEnvironment task_environment_{
      base::test::TaskEnvironment::TimeSource::MOCK_TIME};
};

// Test that we can run one job.
TEST_F(ResourceQueueTest, RunOneJobs) {
  Job::started = 0;
  Job::finished = 0;
  Job job1;
  job1.Request(0, &resource_queue_);
  job1.Release();
  EXPECT_EQ(Job::finished, 1);
}

// Test that we can run multiple jobs.
TEST_F(ResourceQueueTest, RunMultipleJobs) {
  Job::started = 0;
  Job::finished = 0;
  Job job1;
  Job job2;
  job1.Request(0, &resource_queue_);
  job1.Release();
  job2.Request(1, &resource_queue_);
  job2.Release();
  EXPECT_EQ(Job::finished, 2);
}

// Test that we can run multiple interleaved jobs in sequence.
TEST_F(ResourceQueueTest, RunInterleavedJobs) {
  Job::started = 0;
  Job::finished = 0;
  Job job1;
  Job job2;
  job1.Request(0, &resource_queue_);
  job2.Request(1, &resource_queue_);
  job1.Release();
  job2.Release();
  EXPECT_EQ(Job::finished, 2);
}

}  // namespace
}  // namespace diagnostics
