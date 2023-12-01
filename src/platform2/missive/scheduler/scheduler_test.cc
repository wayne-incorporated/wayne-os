// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <utility>

#include <base/check_op.h>
#include <base/functional/bind.h>
#include <base/memory/weak_ptr.h>
#include <base/run_loop.h>
#include <base/task/bind_post_task.h>
#include <base/task/sequenced_task_runner.h>
#include <base/task/task_traits.h>
#include <base/task/thread_pool.h>
#include <base/test/task_environment.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "missive/scheduler/scheduler.h"
#include "missive/util/test_support_callbacks.h"

using ::testing::_;
using ::testing::Eq;
using ::testing::Ge;

namespace reporting {
namespace {

class FakeJob : public Scheduler::Job {
 public:
  using StartCallback = base::OnceCallback<void()>;
  using ReportCompletionCallback = base::OnceCallback<Status()>;
  using CancelCallback = base::OnceCallback<Status(Status)>;

  class FakeJobDelegate : public Scheduler::Job::JobDelegate {
   public:
    FakeJobDelegate(ReportCompletionCallback report_completion_callback,
                    CancelCallback cancel_callback)
        : report_completion_callback_(std::move(report_completion_callback)),
          cancel_callback_(std::move(cancel_callback)) {}

   private:
    Status Complete() override {
      return std::move(report_completion_callback_).Run();
    }

    Status Cancel(Status status) override {
      return std::move(cancel_callback_).Run(status);
    }

    ReportCompletionCallback report_completion_callback_;
    CancelCallback cancel_callback_;
  };

  static SmartPtr<FakeJob> Create(
      std::unique_ptr<FakeJobDelegate> fake_job_delegate) {
    scoped_refptr<base::SequencedTaskRunner> sequenced_task_runner =
        base::ThreadPool::CreateSequencedTaskRunner(
            {base::TaskPriority::BEST_EFFORT, base::MayBlock()});
    return std::unique_ptr<FakeJob, base::OnTaskRunnerDeleter>(
        new FakeJob(std::move(fake_job_delegate), sequenced_task_runner),
        base::OnTaskRunnerDeleter(sequenced_task_runner));
  }

  void SetFinishStatus(Status status) {
    DCHECK_EQ(GetJobState(), JobState::NOT_RUNNING)
        << "Called after the job started";
    finish_status_ = status;
  }

 protected:
  void StartImpl() override {
    // Pause for 1 sec, to make sure only 5 FakeJobs can launch right away,
    // and the rest get delayed.
    base::ThreadPool::PostDelayedTask(
        FROM_HERE, {base::TaskPriority::BEST_EFFORT, base::MayBlock()},
        base::BindPostTask(
            sequenced_task_runner(),
            base::BindOnce(&FakeJob::Finish, weak_ptr_factory_.GetWeakPtr(),
                           finish_status_)),
        base::Seconds(1));
  }

 private:
  FakeJob(std::unique_ptr<FakeJobDelegate> fake_job_delegate,
          scoped_refptr<base::SequencedTaskRunner> sequenced_task_runner)
      : Job(std::move(fake_job_delegate), sequenced_task_runner) {}

  Status finish_status_{Status::StatusOK()};

  base::WeakPtrFactory<FakeJob> weak_ptr_factory_{this};
};

class JobTest : public ::testing::Test {
 public:
  JobTest() = default;

  void SetUp() override {
    report_completion_callback_ = base::BindRepeating(
        [](std::atomic<size_t>* completion_counter,
           test::TestCallbackWaiter* complete_waiter) {
          *completion_counter += 1u;
          complete_waiter->Signal();
          return Status::StatusOK();
        },
        &completion_counter_, &complete_waiter_);

    cancel_callback_ = base::BindRepeating(
        [](std::atomic<size_t>* cancel_counter,
           test::TestCallbackWaiter* complete_waiter, Status status) {
          EXPECT_TRUE(!status.ok());
          *cancel_counter += 1u;
          complete_waiter->Signal();
          return Status::StatusOK();
        },
        &cancel_counter_, &complete_waiter_);
  }

 protected:
  base::test::TaskEnvironment task_environment_{
      base::test::TaskEnvironment::TimeSource::MOCK_TIME};

  std::atomic<size_t> completion_counter_{0};
  std::atomic<size_t> cancel_counter_{0};
  test::TestCallbackWaiter complete_waiter_;
  base::RepeatingCallback<Status()> report_completion_callback_;
  base::RepeatingCallback<Status(Status)> cancel_callback_;
};

TEST_F(JobTest, WillStartOnceWithOKStatusAndReportCompletion) {
  auto delegate = std::make_unique<FakeJob::FakeJobDelegate>(
      report_completion_callback_, cancel_callback_);
  auto job = FakeJob::Create(std::move(delegate));

  {
    test::TestEvent<Status> start_event;
    complete_waiter_.Attach();
    job->Start(start_event.cb());
    task_environment_.FastForwardBy(base::Seconds(1));
    const auto status = start_event.result();
    EXPECT_OK(status) << status;
    complete_waiter_.Wait();
  }

  // The job should have finished successfully.
  EXPECT_THAT(completion_counter_, Eq(1u));
  EXPECT_THAT(cancel_counter_, Eq(0u));
  EXPECT_THAT(job->GetJobState(), Eq(Scheduler::Job::JobState::COMPLETED));

  // Now that the job has completed successfully, it shouldn't be startable, or
  // cancellable.
  {
    test::TestEvent<Status> start_event;
    job->Start(start_event.cb());
    task_environment_.FastForwardBy(base::Seconds(1));
    const auto status = start_event.result();
    EXPECT_FALSE(status.ok());
  }

  // Nothing should have changed from before.
  EXPECT_EQ(completion_counter_, 1u);
  EXPECT_EQ(cancel_counter_, 0u);
  EXPECT_EQ(job->GetJobState(), Scheduler::Job::JobState::COMPLETED);

  EXPECT_FALSE(job->Cancel(Status(error::INTERNAL, "Failing for tests")).ok());

  // Nothing should have changed from before.
  EXPECT_EQ(completion_counter_, 1u);
  EXPECT_EQ(cancel_counter_, 0u);
  EXPECT_EQ(job->GetJobState(), Scheduler::Job::JobState::COMPLETED);
}

TEST_F(JobTest, CancelsWhenJobFails) {
  auto job = FakeJob::Create(std::make_unique<FakeJob::FakeJobDelegate>(
      report_completion_callback_, cancel_callback_));
  job->SetFinishStatus(Status(error::INTERNAL, "Failing for tests"));

  {
    complete_waiter_.Attach();
    test::TestEvent<Status> start_event;
    job->Start(start_event.cb());
    task_environment_.FastForwardBy(base::Seconds(1));
    const auto status = start_event.result();
    EXPECT_OK(status) << status;
    complete_waiter_.Wait();
  }

  // The job should have finished successfully.
  EXPECT_EQ(completion_counter_, 0u);
  EXPECT_EQ(cancel_counter_, 1u);
  EXPECT_EQ(job->GetJobState(), Scheduler::Job::JobState::CANCELLED);
}

TEST_F(JobTest, WillNotStartWithNonOKStatusAndCancels) {
  auto job = FakeJob::Create(std::make_unique<FakeJob::FakeJobDelegate>(
      report_completion_callback_, cancel_callback_));

  EXPECT_TRUE(job->Cancel(Status(error::INTERNAL, "Failing For Tests")).ok());

  test::TestEvent<Status> start_event;
  job->Start(start_event.cb());
  task_environment_.FastForwardBy(base::Seconds(1));
  const auto status = start_event.result();
  EXPECT_FALSE(status.ok());
}

class TestSchedulerObserver : public Scheduler::SchedulerObserver {
 public:
  void Notify(Notification notification) override {
    switch (notification) {
      case (Notification::ACCEPTED_JOB):
        accepted_jobs_ += 1u;
        break;
      case (Notification::REJECTED_JOB):
        rejected_jobs_ += 1u;
        break;
      case (Notification::BLOCKED_JOB):
        blocked_jobs_ += 1u;
        break;
      case (Notification::STARTED_JOB):
        started_jobs_ += 1u;
        break;
      case (Notification::SUCCESSFUL_COMPLETION):
        successful_jobs_ += 1u;
        break;
      case (Notification::UNSUCCESSFUL_COMPLETION):
        unsuccessful_jobs_ += 1u;
        break;
      case (Notification::MEMORY_PRESSURE_CANCELLATION):
        memory_pressure_cancelled_jobs_ += 1u;
        break;
    }
  }

  std::atomic<size_t> accepted_jobs_{0u};
  std::atomic<size_t> rejected_jobs_{0u};
  std::atomic<size_t> blocked_jobs_{0u};
  std::atomic<size_t> started_jobs_{0u};
  std::atomic<size_t> successful_jobs_{0u};
  std::atomic<size_t> unsuccessful_jobs_{0u};
  std::atomic<size_t> memory_pressure_cancelled_jobs_{0u};
};

class SchedulerTest : public ::testing::Test {
 public:
  SchedulerTest() = default;

  void SetUp() override { scheduler_.AddObserver(&scheduler_observer_); }

  void TearDown() override {
    // Let everything ongoing to finish.
    task_environment_.RunUntilIdle();
  }

 protected:
  base::test::TaskEnvironment task_environment_{
      base::test::TaskEnvironment::TimeSource::MOCK_TIME};
  Scheduler scheduler_;
  TestSchedulerObserver scheduler_observer_;
};

TEST_F(SchedulerTest, SchedulesAndRunsJobs) {
  // Many tests rely on "half" of jobs failing. For this reason kNumJobs should
  // be even.
  const size_t kNumJobs = 10u;

  std::atomic<size_t> completion_counter{0};
  std::atomic<size_t> cancel_counter{0};
  {
    test::TestCallbackAutoWaiter complete_waiter;

    const auto report_completion_callback = base::BindRepeating(
        [](std::atomic<size_t>* counter, test::TestCallbackWaiter* waiter) {
          *counter += 1;
          waiter->Signal();
          return Status::StatusOK();
        },
        &completion_counter, &complete_waiter);

    const auto cancel_callback = base::BindRepeating(
        [](std::atomic<size_t>* counter, test::TestCallbackWaiter* waiter,
           Status status) {
          *counter += 1;
          waiter->Signal();
          return Status(error::INTERNAL, "Failing for tests");
        },
        &cancel_counter, &complete_waiter);

    complete_waiter.Attach(kNumJobs);
    for (size_t i = 0; i < kNumJobs; i++) {
      base::ThreadPool::PostTask(
          FROM_HERE, {base::TaskPriority::BEST_EFFORT, base::MayBlock()},
          base::BindOnce(
              [](size_t i, Scheduler* scheduler,
                 base::RepeatingCallback<Status()> report_completion_callback,
                 base::RepeatingCallback<Status(Status)> cancel_callback) {
                auto job =
                    FakeJob::Create(std::make_unique<FakeJob::FakeJobDelegate>(
                        report_completion_callback, cancel_callback));
                if (i % 2u == 0) {
                  job->SetFinishStatus(
                      Status(error::INTERNAL, "Failing for tests"));
                }
                scheduler->EnqueueJob(std::move(job));
              },
              i, base::Unretained(&scheduler_), report_completion_callback,
              cancel_callback));
    }
    complete_waiter.Signal();
    // Jobs are going to run on task limit = 5 threads in parallel.
    task_environment_.FastForwardBy(base::Seconds(2));
  }
  task_environment_.RunUntilIdle();

  ASSERT_THAT(scheduler_observer_.accepted_jobs_, Eq(kNumJobs));

  // We should have at least (kNumJobs - 1) blocked:
  // First we schedule kNumJobs=10 jobs and task limit is 5, <=5 jobs can be
  // started immediately and the rest >=5 are blocked. Then after each job is
  // finished, the new one can start, and for all of them but the last there are
  // still blocked jobs in the queue, while after the last one is started, no
  // jobs are blocked. Hence (kNumJobs/2 + kNumJobs/2 - 1).
  EXPECT_THAT(scheduler_observer_.blocked_jobs_, Ge(kNumJobs - 1));

  // We should have exactly kNumJobs started.
  EXPECT_THAT(scheduler_observer_.started_jobs_, Eq(kNumJobs));

  // Half the jobs should complete successfully.
  EXPECT_THAT(scheduler_observer_.successful_jobs_, Eq(kNumJobs / 2u));

  // Half the jobs should complete unsuccessfully.
  EXPECT_THAT(scheduler_observer_.unsuccessful_jobs_, Eq(kNumJobs / 2u));

  // TODO(1174889) Once memory pressure is enabled, update tests to cause memory
  // pressure issues and ensure jobs are cancelled. At that time we can also
  // test rejected jobs.
  EXPECT_THAT(scheduler_observer_.rejected_jobs_, Eq(0u));

  // Half the jobs should have been cancelled, while the other half should have
  // completed successfully.
  EXPECT_THAT(completion_counter, Eq(kNumJobs / 2u));
  EXPECT_THAT(cancel_counter, Eq(kNumJobs / 2u));
}

// TODO(b/193577465): Add test for Scheduler being destructed before all jobs
// have been run. This might require changes in Scheduler itself.

}  // namespace
}  // namespace reporting
