// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MISSIVE_SCHEDULER_SCHEDULER_H_
#define MISSIVE_SCHEDULER_SCHEDULER_H_

#include <memory>
#include <queue>
#include <vector>

#include <base/sequence_checker.h>
#include <base/task/sequenced_task_runner.h>

#include "missive/util/status.h"

namespace reporting {

// Scheduler manages the running jobs ensuring that we don't overload the
// system memory. It runs in three modes:
// 1. NORMAL: In normal mode Scheduler will schedule up to 5 concurrent jobs
//    keeping the rest in the |jobs_queue_|.
// 2. REDUCED: In reduced mode Scheduler will schedule up to 2 concurrent jobs,
//    although any currently running jobs are allowed to finish.
// 3. OFF: In this mode Scheduler will enqueue no new jobs, all currently
//    running jobs are allowed to finish. Jobs in the |jobs_queue_| will be
//    cancelled.
class Scheduler {
 public:
  // A Job is a unit of work with a common interface. |StartImpl| needs to be
  // overridden to implement the specific job functionality ending up calling
  // |Finish|. To protect work from being corrupted, most of the public
  // functions only work when the job is in the NOT_RUNNING state.
  // It is likely to have weak pointer factory, so it requires a special
  // smart pointer Job::SmartPtr returned by a factory method rather than
  // raw constructor.
  class Job {
   public:
    // Smart pointer class. Job objects should never be created by 'new' - only
    // by a factory method returning such a smart pointer.
    template <typename T>
    using SmartPtr = std::unique_ptr<T, base::OnTaskRunnerDeleter>;

    // States the Job can be in.
    enum class JobState {
      // Initial state of a Job, no methods have been called and it is waiting
      // for the Scheduler to Start it.
      NOT_RUNNING,
      // Protected state of the job, only the Job itself can move to another
      // state.
      RUNNING,
      // Successful terminal state of the Job.
      COMPLETED,
      // Unsuccessful terminal state of the Job.
      CANCELLED,
    };

    // JobDelegate is responsible for sending responses to any
    // listeners.
    class JobDelegate {
     public:
      JobDelegate() = default;
      virtual ~JobDelegate() = default;

     private:
      // Job should be the only class calling Complete or Cancel;
      friend Job;

      // Complete and Cancel will be called by Job::Finish and should notify
      // listeners of the Jobs completion.
      virtual Status Complete() = 0;
      virtual Status Cancel(Status status) = 0;
    };

    virtual ~Job();

    Job(const Job&) = delete;
    Job& operator=(const Job&) = delete;

    // If the job is not currently NOT_RUNNING, will simply return.
    void Start(base::OnceCallback<void(Status)> complete_cb);

    // If the job is not currently NOT_RUNNING, will simply return.
    // Cancel move the job to the CANCELLED state and call |cancel_callback_|
    // with the provided Status.
    // Job cannot be started after a cancellation, so care must be taken to only
    // cancel when appropriate.
    Status Cancel(Status status);

    // Returns the |job_state_| at the time of calling.
    JobState GetJobState() const;

   protected:
    // Constructor to be used by subcalss constructors only.
    Job(std::unique_ptr<JobDelegate> job_response_delegate,
        scoped_refptr<base::SequencedTaskRunner> sequenced_task_runner);

    // StartImpl should perform the unit of work for the Job and call Finish
    // upon completion.
    virtual void StartImpl() = 0;

    // Finish will call either report_completion_callback_ or cancel_callback_
    // based on the provided status. In addition it will also update job_state_
    // appropriately.
    void Finish(Status status);

    // Checks that we are on a right sequenced task runner.
    void CheckValidSequence() const;

    // Accesses sequenced task runner assigned to the Job.
    scoped_refptr<base::SequencedTaskRunner> sequenced_task_runner() const;

    std::unique_ptr<JobDelegate> job_response_delegate_;

   private:
    // Must be first members in the class.
    const scoped_refptr<base::SequencedTaskRunner> sequenced_task_runner_;
    SEQUENCE_CHECKER(sequence_checker_);

    std::atomic<JobState> job_state_{JobState::NOT_RUNNING};

    // |complete_cb_| is set by |Start| and called by |Finish|.
    base::OnceCallback<void(Status)> complete_cb_;
  };

  // SchedulerObserver allows introspection into the goings on of the Scheudler.
  class SchedulerObserver {
   public:
    enum class Notification {
      // A job has successfully been enqueued.
      ACCEPTED_JOB,

      // A job was rejected from enqueuing, and cancelled.
      REJECTED_JOB,

      // A job attempted to acquire a JobBlocker and was unable to do so.
      BLOCKED_JOB,

      // A job was started.
      STARTED_JOB,

      // Set if a job is successfully completed.
      SUCCESSFUL_COMPLETION,

      // Set if a job was unsuccessful in completion.
      UNSUCCESSFUL_COMPLETION,

      // A job was cancelled due to memory pressure.
      MEMORY_PRESSURE_CANCELLATION,
    };

    SchedulerObserver() = default;
    ~SchedulerObserver() = default;

    SchedulerObserver(const SchedulerObserver& other) = delete;
    SchedulerObserver& operator=(const SchedulerObserver& other) = delete;

    virtual void Notify(Notification notification) = 0;
  };

  Scheduler();
  ~Scheduler();

  void AddObserver(SchedulerObserver* observer);
  void NotifyObservers(SchedulerObserver::Notification notification);

  // EnqueueJob will store the job in the |job_queue_|, and it will be executed
  // as long as system memory remains above CRITICAL.
  void EnqueueJob(Job::SmartPtr<Job> job);

 private:
  class JobContext;
  class JobBlocker;
  class JobSemaphore;

  void StartJobs();
  void MaybeStartNextJob(std::unique_ptr<JobBlocker> job_blocker);
  void RunJob(std::unique_ptr<JobBlocker> job_blocker,
              Job::SmartPtr<Job> job_result);

  void ClearQueue();

  // TODO(1174889) Currently unused, once resourced implements
  // MemoryPressureLevels update. Also initialize JobSemaphorePool at
  // TaskLimit::OFF instead of NORMAL, so that it is off until we know the
  // memory pressure level.
  // void UpdateMemoryPressureLevel(
  //     base::MemoryPressureListener::MemoryPressureLevel
  //     memory_pressure_level);

  // Must be the first member of the class.
  scoped_refptr<base::SequencedTaskRunner> sequenced_task_runner_;
  SEQUENCE_CHECKER(sequence_checker_);

  std::unique_ptr<JobSemaphore> job_semaphore_;
  std::queue<Job::SmartPtr<Job>> jobs_queue_;

  std::vector<SchedulerObserver*> observers_;
};

}  // namespace reporting

#endif  // MISSIVE_SCHEDULER_SCHEDULER_H_
