// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_UTILS_RESOURCE_QUEUE_H_
#define DIAGNOSTICS_CROS_HEALTHD_UTILS_RESOURCE_QUEUE_H_

#include <queue>

#include <base/functional/callback_forward.h>
#include <base/functional/callback_helpers.h>
#include <base/memory/weak_ptr.h>

// Calls the next job in queue when the previous job has finished running.
//
// It takes a callback / callbacks which is guaranteed to be called in the order
// that it is enqueued, and at most one job will be running at a given time.
//
// To add a job, call |Enqueue| to add a callback into the queue. The callback
// should accept a |ReleaseLock| callback, and run the callback when the
// resource is done using and the next job can run.
//
// Caveat:
//   1. This is not thread-safe.
//   2. The |ReleaseLock| callback is passed as a ScopedClosureRunner, so even
//      if |ReleaseLock| is not explicitly called the callback should still be
//      ran.
//
// Example: Basic usage:
// class Job {
//  public:
//   Job() = default;
//   Job(const Job&) = delete;
//   const Job& operator=(const Job&) = delete;
//   ~Job() = default;
//
//   // Add a job into the queue.
//   void Request( ResourceQueue* queue) {
//     queue->Enqueue(
//         base::BindOnce(&Job::Run, weak_ptr_factory_.GetWeakPtr()));
//   }
//
//  private:
//   void Run(base::ScopedClosureRunner release_resource_cb) {
//     DoStuff();
//     std::move(release_resource_cb).RunAndReset();
//   }
//
//   // Must be the last class member.
//   base::WeakPtrFactory<Job> weak_ptr_factory_{this};
// };

namespace diagnostics {

class ResourceQueue {
 public:
  ResourceQueue();
  ResourceQueue(const ResourceQueue&) = delete;
  const ResourceQueue& operator=(const ResourceQueue&) = delete;
  ~ResourceQueue();

  // Each job should accept an OnFinish callback to be called when they finish
  // using the resource.
  using OnResourceReadyCallback =
      base::OnceCallback<void(base::ScopedClosureRunner)>;

  // Pushes a job into the queue.
  void Enqueue(OnResourceReadyCallback cb);

 private:
  // Test the resource queue to see if a new job can be run.
  void TryToRunNextTask();

  // A function to be run when each job finishes to unlock and test for resource
  // queue.
  void ReleaseLock();

  // A boolean used as lock to determine whether a resource intensive
  // job can be ran. This is not thread safe.
  bool is_locked_;

  // A queue containing pending jobs for the resource queue.
  std::queue<OnResourceReadyCallback> resource_queue_;

  // Must be the last class member.
  base::WeakPtrFactory<ResourceQueue> weak_ptr_factory_{this};
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_UTILS_RESOURCE_QUEUE_H_
