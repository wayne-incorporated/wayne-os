// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBBRILLO_BRILLO_GRPC_GRPC_COMPLETION_QUEUE_DISPATCHER_H_
#define LIBBRILLO_BRILLO_GRPC_GRPC_COMPLETION_QUEUE_DISPATCHER_H_

#include <map>
#include <memory>

#include <base/functional/callback.h>
#include <base/memory/ref_counted.h>
#include <base/sequence_checker_impl.h>
#include <base/threading/simple_thread.h>
#include <brillo/brillo_export.h>
#include <grpcpp/grpcpp.h>

namespace base {
class SequencedTaskRunner;
}

namespace brillo {
namespace internal {
class MonitoringThreadDelegate;
}

// A GrpcCompletionQueueDispatcher monitors a grpc |CompletionQueue| for
// signalled events and posts tasks to a |SequencedTaskRunner| as a result.
// It uses a background thread to block on the |CompletionQueue|'s next event in
// a loop because this is a blocking operation.
// The |GrpcCompletionQueueDispatcher| may be constructed from anywhere, but its
// public methods should only be called on the same task runner that was passed
// to its constructor.
// This class assumes that every tag that is received from the |CompletionQueue|
// is expected, i.e. that |RegisterTag| has been called for every tag.
class BRILLO_EXPORT GrpcCompletionQueueDispatcher {
 public:
  // Callbacks of this type will be called on the task runner passed
  // to the constructor when an expected event is available on the monitored
  // |CompletionQueue|. |ok| has an operation-specific meaning, see grpc's
  // |CompletionQueue::Next| documentation for details.
  using TagAvailableCallback = base::OnceCallback<void(bool ok)>;

  // The constructed object will monitor |completion_queue| and post tasks to
  // |task_runner|. Note that the |GrpcCompletionQueueDispatcher| only
  // starts monitoring the |completion_queue| when |Start| is called.
  // |completion_queue| should outlive this object.
  GrpcCompletionQueueDispatcher(
      grpc::CompletionQueue* completion_queue,
      scoped_refptr<base::SequencedTaskRunner> task_runner);
  GrpcCompletionQueueDispatcher(const GrpcCompletionQueueDispatcher&) = delete;
  GrpcCompletionQueueDispatcher& operator=(
      const GrpcCompletionQueueDispatcher&) = delete;

  // Note that the destructor CHECKs that this instance has been shut down
  // properly using |Shutdown|.
  ~GrpcCompletionQueueDispatcher();

  // Starts the background thread and consequently starts monitoring the
  // |CompletionQueue| passed to the constructor.
  void Start();

  // Triggers shutting down the |CompletionQueue| and this
  // |GrpcCompletionQueueDispatcher|.
  // |on_shutdown_callback| will be called when the |CompletionQueue| is fully
  // drained and background thread has shut down. Only then may this instance be
  // destroyed.
  // If |Shutdown| has been called before this |GrpcCompletionQueueDispatcher|
  // has been |Start|ed, |on_shutdown_callback| is called immediately.
  // |Shutdown| may only be called once.
  void Shutdown(base::OnceClosure on_shutdown_callback);

  // Starts waiting for an event with |tag|. If |tag| has been or will be sent
  // (through RPC operations or alarms) to the CompletionQueue, |callback| is
  // guaranteed to be called exactly once on the task runner  passed to the
  // constructor. The reason is that the CompletionQueue itself guarantees that
  // every tag sent to the completion queue will be delivered out of the
  // completion queue. |GrpcCompletionQueueDispatcher| additionally guarantees
  // that if |callback| is never called (because |tag| was not sent to the
  // |CompletionQueue|), |callback| will be destroyed on shutdown on the
  // |TaskRunner| passed to the constructor.
  void RegisterTag(const void* tag, TagAvailableCallback callback);

  // Returns the monitored |CompletionQueue|.
  grpc::CompletionQueue* completion_queue() { return completion_queue_; }

 private:
  // This is called on the |task_runner_| when |tag| has been delivered out of
  // the |completion_queue_|.
  void OnTagAvailable(const void* tag, bool ok);

  // This is called on the |task_runner_| when the background thread is shutting
  // down because the |completion_queue_| has no more events.
  void OnShutdown();

  // The |CompletionQueue| that this object is monitoring.
  // Not owned.
  grpc::CompletionQueue* const completion_queue_;
  // The |SequencedTaskRunner| this object is posting tasks to.
  scoped_refptr<base::SequencedTaskRunner> task_runner_;

  // The delegate which will be executed on the |monitoring_thread|.
  std::unique_ptr<internal::MonitoringThreadDelegate>
      monitoring_thread_delegate_;
  // The background thread monitoring the |completion_queue_| and posting tasks
  // back on the task runner.
  std::unique_ptr<base::DelegateSimpleThread> monitoring_thread_;

  // This callback will be invoked when the moniting thread is exiting.
  base::OnceClosure on_shutdown_callback_;
  bool shut_down_ = false;

  // Maps tags to the callbacks that should be run on the |task_runner_| when
  // the corresponding event fires.
  std::map<const void*, TagAvailableCallback> tag_to_callback_map_;

  base::SequenceCheckerImpl sequence_checker_;
};

}  // namespace brillo

#endif  // LIBBRILLO_BRILLO_GRPC_GRPC_COMPLETION_QUEUE_DISPATCHER_H_
