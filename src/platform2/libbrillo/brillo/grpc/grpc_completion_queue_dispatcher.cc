// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "brillo/grpc/grpc_completion_queue_dispatcher.h"

#include <utility>

#include <base/check.h>
#include <base/functional/bind.h>
#include <base/location.h>
#include <base/logging.h>
#include <base/task/sequenced_task_runner.h>

namespace brillo {
namespace internal {

// This is the background ("monitoring") thread delegate used by
// |GrpcCompletionQueueDispatcher|.
class MonitoringThreadDelegate : public base::DelegateSimpleThread::Delegate {
 public:
  using OnTagAvailableCallback =
      base::RepeatingCallback<void(const void* tag, bool ok)>;
  using OnShutdownCallback = base::OnceClosure;

  // |GrpcCompletionQueueDispatcher| guarantees that the unowned pointers
  // outlive this delegate. This delegate will post |on_tag_available_callback|
  // on the |task_runner| when a tag is available on |completion_queue|, and it
  // will post |on_shutdown_callback| on the |task_runner| when it is shutting
  // down.
  MonitoringThreadDelegate(grpc::CompletionQueue* completion_queue,
                           base::SequencedTaskRunner* task_runner,
                           OnTagAvailableCallback on_tag_available_callback,
                           OnShutdownCallback on_shutdown_callback)
      : completion_queue_(completion_queue),
        task_runner_(task_runner),
        on_tag_available_callback_(on_tag_available_callback),
        on_shutdown_callback_(std::move(on_shutdown_callback)) {}

  ~MonitoringThreadDelegate() override = default;

  // base::DelegateSimpleThread::Delegate:
  void Run() override {
    // This runs on the background thread. It monitors |completion_queue_| and
    // posts task to |task_runner_|.
    while (true) {
      void* tag;
      bool ok;

      if (completion_queue_->Next(&tag, &ok)) {
        task_runner_->PostTask(
            FROM_HERE, base::BindOnce(on_tag_available_callback_, tag, ok));
      } else {
        // Next() returned false, which means that this queue has shut down.
        // Exit this 'event loop'.
        break;
      }
    }

    DCHECK(!on_shutdown_callback_.is_null());
    task_runner_->PostTask(FROM_HERE, std::move(on_shutdown_callback_));
  }

 private:
  // The |CompletionQueue| that this object is monitoring.
  // Not owned.
  grpc::CompletionQueue* const completion_queue_;
  // The |SequencedTaskRunner| this object is posting tasks to. It is accessed
  // from the monitoring thread.
  // Not owned.
  base::SequencedTaskRunner* const task_runner_;

  OnTagAvailableCallback on_tag_available_callback_;
  OnShutdownCallback on_shutdown_callback_;
};

}  // namespace internal

GrpcCompletionQueueDispatcher::GrpcCompletionQueueDispatcher(
    grpc::CompletionQueue* completion_queue,
    scoped_refptr<base::SequencedTaskRunner> task_runner)
    : completion_queue_(completion_queue), task_runner_(task_runner) {
  CHECK(task_runner_);
  CHECK(completion_queue_);
}

GrpcCompletionQueueDispatcher::~GrpcCompletionQueueDispatcher() {
  CHECK(sequence_checker_.CalledOnValidSequence());
  // Ensure that this |GrpcCompletionQueueDispatcher| has been shut down
  // properly.
  CHECK(!monitoring_thread_);
  CHECK(tag_to_callback_map_.empty());
}

void GrpcCompletionQueueDispatcher::Start() {
  CHECK(sequence_checker_.CalledOnValidSequence());
  CHECK(!monitoring_thread_);
  CHECK(!shut_down_);
  // Create the delegate which will be run on the background thread.
  // It is OK to pass unowned pointers and use |base::Unretained|  because:
  // - |GrpcCompletionQueueDispatcher| CHECK-fails if it's destroyed
  //   before |OnShutdown| has been called
  // - |task_runner_| is a |SequencedTaskRunner|
  // - |OnShutdown| is posted as the last thing before the background thread
  // exits.
  monitoring_thread_delegate_ =
      std::make_unique<internal::MonitoringThreadDelegate>(
          completion_queue_, task_runner_.get(),
          base::BindRepeating(&GrpcCompletionQueueDispatcher::OnTagAvailable,
                              base::Unretained(this)),
          base::BindOnce(&GrpcCompletionQueueDispatcher::OnShutdown,
                         base::Unretained(this)));
  monitoring_thread_ = std::make_unique<base::DelegateSimpleThread>(
      monitoring_thread_delegate_.get(),
      "GrpcCompletionQueueDispatcher" /* name_prefix */);
  monitoring_thread_->Start();
}

void GrpcCompletionQueueDispatcher::Shutdown(
    base::OnceClosure on_shutdown_callback) {
  CHECK(!shut_down_);
  shut_down_ = true;

  if (!monitoring_thread_) {
    std::move(on_shutdown_callback).Run();
    return;
  }

  CHECK(sequence_checker_.CalledOnValidSequence());
  CHECK(on_shutdown_callback_.is_null());
  CHECK(!on_shutdown_callback.is_null());

  on_shutdown_callback_ = std::move(on_shutdown_callback);
  completion_queue_->Shutdown();
}

void GrpcCompletionQueueDispatcher::RegisterTag(const void* tag,
                                                TagAvailableCallback callback) {
  CHECK(sequence_checker_.CalledOnValidSequence());
  CHECK(tag_to_callback_map_.find(tag) == tag_to_callback_map_.end());
  tag_to_callback_map_.insert(std::make_pair(tag, std::move(callback)));
}

void GrpcCompletionQueueDispatcher::OnTagAvailable(const void* tag, bool ok) {
  CHECK(sequence_checker_.CalledOnValidSequence());
  auto iter = tag_to_callback_map_.find(tag);
  if (iter == tag_to_callback_map_.end()) {
    // Ignore tags received from the |CompletionQueue| that we're not expecting.
    // gRPC documents situations where this may happen - see e.g. the
    // documentation for the grpc::ServerInterface::Shutdown method:
    // https://grpc.io/grpc/cpp/classgrpc_1_1_server_interface.html
    DVLOG(2) << "CompletionQueue returned a tag that was not registered.";
    return;
  }
  TagAvailableCallback callback = std::move(iter->second);
  tag_to_callback_map_.erase(iter);
  std::move(callback).Run(ok);
}

void GrpcCompletionQueueDispatcher::OnShutdown() {
  CHECK(sequence_checker_.CalledOnValidSequence());
  tag_to_callback_map_.clear();

  monitoring_thread_->Join();
  monitoring_thread_.reset();
  monitoring_thread_delegate_.reset();

  if (!on_shutdown_callback_.is_null()) {
    // Post the |on_shutdown_callback_| on the task runner instead of calling it
    // directly, allowing the owner of this instance to delete it in the context
    // of |on_shutdown_callback_|.
    task_runner_->PostTask(FROM_HERE, std::move(on_shutdown_callback_));
  }
}

}  // namespace brillo
