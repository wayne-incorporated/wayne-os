// Copyright 2015 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "trunks/background_command_transceiver.h"

#include <utility>

#include <base/functional/bind.h>
#include <base/functional/callback.h>
#include <base/location.h>
#include <base/logging.h>
#include <base/synchronization/waitable_event.h>
#include <base/task/single_thread_task_runner.h>

namespace {

// A simple callback useful when waiting for an asynchronous call.
void AssignAndSignal(std::string* destination,
                     base::WaitableEvent* event,
                     const std::string& source) {
  *destination = source;
  event->Signal();
}

// A callback which posts another |callback| to a given |task_runner|.
void PostCallbackToTaskRunner(
    trunks::CommandTransceiver::ResponseCallback callback,
    scoped_refptr<base::SingleThreadTaskRunner> task_runner,
    const std::string& response) {
  base::OnceClosure task = base::BindOnce(std::move(callback), response);
  task_runner->PostTask(FROM_HERE, std::move(task));
}

}  // namespace

namespace trunks {

BackgroundCommandTransceiver::BackgroundCommandTransceiver(
    CommandTransceiver* next_transceiver,
    const scoped_refptr<base::SequencedTaskRunner>& task_runner)
    : next_transceiver_(next_transceiver),
      task_runner_(task_runner),
      weak_factory_(this) {}

BackgroundCommandTransceiver::~BackgroundCommandTransceiver() {}

void BackgroundCommandTransceiver::SendCommand(const std::string& command,
                                               ResponseCallback callback) {
  if (task_runner_.get()) {
    ResponseCallback background_callback =
        base::BindOnce(PostCallbackToTaskRunner, std::move(callback),
                       base::SingleThreadTaskRunner::GetCurrentDefault());
    // Use SendCommandTask instead of binding to next_transceiver_ directly to
    // leverage weak pointer semantics.
    base::OnceClosure task =
        base::BindOnce(&BackgroundCommandTransceiver::SendCommandTask,
                       GetWeakPtr(), command, std::move(background_callback));
    task_runner_->PostNonNestableTask(FROM_HERE, std::move(task));
  } else {
    next_transceiver_->SendCommand(command, std::move(callback));
  }
}

std::string BackgroundCommandTransceiver::SendCommandAndWait(
    const std::string& command) {
  if (task_runner_.get()) {
    std::string response;
    base::WaitableEvent response_ready(
        base::WaitableEvent::ResetPolicy::MANUAL,
        base::WaitableEvent::InitialState::NOT_SIGNALED);
    ResponseCallback callback =
        base::BindOnce(&AssignAndSignal, &response, &response_ready);
    // Use SendCommandTask instead of binding to next_transceiver_ directly to
    // leverage weak pointer semantics.
    base::OnceClosure task =
        base::BindOnce(&BackgroundCommandTransceiver::SendCommandTask,
                       GetWeakPtr(), command, std::move(callback));
    task_runner_->PostNonNestableTask(FROM_HERE, std::move(task));
    response_ready.Wait();
    return response;
  } else {
    return next_transceiver_->SendCommandAndWait(command);
  }
}

void BackgroundCommandTransceiver::SendCommandTask(const std::string& command,
                                                   ResponseCallback callback) {
  next_transceiver_->SendCommand(command, std::move(callback));
}

}  // namespace trunks
