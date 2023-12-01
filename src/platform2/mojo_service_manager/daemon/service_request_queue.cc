// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "mojo_service_manager/daemon/service_request_queue.h"

#include <string>
#include <utility>

#include <base/functional/bind.h>
#include <base/task/single_thread_task_runner.h>

#include "mojo_service_manager/daemon/mojo_error_util.h"

namespace chromeos {
namespace mojo_service_manager {

ServiceRequestQueue::ServiceRequestQueue(const std::string& service_name)
    : service_name_(service_name) {}

ServiceRequestQueue::~ServiceRequestQueue() = default;

void ServiceRequestQueue::Push(mojom::ProcessIdentityPtr identity,
                               std::optional<base::TimeDelta> timeout,
                               mojo::ScopedMessagePipeHandle receiver) {
  requests_.push_front(ServiceRequest{
      .identity = std::move(identity),
      .receiver = std::move(receiver),
  });
  if (timeout.has_value()) {
    base::SingleThreadTaskRunner::GetCurrentDefault()->PostDelayedTask(
        FROM_HERE,
        base::BindOnce(&ServiceRequestQueue::PopAndRejectTimeoutRequest,
                       weak_factory_.GetWeakPtr(), requests_.begin()),
        timeout.value());
  }
}

std::list<ServiceRequestQueue::ServiceRequest>
ServiceRequestQueue::TakeAllRequests() {
  // This cancel all the callbacks.
  weak_factory_.InvalidateWeakPtrs();
  std::list<ServiceRequest> res;
  res.swap(requests_);
  return res;
}

void ServiceRequestQueue::PopAndRejectTimeoutRequest(
    std::list<ServiceRequest>::iterator it) {
  LOG(ERROR) << "Failed to request service " + service_name_ +
                    " after timeout exceeded.";
  ResetMojoReceiverPipeWithReason(std::move(it->receiver),
                                  mojom::ErrorCode::kTimeout,
                                  "Failed to request service " + service_name_ +
                                      " after timeout exceeded.");
  requests_.erase(it);
}

}  // namespace mojo_service_manager
}  // namespace chromeos
