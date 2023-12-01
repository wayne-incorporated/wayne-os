// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MOJO_SERVICE_MANAGER_DAEMON_SERVICE_REQUEST_QUEUE_H_
#define MOJO_SERVICE_MANAGER_DAEMON_SERVICE_REQUEST_QUEUE_H_

#include <list>
#include <optional>
#include <string>

#include <base/memory/weak_ptr.h>

#include "mojo_service_manager/lib/mojom/service_manager.mojom.h"

namespace chromeos {
namespace mojo_service_manager {

// Provides a queue to keep the service requests before the servcie is
// available. Each request can have a timeout and the queue rejects the request
// if it is not taken from the queue before the timeout is reached.
class ServiceRequestQueue {
 public:
  // The objects used by a service request.
  struct ServiceRequest {
    // The identity of requester.
    mojom::ProcessIdentityPtr identity;
    // The receiver to be bound to the mojo service.
    mojo::ScopedMessagePipeHandle receiver;
  };

  explicit ServiceRequestQueue(const std::string& service_name);
  ServiceRequestQueue(const ServiceRequestQueue&) = delete;
  ServiceRequestQueue& operator=(const ServiceRequestQueue&) = delete;
  ~ServiceRequestQueue();

  // Push a service request to the queue. If |timeout| is not nullopt, a delayed
  // task is posted to reject the request after |timeout|.
  void Push(mojom::ProcessIdentityPtr identity,
            std::optional<base::TimeDelta> timeout,
            mojo::ScopedMessagePipeHandle receiver);

  // Takes all the service requests from the queue. This cancel all the delayed
  // tasks of this queue which has not yet been run.
  std::list<ServiceRequest> TakeAllRequests();

 private:
  // Pops and rejects a timeouted service request from the queue.
  void PopAndRejectTimeoutRequest(std::list<ServiceRequest>::iterator it);

  // The service name of this queue. For logging.
  const std::string service_name_;
  // The storage to keep the requests. Use std::list so any element can be
  // removed in O(1).
  std::list<ServiceRequest> requests_;
  // Must be the last member.
  base::WeakPtrFactory<ServiceRequestQueue> weak_factory_{this};
};

}  // namespace mojo_service_manager
}  // namespace chromeos

#endif  // MOJO_SERVICE_MANAGER_DAEMON_SERVICE_REQUEST_QUEUE_H_
