// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MOJO_SERVICE_MANAGER_DAEMON_SERVICE_MANAGER_H_
#define MOJO_SERVICE_MANAGER_DAEMON_SERVICE_MANAGER_H_

#include <map>
#include <optional>
#include <set>
#include <string>

#include <base/memory/weak_ptr.h>
#include <mojo/public/cpp/bindings/receiver_set.h>
#include <mojo/public/cpp/bindings/remote_set.h>

#include "mojo_service_manager/daemon/configuration.h"
#include "mojo_service_manager/daemon/service_policy.h"
#include "mojo_service_manager/daemon/service_request_queue.h"
#include "mojo_service_manager/lib/mojom/service_manager.mojom.h"

namespace chromeos {
namespace mojo_service_manager {

// Implements mojom::ServiceManager.
class ServiceManager : public mojom::ServiceManager {
 public:
  ServiceManager(Configuration configuration, ServicePolicyMap policy_map);
  ServiceManager(const ServiceManager&) = delete;
  ServiceManager& operator=(const ServiceManager&) = delete;
  ~ServiceManager() override;

  // Adds a receiver of mojom::ServiceManager to the receiver set. A process
  // identity will be bound to this receiver.
  void AddReceiver(mojom::ProcessIdentityPtr process_identity,
                   mojo::PendingReceiver<mojom::ServiceManager> receiver);

 private:
  // Keeps all the objects related to a mojo service.
  struct ServiceState {
    explicit ServiceState(const std::string& service_name,
                          ServicePolicy policy);
    ServiceState(const ServiceState&) = delete;
    ServiceState& operator=(const ServiceState&) = delete;
    ~ServiceState();

    // The policy applied to this mojo service.
    ServicePolicy policy;
    // The identity of the current owner process.
    mojom::ProcessIdentityPtr owner;
    // The queue to keep the service request before the service is available.
    // Note that this is not moveable.
    ServiceRequestQueue request_queue;
    // The mojo remote to the service provider.
    mojo::Remote<mojom::ServiceProvider> service_provider;
  };

  // mojom::ServiceManager overrides.
  void Register(
      const std::string& service_name,
      mojo::PendingRemote<mojom::ServiceProvider> service_provider) override;
  void Request(const std::string& service_name,
               std::optional<base::TimeDelta> timeout,
               mojo::ScopedMessagePipeHandle receiver) override;
  void Query(const std::string& service_name, QueryCallback callback) override;
  void AddServiceObserver(
      mojo::PendingRemote<mojom::ServiceObserver> observer) override;

  // Handles the disconnect of a service provider.
  void ServiceProviderDisconnectHandler(const std::string& service_name);

  // Sends a service event to observers owned by requesters.
  void SendServiceEvent(const std::set<std::string>& requesters,
                        mojom::ServiceEventPtr event);

  // Handles the disconnect of clients.
  void HandleDisconnect();

  // The service manager configuration.
  const Configuration configuration_;
  // Maps each service name to a ServiceState.
  std::map<std::string, ServiceState> service_map_;
  // The receivers of mojom::ServiceManager. The context type of the
  // mojo::ReceiverSet is set to mojom::ProcessIdentity so it can be used when
  // handle the requests.
  mojo::ReceiverSet<mojom::ServiceManager, mojom::ProcessIdentityPtr>
      receiver_set_;
  // Maps security context to the remote set of service observers. Each set can
  // only receive events sent to each security context.
  std::map<std::string, mojo::RemoteSet<mojom::ServiceObserver>>
      service_observer_map_;
  // Must be the last member.
  base::WeakPtrFactory<ServiceManager> weak_factory_{this};
};

}  // namespace mojo_service_manager
}  // namespace chromeos

#endif  // MOJO_SERVICE_MANAGER_DAEMON_SERVICE_MANAGER_H_
