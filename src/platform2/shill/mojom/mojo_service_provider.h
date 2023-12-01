// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_MOJOM_MOJO_SERVICE_PROVIDER_H_
#define SHILL_MOJOM_MOJO_SERVICE_PROVIDER_H_

#include <map>
#include <memory>
#include <optional>
#include <string>
#include <utility>

#include <base/memory/weak_ptr.h>
#include <base/threading/thread.h>
#include <base/time/time.h>
#include <mojo/core/embedder/scoped_ipc_support.h>
#include <mojo/public/cpp/bindings/receiver.h>
#include <mojo/public/cpp/bindings/receiver_set.h>
#include <mojo/public/cpp/bindings/remote.h>
#include <mojo_service_manager/lib/connect.h>
#include <mojo_service_manager/lib/mojom/service_manager.mojom.h>
#include <mojo_service_manager/mojo_service_manager/lib/mojom/service_manager.mojom.h>

#include "shill/mojom/mojo_passpoint_service.h"

namespace shill {

class Manager;

// Implementation of mojom::ServiceProvider that holds and exposes Shill
// mojo services to the service manager.
class MojoServiceProvider
    : public chromeos::mojo_service_manager::mojom::ServiceProvider {
 public:
  explicit MojoServiceProvider(Manager* manager);
  MojoServiceProvider(const MojoServiceProvider&) = delete;
  MojoServiceProvider& operator=(const MojoServiceProvider&) = delete;

  ~MojoServiceProvider() override;

  // Setup Mojo environment and register the services to the system service
  // manager.
  virtual void Start();
  virtual void Stop();

 private:
  // Bind the provider to the service manager and register our services.
  void ConnectAndRegister();

  // Called when the manager disconnects.
  void OnManagerDisconnected(uint32_t error, const std::string& message);

  void Request(
      chromeos::mojo_service_manager::mojom::ProcessIdentityPtr identity,
      mojo::ScopedMessagePipeHandle receiver) override;

  // Thread for running IPC requests.
  base::Thread ipc_thread_;
  std::unique_ptr<mojo::core::ScopedIPCSupport> ipc_support_;

  // Mojo service manager.
  mojo::Remote<chromeos::mojo_service_manager::mojom::ServiceManager>
      service_manager_;

  // Passpoint mojo service implementation.
  MojoPasspointService passpoint_service_;

  // The receiver of the ServiceProvider
  mojo::Receiver<chromeos::mojo_service_manager::mojom::ServiceProvider>
      receiver_{this};
  mojo::ReceiverSet<chromeos::connectivity::mojom::PasspointService>
      service_receiver_set_;

  // Used to register the Passpoint service as an observer of Passpoint
  // credentials events.
  Manager* manager_;

  // Must be the last class member.
  base::WeakPtrFactory<MojoServiceProvider> weak_ptr_factory_{this};
};

}  // namespace shill

#endif  // SHILL_MOJOM_MOJO_SERVICE_PROVIDER_H_
