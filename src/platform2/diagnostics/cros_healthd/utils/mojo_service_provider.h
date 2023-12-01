// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_UTILS_MOJO_SERVICE_PROVIDER_H_
#define DIAGNOSTICS_CROS_HEALTHD_UTILS_MOJO_SERVICE_PROVIDER_H_

#include <string>
#include <utility>

#include <base/functional/bind.h>
#include <mojo/public/cpp/bindings/receiver.h>
#include <mojo/public/cpp/bindings/receiver_set.h>
#include <mojo_service_manager/lib/mojom/service_manager.mojom.h>

namespace diagnostics {

// Implements the `mojom::ServiceProvider` to provide mojo service to the
// service manager. It takes a pointer to the implementation of the mojo
// service which will be provided. Just like the mojo::Receiver object, this
// should be held by the implementation to guarantee that the implementation
// won't be accessed after free.
template <typename MojoInterfaceType>
class MojoServiceProvider
    : public chromeos::mojo_service_manager::mojom::ServiceProvider {
 public:
  explicit MojoServiceProvider(MojoInterfaceType* impl)
      : receiver_(this), impl_(impl) {}

  // Register the service to the service manager.
  void Register(
      chromeos::mojo_service_manager::mojom::ServiceManager* service_manager,
      const std::string& service_name) {
    service_manager->Register(service_name,
                              receiver_.BindNewPipeAndPassRemote());
    receiver_.set_disconnect_with_reason_handler(base::BindOnce(
        [](const std::string& service_name, uint32_t error,
           const std::string& message) {
          LOG(ERROR) << "The service provider of " << service_name
                     << " disconnected, error: " << error
                     << ", message: " << message;
        },
        service_name));
  }

 private:
  // chromeos::mojo_service_manager::mojom::ServiceProvider overrides.
  void Request(
      chromeos::mojo_service_manager::mojom::ProcessIdentityPtr identity,
      mojo::ScopedMessagePipeHandle receiver) override {
    service_receiver_set_.Add(
        impl_, mojo::PendingReceiver<MojoInterfaceType>(std::move(receiver)));
  }

  // The receiver to receive requests from the service manager.
  mojo::Receiver<chromeos::mojo_service_manager::mojom::ServiceProvider>
      receiver_;
  // The pointer to the implementation of the mojo interface.
  MojoInterfaceType* const impl_;
  // The receiver set to keeps the connections from clients to access the mojo
  // service.
  mojo::ReceiverSet<MojoInterfaceType> service_receiver_set_;
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_UTILS_MOJO_SERVICE_PROVIDER_H_
