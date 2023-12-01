// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_WILCO_DTC_SUPPORTD_MOJO_SERVICE_FACTORY_H_
#define DIAGNOSTICS_WILCO_DTC_SUPPORTD_MOJO_SERVICE_FACTORY_H_

#include <memory>
#include <optional>
#include <string>

#include <base/files/scoped_file.h>
#include <base/functional/callback.h>
#include <mojo/public/cpp/bindings/pending_receiver.h>
#include <mojo/public/cpp/bindings/pending_remote.h>
#include <mojo/public/cpp/bindings/receiver.h>

#include "diagnostics/mojom/public/wilco_dtc_supportd.mojom.h"

namespace diagnostics {
namespace wilco {

class MojoService;
class MojoGrpcAdapter;

// Bootstraps Mojo connection between Chrome and wilco_dtc_supportd daemon over
// D-Bus connection.
//
// Implements the "WilcoDtcSupportdServiceFactory" Mojo interface exposed by the
// wilco_dtc_supportd daemon (see the API definition at
// mojo/wilco_dtc_supportd.mojom).
class MojoServiceFactory final : public chromeos::wilco_dtc_supportd::mojom::
                                     WilcoDtcSupportdServiceFactory {
 public:
  using WilcoServiceFactory =
      chromeos::wilco_dtc_supportd::mojom::WilcoDtcSupportdServiceFactory;
  using MojoReceiver = mojo::Receiver<WilcoServiceFactory>;
  using BindFactoryCallback =
      base::OnceCallback<void(MojoReceiver*, base::ScopedFD)>;

  MojoServiceFactory(MojoGrpcAdapter* grpc_adapter,
                     base::RepeatingClosure shutdown,
                     BindFactoryCallback = CreateBindFactoryCallback());
  MojoServiceFactory(const MojoServiceFactory&) = delete;
  MojoServiceFactory& operator=(const MojoServiceFactory&) = delete;
  virtual ~MojoServiceFactory();

  // Returns the mojo service (can be null, if |Start| has not been called yet).
  MojoService* Get() const;

  // Implements D-Bus call BootstrapMojoConnection().
  // Returns an error message in case an error occurred.
  std::optional<std::string> BootstrapMojoConnection(
      const base::ScopedFD& mojo_fd);

 private:
  // Initializes the service factory.
  std::optional<std::string> Start(base::ScopedFD mojo_pipe_fd);

  // Creates the |BindFactoryCallback| to be used in production:
  //
  // The callback binds the given |receiver| to the Mojo message
  // pipe that works via the given |mojo_pipe_fd|. The pipe has to contain a
  // valid invitation, otherwise |receiver| remains unbound.
  //
  // This is a OnceCallback, since Mojo EDK gives no guarantee to support
  // repeated initialization with different parent handles.
  static BindFactoryCallback CreateBindFactoryCallback();

  // Shuts down the self instance after a Mojo fatal error happens.
  void ShutdownDueToMojoError(const std::string& debug_reason);

  // chromeos::wilco_dtc_supportd::mojom::WilcoDtcSupportdServiceFactory
  // overrides:
  void GetService(
      mojo::PendingReceiver<
          chromeos::wilco_dtc_supportd::mojom::WilcoDtcSupportdService> service,
      mojo::PendingRemote<
          chromeos::wilco_dtc_supportd::mojom::WilcoDtcSupportdClient> client,
      GetServiceCallback callback) override;

  // Unowned. The mojo_grpc_adapter must outlive this instance.
  MojoGrpcAdapter* grpc_adapter_ = nullptr;
  // To be called in case of an unrecoverable mojo error.
  base::RepeatingClosure shutdown_;

  // OnceCallback to bind the |mojo_service_factory_receiver_|.
  BindFactoryCallback bind_factory_callback_;
  // Receiver that connects this instance (which is an implementation of
  // chromeos::wilco_dtc_supportd::mojom::WilcoDtcSupportdServiceFactory) with
  // the message pipe set up on top of the received file descriptor.
  //
  // Is bound after the BootstrapMojoConnection D-Bus method is called.
  MojoReceiver mojo_service_factory_receiver_;
  // Implementation of the Mojo interface exposed by the wilco_dtc_supportd
  // daemon and a proxy that allows sending outgoing Mojo requests.
  //
  // Gets created after the GetService() Mojo method is called.
  std::unique_ptr<MojoService> mojo_service_;
  // Whether receiver of the Mojo service was attempted.
  //
  // This flag is needed for detecting repeated Mojo bootstrapping attempts
  // (alternative ways, like checking |mojo_service_factory_receiver_|, are
  // unreliable during shutdown).
  bool mojo_service_bind_attempted_ = false;
};

}  // namespace wilco
}  // namespace diagnostics

#endif  // DIAGNOSTICS_WILCO_DTC_SUPPORTD_MOJO_SERVICE_FACTORY_H_
