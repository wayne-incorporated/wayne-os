// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CAMERA_DIAGNOSTICS_DIAGNOSTICS_SERVICE_PROVIDER_H_
#define CAMERA_DIAGNOSTICS_DIAGNOSTICS_SERVICE_PROVIDER_H_

#include <mojo/public/cpp/bindings/receiver.h>
#include <mojo/public/cpp/bindings/receiver_set.h>
#include <mojo_service_manager/lib/connect.h>

#include "diagnostics/camera_diagnostics_impl.h"

namespace cros {

class DiagnosticsServiceProvider
    : public chromeos::mojo_service_manager::mojom::ServiceProvider {
 public:
  void Register(
      chromeos::mojo_service_manager::mojom::ServiceManager* service_manager);

 private:
  // overrides ServiceProvider.
  void Request(
      chromeos::mojo_service_manager::mojom::ProcessIdentityPtr identity,
      mojo::ScopedMessagePipeHandle receiver) override;

  // The receiver of ServiceProvider.
  mojo::Receiver<chromeos::mojo_service_manager::mojom::ServiceProvider>
      receiver_{this};
  // The implementation of mojom::CameraDiagnostics.
  CameraDiagnosticsImpl camera_diagnostics_impl_;
  // The receiver set to hold the receivers of CameraDiagnostics.
  mojo::ReceiverSet<mojom::CameraDiagnostics> service_receiver_set_;
};

}  // namespace cros

#endif  // CAMERA_DIAGNOSTICS_DIAGNOSTICS_SERVICE_PROVIDER_H_
