// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/diagnostics_service_provider.h"

#include <utility>

#include <chromeos/mojo/service_constants.h>

namespace cros {

void DiagnosticsServiceProvider::Register(
    chromeos::mojo_service_manager::mojom::ServiceManager* service_manager) {
  service_manager->Register(/*service_name=*/
                            chromeos::mojo_services::kCrosCameraDiagnostics,
                            receiver_.BindNewPipeAndPassRemote());
}

void DiagnosticsServiceProvider::Request(
    chromeos::mojo_service_manager::mojom::ProcessIdentityPtr identity,
    mojo::ScopedMessagePipeHandle receiver) {
  service_receiver_set_.Add(
      &camera_diagnostics_impl_,
      mojo::PendingReceiver<mojom::CameraDiagnostics>(std::move(receiver)));
}

}  // namespace cros
