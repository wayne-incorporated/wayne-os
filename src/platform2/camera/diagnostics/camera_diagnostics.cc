// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/camera_diagnostics.h"

#include <base/task/sequenced_task_runner.h>
#include <mojo/core/embedder/embedder.h>
#include <mojo/public/cpp/bindings/remote.h>
#include <mojo_service_manager/lib/connect.h>

#include "cros-camera/common.h"

namespace cros {

void CameraDiagnostics::Start() {
  LOGF(INFO) << "Initialize mojo IPC";
  mojo::core::Init();
  ipc_support_ = std::make_unique<mojo::core::ScopedIPCSupport>(
      base::SingleThreadTaskRunner::GetCurrentDefault(),
      mojo::core::ScopedIPCSupport::ShutdownPolicy::
          CLEAN /* blocking shutdown */);

  LOGF(INFO) << "Registering camera diagnostics service provider";
  mojo::Remote<chromeos::mojo_service_manager::mojom::ServiceManager>
      service_manager{
          chromeos::mojo_service_manager::ConnectToMojoServiceManager()};

  service_provider_.Register(service_manager.get());
}

}  // namespace cros
