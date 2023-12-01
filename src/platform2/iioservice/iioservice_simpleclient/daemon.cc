// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "iioservice/iioservice_simpleclient/daemon.h"

#include <sysexits.h>

#include <memory>
#include <utility>

#include <base/functional/bind.h>
#include <chromeos/mojo/service_constants.h>
#include <mojo/core/embedder/embedder.h>

#include "iioservice/include/common.h"

namespace iioservice {

Daemon::~Daemon() = default;

Daemon::Daemon() = default;

int Daemon::OnInit() {
  int exit_code = brillo::Daemon::OnInit();
  if (exit_code != EX_OK)
    return exit_code;

  mojo::core::Init();
  ipc_support_ = std::make_unique<mojo::core::ScopedIPCSupport>(
      base::SingleThreadTaskRunner::GetCurrentDefault(),
      mojo::core::ScopedIPCSupport::ShutdownPolicy::FAST);

  SetSensorClient();

  ConnectToMojoServiceManager();

  return exit_code;
}

void Daemon::OnMojoDisconnect() {
  LOGF(INFO) << "Quitting this process.";
  Quit();
}

void Daemon::ConnectToMojoServiceManager() {
  auto service_manager_remote =
      chromeos::mojo_service_manager::ConnectToMojoServiceManager();

  if (!service_manager_remote) {
    LOGF(ERROR) << "Failed to connect to Mojo Service Manager";

    Quit();
    return;
  }

  service_manager_.Bind(std::move(service_manager_remote));
  service_manager_.set_disconnect_with_reason_handler(base::BindOnce(
      &Daemon::OnServiceManagerDisconnect, base::Unretained(this)));

  mojo::PendingRemote<cros::mojom::SensorService> sensor_service_remote;

  service_manager_->Request(
      chromeos::mojo_services::kIioSensor, std::nullopt,
      sensor_service_remote.InitWithNewPipeAndPassReceiver().PassPipe());
  sensor_client_->SetUpChannel(std::move(sensor_service_remote));
}

void Daemon::OnServiceManagerDisconnect(uint32_t custom_reason,
                                        const std::string& description) {
  auto error = static_cast<chromeos::mojo_service_manager::mojom::ErrorCode>(
      custom_reason);
  LOGF(ERROR) << "ServiceManagerDisconnected, error: " << error
              << ", description: " << description;

  Quit();
}

}  // namespace iioservice
