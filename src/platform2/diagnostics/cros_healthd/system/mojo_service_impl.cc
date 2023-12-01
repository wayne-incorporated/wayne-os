// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/system/mojo_service_impl.h"

#include <functional>
#include <memory>
#include <string>
#include <utility>

#include <base/task/single_thread_task_runner.h>
#include <base/time/time.h>
#include <chromeos/mojo/service_constants.h>
#include <mojo/public/cpp/bindings/enum_utils.h>
#include <mojo_service_manager/lib/connect.h>

namespace diagnostics {

namespace service_manager_mojom = chromeos::mojo_service_manager::mojom;

// Don't delay when first connects.
constexpr base::TimeDelta kFirstConnectDelay = base::Seconds(0);
// The delay of reconnecting when disconnect from the services.
constexpr base::TimeDelta kReconnectDelay = base::Seconds(1);

MojoServiceImpl::MojoServiceImpl()
    : network_health_adapter_(nullptr), network_diagnostics_adapter_(nullptr) {}

MojoServiceImpl::MojoServiceImpl(
    NetworkHealthAdapter* network_health_adapter,
    NetworkDiagnosticsAdapter* network_diagnostics_adapter)
    : network_health_adapter_(network_health_adapter),
      network_diagnostics_adapter_(network_diagnostics_adapter) {}

MojoServiceImpl::~MojoServiceImpl() = default;

// static
std::unique_ptr<MojoServiceImpl> MojoServiceImpl::Create(
    base::OnceClosure shutdown_callback,
    NetworkHealthAdapter* network_health_adapter,
    NetworkDiagnosticsAdapter* network_diagnostics_adapter) {
  auto pending_remote =
      chromeos::mojo_service_manager::ConnectToMojoServiceManager();
  CHECK(pending_remote) << "Failed to connect to mojo service manager.";

  auto impl = std::unique_ptr<MojoServiceImpl>(
      new MojoServiceImpl(network_health_adapter, network_diagnostics_adapter));
  impl->service_manager_.Bind(std::move(pending_remote));
  impl->service_manager_.set_disconnect_with_reason_handler(
      base::BindOnce([](uint32_t error, const std::string& message) {
        LOG(INFO) << "Disconnected from mojo service manager (the mojo broker "
                     "process). Error: "
                  << error << ", message: " << message
                  << ". Shutdown and wait for respawn.";
      }).Then(std::move(shutdown_callback)));

  impl->RequestService(
      chromeos::mojo_services::kChromiumCrosHealthdDataCollector,
      impl->chromium_data_collector_, kFirstConnectDelay);
  impl->RequestService(chromeos::mojo_services::kChromiumNetworkHealth,
                       impl->network_health_, kFirstConnectDelay);
  impl->RequestService(
      chromeos::mojo_services::kChromiumNetworkDiagnosticsRoutines,
      impl->network_diagnostics_routines_, kFirstConnectDelay);
  impl->RequestService(chromeos::mojo_services::kIioSensor,
                       impl->sensor_service_, kFirstConnectDelay);
  return impl;
}

chromeos::mojo_service_manager::mojom::ServiceManager*
MojoServiceImpl::GetServiceManager() {
  DCHECK(service_manager_.is_bound());
  return service_manager_.get();
}

ash::cros_healthd::internal::mojom::ChromiumDataCollector*
MojoServiceImpl::GetChromiumDataCollector() {
  DCHECK(chromium_data_collector_.is_bound());
  return chromium_data_collector_.get();
}

chromeos::network_health::mojom::NetworkHealthService*
MojoServiceImpl::GetNetworkHealth() {
  DCHECK(network_health_.is_bound());
  return network_health_.get();
}

chromeos::network_diagnostics::mojom::NetworkDiagnosticsRoutines*
MojoServiceImpl::GetNetworkDiagnosticsRoutines() {
  DCHECK(network_diagnostics_routines_.is_bound());
  return network_diagnostics_routines_.get();
}

cros::mojom::SensorService* MojoServiceImpl::GetSensorService() {
  DCHECK(sensor_service_.is_bound());
  return sensor_service_.get();
}

cros::mojom::SensorDevice* MojoServiceImpl::GetSensorDevice(int32_t device_id) {
  MojoServiceImpl::BindSensorDeviceRemoteIfNeeded(device_id);
  return sensor_devices_[device_id].get();
}

void MojoServiceImpl::BindSensorDeviceRemoteIfNeeded(int32_t device_id) {
  if (sensor_devices_[device_id].is_bound())
    return;

  MojoServiceImpl::GetSensorService()->GetDevice(
      device_id, sensor_devices_[device_id].BindNewPipeAndPassReceiver());
}

template <typename InterfaceType>
void MojoServiceImpl::RequestService(const std::string& service_name,
                                     mojo::Remote<InterfaceType>& remote,
                                     const base::TimeDelta& delay) {
  base::SingleThreadTaskRunner::GetCurrentDefault()->PostDelayedTask(
      FROM_HERE,
      base::BindOnce(&MojoServiceImpl::SendServiceRequest<InterfaceType>,
                     weak_ptr_factory_.GetWeakPtr(), service_name,
                     remote.BindNewPipeAndPassReceiver()),
      delay);
  // std::ref() is safe here because it must be a member of this class.
  remote.set_disconnect_with_reason_handler(base::BindOnce(
      &MojoServiceImpl::OnServiceDisconnect<InterfaceType>,
      weak_ptr_factory_.GetWeakPtr(), service_name, std::ref(remote)));
}

template <typename InterfaceType>
void MojoServiceImpl::SendServiceRequest(
    const std::string& service_name,
    mojo::PendingReceiver<InterfaceType> pending_receiver) {
  // When shutdowning, the service manager could be disconnected. Don't call the
  // interface to prevent crashing during shutdown.
  if (!service_manager_.is_connected())
    return;
  service_manager_->Request(service_name, std::nullopt,
                            pending_receiver.PassPipe());

  // Bind an additional connection to network adapters. TODO(b/237239654):
  // Remove this after we remove these network adapters.
  if (service_name == chromeos::mojo_services::kChromiumNetworkHealth) {
    mojo::PendingRemote<chromeos::network_health::mojom::NetworkHealthService>
        pending_remote;
    service_manager_->Request(
        service_name, std::nullopt,
        pending_remote.InitWithNewPipeAndPassReceiver().PassPipe());
    network_health_adapter_->SetServiceRemote(std::move(pending_remote));
  }
  if (service_name ==
      chromeos::mojo_services::kChromiumNetworkDiagnosticsRoutines) {
    mojo::PendingRemote<
        chromeos::network_diagnostics::mojom::NetworkDiagnosticsRoutines>
        pending_remote;
    service_manager_->Request(
        service_name, std::nullopt,
        pending_remote.InitWithNewPipeAndPassReceiver().PassPipe());
    network_diagnostics_adapter_->SetNetworkDiagnosticsRoutines(
        std::move(pending_remote));
  }
}

template <typename InterfaceType>
void MojoServiceImpl::OnServiceDisconnect(const std::string& service_name,
                                          mojo::Remote<InterfaceType>& remote,
                                          uint32_t error,
                                          const std::string& message) {
  if (!error) {
    // The remote service probably restarted so try to reconnect.
    remote.reset();
    RequestService(service_name, remote, kReconnectDelay);
    return;
  }
  std::optional<service_manager_mojom::ErrorCode> error_enum =
      mojo::ConvertIntToMojoEnum<service_manager_mojom::ErrorCode>(
          static_cast<int32_t>(error));
  if (error_enum) {
    LOG(ERROR) << "Service " << service_name
               << "disconnectemessaged with error " << error_enum.value()
               << ", message: " << message;
  } else {
    LOG(ERROR) << "Service " << service_name
               << "disconnectemessaged with error " << error
               << ", message: " << message;
  }
}

}  // namespace diagnostics
