// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <mojo_service_manager/lib/connect.h>

#include "base/check.h"
#include "base/logging.h"
#include "mojo/service_constants.h"
#include "rmad/utils/mojo_service_utils.h"

namespace rmad {

void MojoServiceUtilsImpl::Initialize() {
  // Reset the states of service manager and underlying services.
  service_manager_.reset();
  sensor_service_.reset();
  sensor_devices_map_.clear();

  // Connect to the Mojo Service Manager.
  auto pending_remote =
      chromeos::mojo_service_manager::ConnectToMojoServiceManager();

  CHECK(pending_remote);
  service_manager_.Bind(std::move(pending_remote));
  service_manager_.set_disconnect_with_reason_handler(base::BindOnce(
      [](base::RepeatingCallback<void()> callback, uint32_t error,
         const std::string& message) {
        LOG(ERROR) << "Mojo service manager disconnected\n"
                   << "Error code: " << error << ", message: " << message;
        callback.Run();
      },
      connection_error_callback_));

  // Bind the Sensor Service.
  service_manager_->Request(
      chromeos::mojo_services::kIioSensor, std::nullopt,
      sensor_service_.BindNewPipeAndPassReceiver().PassPipe());
  sensor_service_.set_disconnect_with_reason_handler(base::BindOnce(
      [](base::RepeatingCallback<void()> callback, uint32_t error,
         const std::string& message) {
        LOG(ERROR) << "Sensor service disconnected\n"
                   << "Error code: " << error << ", message: " << message;
        callback.Run();
      },
      connection_error_callback_));

  is_initialized = true;
}

cros::mojom::SensorDevice* MojoServiceUtilsImpl::GetSensorDevice(
    int device_id) {
  if (!is_initialized) {
    LOG(ERROR) << "The service is not yet initialized.";
    return nullptr;
  }

  // Bind the Sensor Device if it's not bound yet.
  if (sensor_devices_map_.find(device_id) == sensor_devices_map_.end() ||
      !sensor_devices_map_[device_id].is_bound()) {
    sensor_service_->GetDevice(
        device_id, sensor_devices_map_[device_id].BindNewPipeAndPassReceiver());
    sensor_devices_map_[device_id].set_disconnect_with_reason_handler(
        base::BindOnce(
            [](int device_id, base::RepeatingCallback<void()> callback,
               uint32_t error, const std::string& message) {
              LOG(ERROR) << "Device " << device_id << " disconnected\n"
                         << "Error code: " << error << ", message: " << message;
              callback.Run();
            },
            device_id, connection_error_callback_));
  }

  return sensor_devices_map_[device_id].get();
}

void MojoServiceUtilsImpl::SetSensorServiceForTesting(
    mojo::PendingRemote<cros::mojom::SensorService> service) {
  sensor_service_.Bind(std::move(service));
}

void MojoServiceUtilsImpl::SetInitializedForTesting() {
  is_initialized = true;
}

void MojoServiceUtilsImpl::InsertDeviceForTesting(int device_id) {
  sensor_service_->GetDevice(
      device_id, sensor_devices_map_[device_id].BindNewPipeAndPassReceiver());
}

void MojoServiceUtilsImpl::SetConnectionErrorHandler(
    base::RepeatingCallback<void()> callback) {
  connection_error_callback_ = std::move(callback);
}

}  // namespace rmad
