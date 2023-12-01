// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/powerd/system/sensor_service_handler.h"

#include <algorithm>
#include <utility>

#include <base/functional/bind.h>
#include <base/task/single_thread_task_runner.h>

#include "power_manager/common/tracing.h"

namespace power_manager::system {
namespace {
constexpr uint32_t kMaxReconnectDelayInSeconds = 1000;
}  // namespace

SensorServiceHandler::SensorServiceHandler() = default;

SensorServiceHandler::~SensorServiceHandler() {
  ResetSensorService(false);
}

void SensorServiceHandler::SetUpChannel(
    mojo::PendingRemote<cros::mojom::SensorService> pending_remote,
    OnIioSensorDisconnectCallback on_iio_sensor_disconnect_callback) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  if (sensor_service_remote_.is_bound()) {
    LOG(ERROR) << "Ignoring the second Remote<SensorService>";
    return;
  }

  on_iio_sensor_disconnect_callback_ =
      std::move(on_iio_sensor_disconnect_callback);

  sensor_service_remote_.Bind(std::move(pending_remote));
  sensor_service_remote_.set_disconnect_handler(
      base::BindOnce(&SensorServiceHandler::OnSensorServiceDisconnect,
                     base::Unretained(this)));

  sensor_service_remote_->RegisterNewDevicesObserver(
      new_devices_observer_.BindNewPipeAndPassRemote());
  new_devices_observer_.set_disconnect_handler(
      base::BindOnce(&SensorServiceHandler::OnNewDevicesObserverDisconnect,
                     base::Unretained(this)));

  sensor_service_remote_->GetAllDeviceIds(base::BindOnce(
      &SensorServiceHandler::GetAllDeviceIdsCallback, base::Unretained(this)));

  for (auto& observer : observers_)
    observer.SensorServiceConnected();
}

void SensorServiceHandler::OnNewDeviceAdded(
    int32_t iio_device_id, const std::vector<cros::mojom::DeviceType>& types) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  iio_device_ids_types_.emplace(iio_device_id, types);

  for (auto& observer : observers_)
    observer.OnNewDeviceAdded(iio_device_id, types);
}

void SensorServiceHandler::AddObserver(SensorServiceHandlerObserver* observer) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  observers_.AddObserver(observer);

  base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
      FROM_HERE,
      base::BindOnce(&SensorServiceHandler::NotifyObserverWithCurrentDevices,
                     weak_factory_.GetWeakPtr(), observer));
}

void SensorServiceHandler::RemoveObserver(
    SensorServiceHandlerObserver* observer) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  observers_.RemoveObserver(observer);
}

void SensorServiceHandler::GetDevice(
    int32_t iio_device_id,
    mojo::PendingReceiver<cros::mojom::SensorDevice> pending_receiver) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  DCHECK(sensor_service_remote_.is_bound());

  sensor_service_remote_->GetDevice(iio_device_id, std::move(pending_receiver));
}

void SensorServiceHandler::OnSensorServiceDisconnect() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  LOG(ERROR) << "SensorService connection lost";

  ResetSensorService();
}

void SensorServiceHandler::OnNewDevicesObserverDisconnect() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  LOG(ERROR)
      << "OnNewDevicesObserverDisconnect, resetting SensorService as "
         "IIO Service should be destructed and waiting for it to relaunch.";
  ResetSensorService();
}

void SensorServiceHandler::ResetSensorService(bool reconnect) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  if (sensor_service_remote_.is_bound()) {
    for (auto& observer : observers_)
      observer.SensorServiceDisconnected();
  }

  new_devices_observer_.reset();
  sensor_service_remote_.reset();

  iio_device_ids_types_.clear();

  if (!reconnect) {
    on_iio_sensor_disconnect_callback_.Reset();
    return;
  }

  if (on_iio_sensor_disconnect_callback_) {
    std::move(on_iio_sensor_disconnect_callback_)
        .Run(base::Seconds(reconnect_delay_in_seconds_));

    reconnect_delay_in_seconds_ =
        std::min(reconnect_delay_in_seconds_ * 2, kMaxReconnectDelayInSeconds);
  }
}

void SensorServiceHandler::GetAllDeviceIdsCallback(
    const base::flat_map<int32_t, std::vector<cros::mojom::DeviceType>>&
        iio_device_ids_types) {
  // Reset reconnect delay upon successful reconnection.
  reconnect_delay_in_seconds_ = 1;

  iio_device_ids_types_ = iio_device_ids_types;

  for (auto& observer : observers_)
    NotifyObserverWithCurrentDevices(&observer);
}

void SensorServiceHandler::NotifyObserverWithCurrentDevices(
    SensorServiceHandlerObserver* observer) {
  TRACE_EVENT("power",
              "SensorServiceHandler::NotifyObserverWithCurrentDevices");
  for (auto& id_types : iio_device_ids_types_)
    observer->OnNewDeviceAdded(id_types.first, id_types.second);
}

}  // namespace power_manager::system
