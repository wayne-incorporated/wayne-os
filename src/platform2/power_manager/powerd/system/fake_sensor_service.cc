// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/powerd/system/fake_sensor_service.h"

#include <utility>

namespace power_manager::system {

FakeSensorService::FakeSensorService() = default;
FakeSensorService::~FakeSensorService() = default;

void FakeSensorService::AddReceiver(
    mojo::PendingReceiver<cros::mojom::SensorService> pending_receiver) {
  receiver_set_.Add(this, std::move(pending_receiver));
}

void FakeSensorService::ClearReceivers() {
  receiver_set_.Clear();

  for (auto& [_, device_info] : device_infos_)
    device_info.sensor_device->ClearReceiverWithReason();
}

bool FakeSensorService::HasReceivers() const {
  return !receiver_set_.empty();
}

void FakeSensorService::SetSensorDevice(
    int32_t iio_device_id, std::unique_ptr<FakeSensorDevice> sensor_device) {
  auto type = sensor_device->GetDeviceType();
  DeviceInfo info = {.type = type, .sensor_device = std::move(sensor_device)};
  device_infos_[iio_device_id] = std::move(info);

  for (auto& observer : observers_) {
    observer->OnNewDeviceAdded(iio_device_id,
                               std::vector<cros::mojom::DeviceType>{type});
  }
}

void FakeSensorService::GetDeviceIds(cros::mojom::DeviceType type,
                                     GetDeviceIdsCallback callback) {
  std::vector<int32_t> ids;
  for (const auto& device_info : device_infos_) {
    if (device_info.second.type == type)
      ids.push_back(device_info.first);
  }

  base::SequencedTaskRunner::GetCurrentDefault()->PostTask(
      FROM_HERE, base::BindOnce(std::move(callback), std::move(ids)));
}

void FakeSensorService::GetAllDeviceIds(GetAllDeviceIdsCallback callback) {
  base::flat_map<int32_t, std::vector<cros::mojom::DeviceType>> id_types;
  for (const auto& device_info : device_infos_) {
    id_types.emplace(device_info.first, std::vector<cros::mojom::DeviceType>{
                                            device_info.second.type});
  }

  base::SequencedTaskRunner::GetCurrentDefault()->PostTask(
      FROM_HERE, base::BindOnce(std::move(callback), std::move(id_types)));
}

void FakeSensorService::GetDevice(
    int32_t iio_device_id,
    mojo::PendingReceiver<cros::mojom::SensorDevice> device_request) {
  auto it = device_infos_.find(iio_device_id);
  if (it == device_infos_.end())
    return;

  it->second.sensor_device->AddReceiver(std::move(device_request));
}

void FakeSensorService::RegisterNewDevicesObserver(
    mojo::PendingRemote<cros::mojom::SensorServiceNewDevicesObserver>
        observer) {
  observers_.emplace_back(std::move(observer));
}

}  // namespace power_manager::system
