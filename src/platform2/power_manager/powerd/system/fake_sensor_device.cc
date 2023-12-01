// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/powerd/system/fake_sensor_device.h"

#include <optional>
#include <utility>

#include <base/check.h>
#include <base/logging.h>

namespace power_manager::system {

mojo::ReceiverId FakeSensorDevice::AddReceiver(
    mojo::PendingReceiver<cros::mojom::SensorDevice> pending_receiver) {
  return receiver_set_.Add(this, std::move(pending_receiver));
}

bool FakeSensorDevice::HasReceivers() const {
  return !receiver_set_.empty();
}

void FakeSensorDevice::ClearReceiverWithReason(
    cros::mojom::SensorDeviceDisconnectReason reason,
    const std::string& description) {
  uint32_t custom_reason_code = base::checked_cast<uint32_t>(reason);

  for (auto& observer : samples_observers_) {
    auto remote = mojo::Remote<cros::mojom::SensorDeviceSamplesObserver>(
        std::move(observer.second));
    remote.ResetWithReason(custom_reason_code, description);
  }
  samples_observers_.clear();

  receiver_set_.ClearWithReason(custom_reason_code, description);
}

void FakeSensorDevice::ResetSamplesObserverRemote(mojo::ReceiverId id) {
  auto it = samples_observers_.find(id);
  DCHECK(it != samples_observers_.end());

  samples_observers_.erase(it);
}

void FakeSensorDevice::OnSampleUpdated(
    const base::flat_map<int32_t, int64_t>& sample) {
  for (auto& samples_observer : samples_observers_)
    samples_observer.second->OnSampleUpdated(std::move(sample));
}

void FakeSensorDevice::OnEventUpdated(cros::mojom::IioEventPtr event) {
  for (auto& events_observer : events_observers_)
    events_observer->OnEventUpdated(event.Clone());
}

void FakeSensorDevice::SetAttribute(std::string attr_name, std::string value) {
  attributes_[attr_name] = value;
}

void FakeSensorDevice::GetAttributes(const std::vector<std::string>& attr_names,
                                     GetAttributesCallback callback) {
  std::vector<std::optional<std::string>> attr_values;
  attr_values.reserve(attr_names.size());
  for (const auto& attr_name : attr_names) {
    auto it = attributes_.find(attr_name);
    if (it != attributes_.end())
      attr_values.push_back(it->second);
    else
      attr_values.push_back(std::nullopt);
  }

  std::move(callback).Run(std::move(attr_values));
}

void FakeSensorDevice::SetFrequency(double frequency,
                                    SetFrequencyCallback callback) {
  std::move(callback).Run(frequency);
}

void FakeSensorDevice::StartReadingSamples(
    mojo::PendingRemote<cros::mojom::SensorDeviceSamplesObserver> observer) {
  mojo::ReceiverId id = receiver_set_.current_receiver();
  auto it = samples_observers_.find(id);
  if (it != samples_observers_.end()) {
    LOG(ERROR) << "Failed to start reading samples: Already started";
    mojo::Remote<cros::mojom::SensorDeviceSamplesObserver>(std::move(observer))
        ->OnErrorOccurred(cros::mojom::ObserverErrorType::ALREADY_STARTED);
    return;
  }

  samples_observers_[id].Bind(std::move(observer));
}

void FakeSensorDevice::StopReadingSamples() {
  samples_observers_.erase(receiver_set_.current_receiver());
}

void FakeSensorDevice::GetAllChannelIds(GetAllChannelIdsCallback callback) {
  std::move(callback).Run({});
}

void FakeSensorDevice::SetChannelsEnabled(
    const std::vector<int32_t>& iio_chn_indices,
    bool en,
    SetChannelsEnabledCallback callback) {
  std::move(callback).Run({});
}

void FakeSensorDevice::GetChannelsEnabled(
    const std::vector<int32_t>& iio_chn_indices,
    GetChannelsEnabledCallback callback) {
  std::move(callback).Run(
      std::move(std::vector<bool>(iio_chn_indices.size(), true)));
}

void FakeSensorDevice::GetChannelsAttributes(
    const std::vector<int32_t>& iio_chn_indices,
    const std::string& attr_name,
    GetChannelsAttributesCallback callback) {
  std::move(callback).Run(std::move(std::vector<std::optional<std::string>>(
      iio_chn_indices.size(), std::nullopt)));
}

void FakeSensorDevice::GetAllEvents(GetAllEventsCallback callback) {
  std::move(callback).Run({});
}

void FakeSensorDevice::GetEventsAttributes(
    const std::vector<int32_t>& iio_event_indices,
    const std::string& attr_name,
    GetEventsAttributesCallback callback) {
  std::move(callback).Run(std::vector<std::optional<std::string>>(
      iio_event_indices.size(), std::nullopt));
}

void FakeSensorDevice::StartReadingEvents(
    const std::vector<int32_t>& iio_event_indices,
    mojo::PendingRemote<cros::mojom::SensorDeviceEventsObserver> observer) {
  events_enabled_indices_[events_observers_.Add(std::move(observer))] =
      iio_event_indices;
}

}  // namespace power_manager::system
