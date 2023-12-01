// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/fake/fake_sensor_device.h"

#include <utility>

namespace diagnostics {

FakeSensorDevice::FakeSensorDevice(const std::optional<std::string>& name,
                                   const std::optional<std::string>& location,
                                   const std::vector<std::string>& channels,
                                   base::OnceClosure on_start_reading)
    : sensor_name_(name),
      sensor_location_(location),
      sensor_channels_(channels),
      on_start_reading_(std::move(on_start_reading)) {}

void FakeSensorDevice::SetTimeout(uint32_t timeout) {
  NOTIMPLEMENTED();
}

void FakeSensorDevice::GetAttributes(const std::vector<std::string>& attr_names,
                                     GetAttributesCallback callback) {
  CHECK(!attr_names.empty());

  std::vector<std::optional<std::string>> values(attr_names.size());
  for (int i = 0; i < attr_names.size(); i++) {
    if (attr_names[i] == cros::mojom::kDeviceName) {
      values[i] = sensor_name_;
    } else if (attr_names[i] == cros::mojom::kLocation) {
      values[i] = sensor_location_;
    } else {
      NOTREACHED() << "Unexpected attribute name: " << attr_names[i];
    }
  }
  std::move(callback).Run(values);
}

void FakeSensorDevice::SetFrequency(double frequency,
                                    SetFrequencyCallback callback) {
  std::move(callback).Run(return_frequency_.value_or(frequency));
}

void FakeSensorDevice::StartReadingSamples(
    mojo::PendingRemote<cros::mojom::SensorDeviceSamplesObserver> observer) {
  observer_.reset();
  observer_.Bind(std::move(observer));
  if (on_start_reading_)
    std::move(on_start_reading_).Run();
}

void FakeSensorDevice::StopReadingSamples() {
  observer_.reset();
}

void FakeSensorDevice::GetAllChannelIds(GetAllChannelIdsCallback callback) {
  std::move(callback).Run(sensor_channels_);
}

void FakeSensorDevice::SetChannelsEnabled(
    const std::vector<int32_t>& iio_chn_indices,
    bool en,
    SetChannelsEnabledCallback callback) {
  std::move(callback).Run(failed_channel_indices_);
}

void FakeSensorDevice::GetChannelsEnabled(
    const std::vector<int32_t>& iio_chn_indices,
    GetChannelsEnabledCallback callback) {
  NOTIMPLEMENTED();
}

void FakeSensorDevice::GetChannelsAttributes(
    const std::vector<int32_t>& iio_chn_indices,
    const std::string& attr_name,
    GetChannelsAttributesCallback callback) {
  NOTIMPLEMENTED();
}

void FakeSensorDevice::GetAllEvents(GetAllEventsCallback callback) {
  NOTIMPLEMENTED();
}

void FakeSensorDevice::GetEventsAttributes(
    const std::vector<int32_t>& iio_event_indices,
    const std::string& attr_name,
    GetEventsAttributesCallback callback) {
  NOTIMPLEMENTED();
}

void FakeSensorDevice::StartReadingEvents(
    const std::vector<int32_t>& iio_event_indices,
    mojo::PendingRemote<cros::mojom::SensorDeviceEventsObserver> observer) {
  NOTIMPLEMENTED();
}

}  // namespace diagnostics
