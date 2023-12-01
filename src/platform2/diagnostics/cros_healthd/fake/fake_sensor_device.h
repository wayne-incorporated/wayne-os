// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_FAKE_FAKE_SENSOR_DEVICE_H_
#define DIAGNOSTICS_CROS_HEALTHD_FAKE_FAKE_SENSOR_DEVICE_H_

#include <string>
#include <vector>

#include <iioservice/mojo/sensor.mojom.h>
#include <mojo/public/cpp/bindings/pending_remote.h>
#include <mojo/public/cpp/bindings/receiver.h>
#include <mojo/public/cpp/bindings/remote.h>

namespace diagnostics {

// Fake implementation of SensorDevice.
class FakeSensorDevice : public cros::mojom::SensorDevice {
 public:
  explicit FakeSensorDevice(
      const std::optional<std::string>& name,
      const std::optional<std::string>& location,
      const std::vector<std::string>& channels = {},
      base::OnceClosure on_start_reading = base::DoNothing());
  FakeSensorDevice(const FakeSensorDevice&) = delete;
  FakeSensorDevice& operator=(const FakeSensorDevice&) = delete;
  ~FakeSensorDevice() override = default;

  // Getter for the mojo receiver of SensorDevice, bound in FakeSensorService.
  mojo::Receiver<cros::mojom::SensorDevice>& receiver() { return receiver_; }
  // Getter for the observer remote, bound when |StartReadingSamples| is called
  // and used for sending fake samples and observer errors.
  mojo::Remote<cros::mojom::SensorDeviceSamplesObserver>& observer() {
    return observer_;
  }

  // Fake property setters.
  inline void set_return_frequency(std::optional<double> frequency) {
    return_frequency_ = frequency;
  }
  inline void set_failed_channel_indices(std::vector<int32_t> indices) {
    failed_channel_indices_ = indices;
  }

 private:
  // cros::mojom::SensorDevice overrides.
  void SetTimeout(uint32_t timeout) override;
  void GetAttributes(const std::vector<std::string>& attr_names,
                     GetAttributesCallback callback) override;
  void SetFrequency(double frequency, SetFrequencyCallback callback) override;
  void StartReadingSamples(
      mojo::PendingRemote<cros::mojom::SensorDeviceSamplesObserver> observer)
      override;
  void StopReadingSamples() override;
  void GetAllChannelIds(GetAllChannelIdsCallback callback) override;
  void SetChannelsEnabled(const std::vector<int32_t>& iio_chn_indices,
                          bool en,
                          SetChannelsEnabledCallback callback) override;
  void GetChannelsEnabled(const std::vector<int32_t>& iio_chn_indices,
                          GetChannelsEnabledCallback callback) override;
  void GetChannelsAttributes(const std::vector<int32_t>& iio_chn_indices,
                             const std::string& attr_name,
                             GetChannelsAttributesCallback callback) override;
  void GetAllEvents(GetAllEventsCallback callback) override;
  void GetEventsAttributes(const std::vector<int32_t>& iio_event_indices,
                           const std::string& attr_name,
                           GetEventsAttributesCallback callback) override;
  void StartReadingEvents(
      const std::vector<int32_t>& iio_event_indices,
      mojo::PendingRemote<cros::mojom::SensorDeviceEventsObserver> observer)
      override;

  // Mojo receiver for binding pipe.
  mojo::Receiver<cros::mojom::SensorDevice> receiver_{this};
  // Sensor attributes.
  std::optional<std::string> sensor_name_;
  std::optional<std::string> sensor_location_;
  // If |return_frequency_| is not null, return it instead of set frequency when
  // calling |SetFrequency|.
  std::optional<double> return_frequency_ = std::nullopt;
  // Sensor channel names.
  std::vector<std::string> sensor_channels_;
  // Channels indices that can not be enabled.
  std::vector<int32_t> failed_channel_indices_ = {};
  // Observer remote.
  mojo::Remote<cros::mojom::SensorDeviceSamplesObserver> observer_;
  // Start reading callback, triggered when |observer_| is bound.
  base::OnceClosure on_start_reading_;
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_FAKE_FAKE_SENSOR_DEVICE_H_
