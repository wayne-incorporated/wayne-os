// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef POWER_MANAGER_POWERD_SYSTEM_FAKE_SENSOR_DEVICE_H_
#define POWER_MANAGER_POWERD_SYSTEM_FAKE_SENSOR_DEVICE_H_

#include <map>
#include <optional>
#include <string>
#include <vector>

#include <iioservice/mojo/sensor.mojom.h>
#include <mojo/public/cpp/bindings/receiver_set.h>
#include <mojo/public/cpp/bindings/remote_set.h>

namespace power_manager::system {

class FakeSensorDevice : public cros::mojom::SensorDevice {
 public:
  mojo::ReceiverId AddReceiver(
      mojo::PendingReceiver<cros::mojom::SensorDevice> pending_receiver);
  bool HasReceivers() const;
  void ClearReceiverWithReason(
      cros::mojom::SensorDeviceDisconnectReason reason =
          cros::mojom::SensorDeviceDisconnectReason::IIOSERVICE_CRASHED,
      const std::string& description = "");

  void ResetSamplesObserverRemote(mojo::ReceiverId id);

  void SetAttribute(std::string attr_name, std::string value);

  virtual cros::mojom::DeviceType GetDeviceType() const = 0;

  void OnSampleUpdated(const base::flat_map<int32_t, int64_t>& sample);
  void OnEventUpdated(cros::mojom::IioEventPtr event);

  // Implementation of cros::mojom::SensorDevice.
  void SetTimeout(uint32_t timeout) override {}
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

 protected:
  std::map<std::string, std::string> attributes_;

  std::map<mojo::ReceiverId,
           mojo::Remote<cros::mojom::SensorDeviceSamplesObserver>>
      samples_observers_;

  mojo::RemoteSet<cros::mojom::SensorDeviceEventsObserver> events_observers_;
  std::map<mojo::RemoteSetElementId, std::vector<int32_t>>
      events_enabled_indices_;

  mojo::ReceiverSet<cros::mojom::SensorDevice> receiver_set_;
};

}  // namespace power_manager::system

#endif  // POWER_MANAGER_POWERD_SYSTEM_FAKE_SENSOR_DEVICE_H_
