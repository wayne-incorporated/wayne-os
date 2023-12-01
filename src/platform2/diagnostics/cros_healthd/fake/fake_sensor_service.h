// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_FAKE_FAKE_SENSOR_SERVICE_H_
#define DIAGNOSTICS_CROS_HEALTHD_FAKE_FAKE_SENSOR_SERVICE_H_

#include <map>
#include <memory>
#include <string>
#include <vector>

#include <iioservice/mojo/sensor.mojom.h>
#include <mojo/public/cpp/bindings/pending_remote.h>
#include <mojo/public/cpp/bindings/receiver.h>

#include "diagnostics/cros_healthd/fake/fake_sensor_device.h"

namespace diagnostics {

// Fake implementation of SensorService.
class FakeSensorService : public cros::mojom::SensorService {
 public:
  FakeSensorService() = default;
  FakeSensorService(const FakeSensorService&) = delete;
  FakeSensorService& operator=(const FakeSensorService&) = delete;
  ~FakeSensorService() override = default;

  // Getter for the mojo receiver.
  mojo::Receiver<cros::mojom::SensorService>& receiver() { return receiver_; }

  // Sets the fake sensor ids and types.
  void SetIdsTypes(
      const base::flat_map<int32_t, std::vector<cros::mojom::DeviceType>>&
          ids_types);

  // Sets the fake sensor device for the given sensor id.
  void SetSensorDevice(int32_t id, std::unique_ptr<FakeSensorDevice> device);

 private:
  // cros::mojom::SensorService overrides.
  void GetDeviceIds(cros::mojom::DeviceType type,
                    GetDeviceIdsCallback callback) override;
  void GetAllDeviceIds(GetAllDeviceIdsCallback callback) override;
  void GetDevice(
      int32_t iio_device_id,
      mojo::PendingReceiver<cros::mojom::SensorDevice> device_request) override;
  void RegisterNewDevicesObserver(
      mojo::PendingRemote<cros::mojom::SensorServiceNewDevicesObserver>
          observer) override;

  // First is the device id, second is the device's types.
  base::flat_map<int32_t, std::vector<cros::mojom::DeviceType>> ids_types_;
  // First is the device id, second is unique ptr to FakeSensorDevice.
  std::map<int32_t, std::unique_ptr<FakeSensorDevice>> ids_devices_;
  // Mojo receiver for binding pipe.
  mojo::Receiver<cros::mojom::SensorService> receiver_{this};
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_FAKE_FAKE_SENSOR_SERVICE_H_
