// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef POWER_MANAGER_POWERD_SYSTEM_AMBIENT_LIGHT_SENSOR_WATCHER_MOJO_H_
#define POWER_MANAGER_POWERD_SYSTEM_AMBIENT_LIGHT_SENSOR_WATCHER_MOJO_H_

#include <map>
#include <optional>
#include <string>
#include <vector>

#include "power_manager/powerd/system/ambient_light_sensor_watcher_interface.h"
#include "power_manager/powerd/system/sensor_service_handler.h"
#include "power_manager/powerd/system/sensor_service_handler_observer.h"

namespace power_manager::system {

// Mojo implementation of AmbientLightSensorWatcherInterface that reports
// devices from iioserivce.
class AmbientLightSensorWatcherMojo : public AmbientLightSensorWatcherInterface,
                                      public SensorServiceHandlerObserver {
 public:
  explicit AmbientLightSensorWatcherMojo(
      SensorServiceHandler* sensor_service_handler);
  AmbientLightSensorWatcherMojo(const AmbientLightSensorWatcherMojo&) = delete;
  AmbientLightSensorWatcherMojo& operator=(
      const AmbientLightSensorWatcherMojo&) = delete;

  ~AmbientLightSensorWatcherMojo() override = default;

  // SensorServiceHandlerObserver overrides:
  void OnNewDeviceAdded(
      int32_t iio_device_id,
      const std::vector<cros::mojom::DeviceType>& types) override;
  void SensorServiceConnected() override;
  void SensorServiceDisconnected() override;

  // Passes the pending receiver to |sensor_service_handler_->GetDevice()|.
  mojo::Remote<cros::mojom::SensorDevice> GetDevice(int32_t iio_device_id);

 private:
  void GetSysPathCallback(
      int32_t iio_device_id,
      const std::vector<std::optional<std::string>>& values);

  void OnSensorDeviceDisconnect(int32_t iio_device_id,
                                uint32_t custom_reason_code,
                                const std::string& description);

  // SensorDevice mojo remotes to query attributes and wait for disconnections.
  std::map<int32_t, mojo::Remote<cros::mojom::SensorDevice>> device_remotes_;
};

}  // namespace power_manager::system

#endif  // POWER_MANAGER_POWERD_SYSTEM_AMBIENT_LIGHT_SENSOR_WATCHER_MOJO_H_
