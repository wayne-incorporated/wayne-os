// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef POWER_MANAGER_POWERD_SYSTEM_SENSOR_SERVICE_HANDLER_OBSERVER_H_
#define POWER_MANAGER_POWERD_SYSTEM_SENSOR_SERVICE_HANDLER_OBSERVER_H_

#include <vector>

#include <base/observer_list_types.h>
#include <iioservice/mojo/sensor.mojom.h>

namespace power_manager::system {

class SensorServiceHandler;

class SensorServiceHandlerObserver : public base::CheckedObserver {
 public:
  virtual void OnNewDeviceAdded(
      int32_t iio_device_id,
      const std::vector<cros::mojom::DeviceType>& types) = 0;

  virtual void SensorServiceConnected() = 0;
  virtual void SensorServiceDisconnected() = 0;

  ~SensorServiceHandlerObserver() override;

 protected:
  // Will add itself to |sensor_service_handler_| in c'tor, and remove itself in
  // d'tor.
  explicit SensorServiceHandlerObserver(
      SensorServiceHandler* sensor_service_handler);

  SensorServiceHandler* sensor_service_handler_;
};

}  // namespace power_manager::system

#endif  // POWER_MANAGER_POWERD_SYSTEM_SENSOR_SERVICE_HANDLER_OBSERVER_H_
