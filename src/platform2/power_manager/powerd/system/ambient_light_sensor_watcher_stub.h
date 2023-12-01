// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef POWER_MANAGER_POWERD_SYSTEM_AMBIENT_LIGHT_SENSOR_WATCHER_STUB_H_
#define POWER_MANAGER_POWERD_SYSTEM_AMBIENT_LIGHT_SENSOR_WATCHER_STUB_H_

#include "power_manager/powerd/system/ambient_light_sensor_watcher_interface.h"

namespace power_manager::system {

// Stub implementation of AmbientLightSensorWatcherInterface for testing.
class AmbientLightSensorWatcherStub
    : public AmbientLightSensorWatcherInterface {
 public:
  AmbientLightSensorWatcherStub() = default;
  AmbientLightSensorWatcherStub(const AmbientLightSensorWatcherStub&) = delete;
  AmbientLightSensorWatcherStub& operator=(
      const AmbientLightSensorWatcherStub&) = delete;

  ~AmbientLightSensorWatcherStub() override = default;

  void AddSensor(const AmbientLightSensorInfo& device_info);
  void RemoveSensor(const AmbientLightSensorInfo& device_info);
};

}  // namespace power_manager::system

#endif  // POWER_MANAGER_POWERD_SYSTEM_AMBIENT_LIGHT_SENSOR_WATCHER_STUB_H_
