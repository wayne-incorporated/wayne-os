// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef POWER_MANAGER_POWERD_SYSTEM_AMBIENT_LIGHT_SENSOR_MANAGER_INTERFACE_H_
#define POWER_MANAGER_POWERD_SYSTEM_AMBIENT_LIGHT_SENSOR_MANAGER_INTERFACE_H_

#include "power_manager/powerd/system/ambient_light_sensor_interface.h"

namespace power_manager::system {

class AmbientLightSensorManagerInterface {
 public:
  AmbientLightSensorManagerInterface() = default;
  AmbientLightSensorManagerInterface(
      const AmbientLightSensorManagerInterface&) = delete;
  AmbientLightSensorManagerInterface& operator=(
      const AmbientLightSensorManagerInterface&) = delete;
  virtual ~AmbientLightSensorManagerInterface() = default;

  virtual AmbientLightSensorInterface* GetSensorForInternalBacklight() = 0;
  virtual AmbientLightSensorInterface* GetSensorForKeyboardBacklight() = 0;

  virtual bool HasColorSensor() = 0;
};

}  // namespace power_manager::system

#endif  // POWER_MANAGER_POWERD_SYSTEM_AMBIENT_LIGHT_SENSOR_MANAGER_INTERFACE_H_
