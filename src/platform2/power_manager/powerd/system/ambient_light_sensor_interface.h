// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef POWER_MANAGER_POWERD_SYSTEM_AMBIENT_LIGHT_SENSOR_INTERFACE_H_
#define POWER_MANAGER_POWERD_SYSTEM_AMBIENT_LIGHT_SENSOR_INTERFACE_H_

#include <base/files/file_path.h>

#include "power_manager/powerd/system/ambient_light_observer.h"

namespace power_manager::system {

class AmbientLightSensorInterface {
 public:
  AmbientLightSensorInterface() = default;
  AmbientLightSensorInterface(const AmbientLightSensorInterface&) = delete;
  AmbientLightSensorInterface& operator=(const AmbientLightSensorInterface&) =
      delete;
  virtual ~AmbientLightSensorInterface() = default;

  // Adds or removes observers for sensor readings.
  virtual void AddObserver(AmbientLightObserver* observer) = 0;
  virtual void RemoveObserver(AmbientLightObserver* observer) = 0;

  // Whether or not this ALS supports color readings.
  virtual bool IsColorSensor() const = 0;

  // Used by observers in their callback to get the raw reading from the sensor
  // for the ambient light level. -1 is considered an error value.
  virtual int GetAmbientLightLux() = 0;

  // Latest color temperature measured if supported. -1 is considered an error
  // value.
  virtual int GetColorTemperature() = 0;

  // Returns the path to the illuminance file being monitored, or an empty path
  // if a device has not yet been found.
  virtual base::FilePath GetIlluminancePath() const = 0;
};

}  // namespace power_manager::system

#endif  // POWER_MANAGER_POWERD_SYSTEM_AMBIENT_LIGHT_SENSOR_INTERFACE_H_
