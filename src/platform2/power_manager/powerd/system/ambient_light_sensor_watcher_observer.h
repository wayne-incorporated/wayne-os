// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef POWER_MANAGER_POWERD_SYSTEM_AMBIENT_LIGHT_SENSOR_WATCHER_OBSERVER_H_
#define POWER_MANAGER_POWERD_SYSTEM_AMBIENT_LIGHT_SENSOR_WATCHER_OBSERVER_H_

#include <vector>

#include <base/observer_list_types.h>

#include "power_manager/powerd/system/ambient_light_sensor_info.h"

namespace power_manager::system {

// Interface for receiving notifications from AmbientLightSensorWatcher about
// changes to ambient light sensors.
class AmbientLightSensorWatcherObserver : public base::CheckedObserver {
 public:
  // Called when an ambient light sensor is connected or disconnected.
  virtual void OnAmbientLightSensorsChanged(
      const std::vector<AmbientLightSensorInfo>& ambient_light_sensors) = 0;
};

}  // namespace power_manager::system

#endif  // POWER_MANAGER_POWERD_SYSTEM_AMBIENT_LIGHT_SENSOR_WATCHER_OBSERVER_H_
