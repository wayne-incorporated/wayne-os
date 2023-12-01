// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef POWER_MANAGER_POWERD_SYSTEM_AMBIENT_LIGHT_SENSOR_WATCHER_INTERFACE_H_
#define POWER_MANAGER_POWERD_SYSTEM_AMBIENT_LIGHT_SENSOR_WATCHER_INTERFACE_H_

#include <vector>

#include <base/observer_list.h>

#include "power_manager/powerd/system/ambient_light_sensor_info.h"
#include "power_manager/powerd/system/ambient_light_sensor_watcher_observer.h"

namespace power_manager::system {

// Watches for ambient light sensors being connected or disconnected.
class AmbientLightSensorWatcherInterface {
 public:
  virtual ~AmbientLightSensorWatcherInterface() = default;

  // Returns the current list of connected ambient light sensors.
  const std::vector<AmbientLightSensorInfo>& GetAmbientLightSensors() const;

  // Adds or removes an observer.
  void AddObserver(AmbientLightSensorWatcherObserver* observer);
  void RemoveObserver(AmbientLightSensorWatcherObserver* observer);

 protected:
  void AddSensorAndNotifyObservers(AmbientLightSensorInfo new_als);

  // Called when changes are made to |ambient_light_sensors_| to notify
  // observers.
  void NotifyObservers();

  // Currently-connected ambient light sensors.
  std::vector<AmbientLightSensorInfo> ambient_light_sensors_;

  base::ObserverList<AmbientLightSensorWatcherObserver> observers_;
};

}  // namespace power_manager::system

#endif  // POWER_MANAGER_POWERD_SYSTEM_AMBIENT_LIGHT_SENSOR_WATCHER_INTERFACE_H_
