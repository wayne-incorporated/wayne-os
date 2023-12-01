// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef POWER_MANAGER_POWERD_SYSTEM_AMBIENT_LIGHT_SENSOR_WATCHER_OBSERVER_STUB_H_
#define POWER_MANAGER_POWERD_SYSTEM_AMBIENT_LIGHT_SENSOR_WATCHER_OBSERVER_STUB_H_

#include "power_manager/powerd/system/ambient_light_sensor_watcher_observer.h"

#include <vector>

#include "power_manager/powerd/system/ambient_light_sensor_watcher_interface.h"

namespace power_manager::system {

// Stub implementation of AmbientLightSensorWatcherObserver.
class AmbientLightSensorWatcherObserverStub
    : public AmbientLightSensorWatcherObserver {
 public:
  explicit AmbientLightSensorWatcherObserverStub(
      AmbientLightSensorWatcherInterface* watcher);

  AmbientLightSensorWatcherObserverStub(
      const AmbientLightSensorWatcherObserverStub&) = delete;
  AmbientLightSensorWatcherObserverStub& operator=(
      const AmbientLightSensorWatcherObserverStub&) = delete;

  ~AmbientLightSensorWatcherObserverStub() override;

  int num_als_changes() const;
  int num_als() const;

  // AmbientLightSensorWatcherObserver implementation:
  void OnAmbientLightSensorsChanged(
      const std::vector<AmbientLightSensorInfo>& displays) override;

 private:
  AmbientLightSensorWatcherInterface* watcher_;  // Not owned.
  // Number of times that OnAmbientLightSensorsChanged() has been called.
  int num_als_changes_ = 0;
  int num_als_ = 0;
};

}  // namespace power_manager::system

#endif  // POWER_MANAGER_POWERD_SYSTEM_AMBIENT_LIGHT_SENSOR_WATCHER_OBSERVER_STUB_H_
