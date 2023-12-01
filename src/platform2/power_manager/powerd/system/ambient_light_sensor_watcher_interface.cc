// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/powerd/system/ambient_light_sensor_watcher_interface.h"

#include <string>
#include <utility>

namespace power_manager::system {

const std::vector<AmbientLightSensorInfo>&
AmbientLightSensorWatcherInterface::GetAmbientLightSensors() const {
  return ambient_light_sensors_;
}

void AmbientLightSensorWatcherInterface::AddObserver(
    AmbientLightSensorWatcherObserver* observer) {
  DCHECK(observer);
  observers_.AddObserver(observer);
}

void AmbientLightSensorWatcherInterface::RemoveObserver(
    AmbientLightSensorWatcherObserver* observer) {
  DCHECK(observer);
  observers_.RemoveObserver(observer);
}

void AmbientLightSensorWatcherInterface::AddSensorAndNotifyObservers(
    AmbientLightSensorInfo new_als) {
  // This is a hack to use only hot-pluggable HID-stack ALS, as there is no way
  // to determine that with iio device's attributes.
  if (new_als.iio_path.value().find("HID-SENSOR-200041") == std::string::npos) {
    return;
  }

  ambient_light_sensors_.push_back(std::move(new_als));
  NotifyObservers();
}

void AmbientLightSensorWatcherInterface::NotifyObservers() {
  for (auto& observer : observers_) {
    observer.OnAmbientLightSensorsChanged(ambient_light_sensors_);
  }
}

}  // namespace power_manager::system
