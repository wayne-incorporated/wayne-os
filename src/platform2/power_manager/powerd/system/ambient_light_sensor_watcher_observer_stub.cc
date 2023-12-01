// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/powerd/system/ambient_light_sensor_watcher_observer_stub.h"

namespace power_manager::system {

AmbientLightSensorWatcherObserverStub::AmbientLightSensorWatcherObserverStub(
    AmbientLightSensorWatcherInterface* watcher)
    : watcher_(watcher) {
  watcher_->AddObserver(this);
}

AmbientLightSensorWatcherObserverStub::
    ~AmbientLightSensorWatcherObserverStub() {
  watcher_->RemoveObserver(this);
}

int AmbientLightSensorWatcherObserverStub::num_als_changes() const {
  return num_als_changes_;
}

int AmbientLightSensorWatcherObserverStub::num_als() const {
  return num_als_;
}

void AmbientLightSensorWatcherObserverStub::OnAmbientLightSensorsChanged(
    const std::vector<AmbientLightSensorInfo>& displays) {
  num_als_changes_++;
  num_als_ = displays.size();
}

}  // namespace power_manager::system
