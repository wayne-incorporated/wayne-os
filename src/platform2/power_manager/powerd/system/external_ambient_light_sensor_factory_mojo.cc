// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/powerd/system/external_ambient_light_sensor_factory_mojo.h"

#include <utility>

#include "power_manager/powerd/system/ambient_light_sensor.h"
#include "power_manager/powerd/system/ambient_light_sensor_delegate_mojo.h"

namespace power_manager::system {

ExternalAmbientLightSensorFactoryMojo::ExternalAmbientLightSensorFactoryMojo(
    AmbientLightSensorWatcherMojo* watcher)
    : watcher_(watcher) {}

std::unique_ptr<AmbientLightSensorInterface>
ExternalAmbientLightSensorFactoryMojo::CreateSensor(
    const AmbientLightSensorInfo& als_info) const {
  auto remote = watcher_->GetDevice(als_info.id);
  DCHECK(remote.is_bound());

  auto delegate = AmbientLightSensorDelegateMojo::Create(
      als_info.id, std::move(remote), false);
  auto sensor = std::make_unique<AmbientLightSensor>();
  sensor->SetDelegate(std::move(delegate));
  return sensor;
}

}  // namespace power_manager::system
