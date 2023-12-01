// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/powerd/system/external_ambient_light_sensor_factory_file.h"

#include <utility>

#include "power_manager/powerd/system/ambient_light_sensor.h"
#include "power_manager/powerd/system/ambient_light_sensor_delegate_file.h"

namespace power_manager::system {

std::unique_ptr<AmbientLightSensorInterface>
ExternalAmbientLightSensorFactoryFile::CreateSensor(
    const AmbientLightSensorInfo& als_info) const {
  auto delegate =
      std::make_unique<AmbientLightSensorDelegateFile>(als_info.device, false);
  delegate->Init(false);
  auto sensor = std::make_unique<AmbientLightSensor>();
  sensor->SetDelegate(std::move(delegate));
  return sensor;
}

}  // namespace power_manager::system
