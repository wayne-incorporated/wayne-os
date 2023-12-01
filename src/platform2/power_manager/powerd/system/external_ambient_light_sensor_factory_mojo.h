// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef POWER_MANAGER_POWERD_SYSTEM_EXTERNAL_AMBIENT_LIGHT_SENSOR_FACTORY_MOJO_H_
#define POWER_MANAGER_POWERD_SYSTEM_EXTERNAL_AMBIENT_LIGHT_SENSOR_FACTORY_MOJO_H_

#include <memory>

#include "power_manager/powerd/system/ambient_light_sensor_watcher_mojo.h"
#include "power_manager/powerd/system/external_ambient_light_sensor_factory_interface.h"

namespace power_manager::system {

// Creates external ambient light sensors that use
// AmbientLightSensorDelegateMojo.
class ExternalAmbientLightSensorFactoryMojo
    : public ExternalAmbientLightSensorFactoryInterface {
 public:
  explicit ExternalAmbientLightSensorFactoryMojo(
      AmbientLightSensorWatcherMojo* watcher);
  std::unique_ptr<AmbientLightSensorInterface> CreateSensor(
      const AmbientLightSensorInfo& als_info) const override;

  AmbientLightSensorWatcherMojo* watcher_ = nullptr;
};

}  // namespace power_manager::system

#endif  // POWER_MANAGER_POWERD_SYSTEM_EXTERNAL_AMBIENT_LIGHT_SENSOR_FACTORY_MOJO_H_
