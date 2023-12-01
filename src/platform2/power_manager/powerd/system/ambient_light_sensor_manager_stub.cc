// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/powerd/system/ambient_light_sensor_manager_stub.h"

#include <memory>
#include <string>

namespace power_manager::system {

AmbientLightSensorManagerStub::AmbientLightSensorManagerStub()
    : AmbientLightSensorManagerStub(0) {}

AmbientLightSensorManagerStub::AmbientLightSensorManagerStub(int lux) {
  internal_backlight_sensor_ =
      std::make_unique<system::AmbientLightSensorStub>(lux);
  keyboard_backlight_sensor_ =
      std::make_unique<system::AmbientLightSensorStub>(lux);
}

AmbientLightSensorManagerStub::~AmbientLightSensorManagerStub() = default;

bool AmbientLightSensorManagerStub::HasColorSensor() {
  return internal_backlight_sensor_->IsColorSensor() ||
         keyboard_backlight_sensor_->IsColorSensor();
}

AmbientLightSensorInterface*
AmbientLightSensorManagerStub::GetSensorForInternalBacklight() {
  return internal_backlight_sensor_.get();
}

AmbientLightSensorInterface*
AmbientLightSensorManagerStub::GetSensorForKeyboardBacklight() {
  return keyboard_backlight_sensor_.get();
}

}  // namespace power_manager::system
