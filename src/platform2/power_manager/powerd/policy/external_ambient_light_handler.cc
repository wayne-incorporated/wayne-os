// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/powerd/policy/external_ambient_light_handler.h"

#include <memory>
#include <string>
#include <utility>

#include "power_manager/powerd/system/ambient_light_sensor_interface.h"

namespace power_manager::policy {

ExternalAmbientLightHandler::ExternalAmbientLightHandler(
    std::unique_ptr<system::AmbientLightSensorInterface> sensor,
    const system::DisplayInfo& display_info,
    Delegate* delegate)
    : sensor_(std::move(sensor)),
      display_info_(display_info),
      delegate_(delegate),
      handler_(sensor_.get(), this) {
  DCHECK(sensor_);
  DCHECK(delegate_);
  handler_.set_name(display_info.drm_path.value());
}

void ExternalAmbientLightHandler::Init(const std::string& steps_pref_value,
                                       double initial_brightness_percent,
                                       double smoothing_constant) {
  handler_.Init(steps_pref_value, initial_brightness_percent,
                smoothing_constant);
}

void ExternalAmbientLightHandler::HandlePowerSourceChange(PowerSource source) {
  handler_.HandlePowerSourceChange(source);
}

void ExternalAmbientLightHandler::HandleResume() {
  handler_.HandleResume();
}

void ExternalAmbientLightHandler::SetBrightnessPercentForAmbientLight(
    double brightness_percent,
    AmbientLightHandler::BrightnessChangeCause cause) {
  delegate_->SetBrightnessPercentForAmbientLight(display_info_,
                                                 brightness_percent);
}

void ExternalAmbientLightHandler::OnColorTemperatureChanged(
    int color_temperature) {}

}  // namespace power_manager::policy
