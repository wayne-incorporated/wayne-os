// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef POWER_MANAGER_POWERD_POLICY_EXTERNAL_AMBIENT_LIGHT_HANDLER_H_
#define POWER_MANAGER_POWERD_POLICY_EXTERNAL_AMBIENT_LIGHT_HANDLER_H_

#include <memory>
#include <string>

#include <base/files/file_path.h>

#include "power_manager/powerd/policy/ambient_light_handler.h"
#include "power_manager/powerd/system/display/display_info.h"

namespace power_manager {

namespace system {
class AmbientLightSensorInterface;
}  // namespace system

namespace policy {

// Uses AmbientLightHandler to observe changes to an external ambient light
// sensor and make decisions about when backlight brightness should be adjusted.
// Stores the external display that corresponds to the external ambient light
// sensor.
class ExternalAmbientLightHandler : public AmbientLightHandler::Delegate {
 public:
  // Interface for classes that perform actions on behalf of
  // ExternalAmbientLightHandler.
  class Delegate {
   public:
    Delegate() = default;
    virtual ~Delegate() = default;

    // Invoked when the backlight brightness should be adjusted in response
    // to a change in ambient light.
    virtual void SetBrightnessPercentForAmbientLight(
        const system::DisplayInfo& display_info, double brightness_percent) = 0;
  };

  ExternalAmbientLightHandler(
      std::unique_ptr<system::AmbientLightSensorInterface> sensor,
      const system::DisplayInfo& display_info,
      Delegate* delegate);
  ExternalAmbientLightHandler(const ExternalAmbientLightHandler&) = delete;
  ExternalAmbientLightHandler& operator=(const ExternalAmbientLightHandler&) =
      delete;

  // See AmbientLightHandler::Init for details.
  void Init(const std::string& steps_pref_value,
            double initial_brightness_percent,
            double smoothing_constant);

  // Should be called when the power source changes.
  void HandlePowerSourceChange(PowerSource source);

  // Should be called when resuming.
  void HandleResume();

  // AmbientLightHandler::Delegate implementation:
  void SetBrightnessPercentForAmbientLight(
      double brightness_percent,
      AmbientLightHandler::BrightnessChangeCause cause) override;
  void OnColorTemperatureChanged(int color_temperature) override;

 private:
  std::unique_ptr<system::AmbientLightSensorInterface> sensor_;
  const system::DisplayInfo display_info_;
  Delegate* delegate_;
  AmbientLightHandler handler_;
};

}  // namespace policy
}  // namespace power_manager

#endif  // POWER_MANAGER_POWERD_POLICY_EXTERNAL_AMBIENT_LIGHT_HANDLER_H_
