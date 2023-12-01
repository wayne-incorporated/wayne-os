// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef POWER_MANAGER_POWERD_POLICY_MOCK_BACKLIGHT_CONTROLLER_H_
#define POWER_MANAGER_POWERD_POLICY_MOCK_BACKLIGHT_CONTROLLER_H_

#include <vector>

#include <gmock/gmock.h>

#include "power_manager/powerd/policy/ambient_light_handler.h"
#include "power_manager/powerd/policy/backlight_controller.h"

namespace power_manager {
namespace policy {

class MockBacklightController : public BacklightController,
                                public AmbientLightHandler::Delegate {
 public:
  MockBacklightController() = default;
  MockBacklightController(const MockBacklightController&) = delete;
  MockBacklightController& operator=(const MockBacklightController&) = delete;
  ~MockBacklightController() override = default;

  // BacklightController methods
  MOCK_METHOD(void,
              AddObserver,
              (BacklightControllerObserver * observer),
              (override));
  MOCK_METHOD(void,
              RemoveObserver,
              (BacklightControllerObserver * observer),
              (override));
  MOCK_METHOD(void, HandlePowerSourceChange, (PowerSource source), (override));
  MOCK_METHOD(void, HandleDisplayModeChange, (DisplayMode mode), (override));
  MOCK_METHOD(void, HandleSessionStateChange, (SessionState state), (override));
  MOCK_METHOD(void, HandlePowerButtonPress, (), (override));
  MOCK_METHOD(void, HandleLidStateChange, (LidState state), (override));
  MOCK_METHOD(void, HandleUserActivity, (UserActivityType type), (override));
  MOCK_METHOD(void, HandleVideoActivity, (bool is_fullscreen), (override));
  MOCK_METHOD(void, HandleWakeNotification, (), (override));
  MOCK_METHOD(void, HandleHoverStateChange, (bool hovering), (override));
  MOCK_METHOD(void, HandleTabletModeChange, (TabletMode mode), (override));
  MOCK_METHOD(void,
              HandlePolicyChange,
              (const PowerManagementPolicy& policy),
              (override));
  MOCK_METHOD(void, HandleDisplayServiceStart, (), (override));
  MOCK_METHOD(void,
              HandleBatterySaverModeChange,
              (const BatterySaverModeState& state),
              (override));
  MOCK_METHOD(void, SetDimmedForInactivity, (bool dimmed), (override));
  MOCK_METHOD(void, SetOffForInactivity, (bool off), (override));
  MOCK_METHOD(void, SetSuspended, (bool suspended), (override));
  MOCK_METHOD(void, SetShuttingDown, (bool shutting_down), (override));
  MOCK_METHOD(void, SetForcedOff, (bool forced_off), (override));
  MOCK_METHOD(bool, GetForcedOff, (), (override));
  MOCK_METHOD(bool, GetBrightnessPercent, (double* percent), (override));
  MOCK_METHOD(int, GetNumAmbientLightSensorAdjustments, (), (const, override));
  MOCK_METHOD(int, GetNumUserAdjustments, (), (const, override));
  MOCK_METHOD(int64_t, PercentToLevel, (double percent), (const, override));
  MOCK_METHOD(double, LevelToPercent, (int64_t level), (const, override));
  MOCK_METHOD(void,
              RegisterAmbientLightResumeMetricsHandler,
              (AmbientLightOnResumeMetricsCallback callback),
              (override));

  // AmbientLightHandler::Delegate methods
  MOCK_METHOD(void,
              SetBrightnessPercentForAmbientLight,
              (double brightness_percent,
               AmbientLightHandler::BrightnessChangeCause cause),
              (override));
  MOCK_METHOD(void,
              OnColorTemperatureChanged,
              (int color_temperature),
              (override));
  MOCK_METHOD(void, ReportAmbientLightOnResumeMetrics, (int lux), (override));
  MOCK_METHOD(bool, IsUsingAmbientLight, (), (const, override));
};

}  // namespace policy

}  // namespace power_manager

#endif  // POWER_MANAGER_POWERD_POLICY_MOCK_BACKLIGHT_CONTROLLER_H_
