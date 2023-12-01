// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/powerd/policy/external_backlight_controller.h"

#include <algorithm>
#include <atomic>
#include <cmath>
#include <cstdlib>
#include <iterator>
#include <memory>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <chromeos/dbus/service_constants.h>

#include "power_manager/common/prefs.h"
#include "power_manager/powerd/policy/backlight_controller_observer.h"
#include "power_manager/powerd/system/ambient_light_sensor_watcher_interface.h"
#include "power_manager/powerd/system/dbus_wrapper.h"
#include "power_manager/powerd/system/display/display_power_setter.h"
#include "power_manager/powerd/system/display/display_watcher.h"
#include "power_manager/powerd/system/display/external_display.h"
#include "power_manager/powerd/system/external_ambient_light_sensor_factory_interface.h"

#include <base/check.h>
#include <base/logging.h>
#include <base/notreached.h>
#include <dbus/message.h>

namespace power_manager::policy {

namespace {

// Amount the brightness will be adjusted up or down in response to a user
// request, as a linearly-calculated percent in the range [0.0, 100.0].
constexpr double kBrightnessAdjustmentPercent = 5.0;

// Minimum number of syspath components that must be the same for an external
// display to be matched with an external ambient light sensor.
constexpr int kMinimumAssociationScore = 4;

// Constants used to initialize ExternalAmbientLightHandlers. See
// AmbientLightHandler::Init for a more detailed explanation of these values.
constexpr double kExternalAmbientLightHandlerInitialBrightness = 100.0;
constexpr double kExternalAmbientLightHandlerSmoothingConstant = 1.0;

}  // namespace

ExternalBacklightController::ExternalBacklightController()
    : weak_ptr_factory_(this) {}

ExternalBacklightController::~ExternalBacklightController() {
  if (display_watcher_)
    display_watcher_->RemoveObserver(this);
  if (ambient_light_sensor_watcher_) {
    ambient_light_sensor_watcher_->RemoveObserver(this);
  }
}

void ExternalBacklightController::Init(
    PrefsInterface* prefs,
    system::AmbientLightSensorWatcherInterface* ambient_light_sensor_watcher,
    system::ExternalAmbientLightSensorFactoryInterface*
        external_ambient_light_sensor_factory,
    system::DisplayWatcherInterface* display_watcher,
    system::DisplayPowerSetterInterface* display_power_setter,
    system::DBusWrapperInterface* dbus_wrapper) {
  prefs_ = prefs;
  ambient_light_sensor_watcher_ = ambient_light_sensor_watcher;
  external_ambient_light_sensor_factory_ =
      external_ambient_light_sensor_factory;
  if (ambient_light_sensor_watcher_) {
    external_display_als_brightness_enabled_ = true;
    CHECK(prefs_->GetString(kExternalBacklightAlsStepsPref,
                            &external_backlight_als_steps_))
        << "Failed to read pref " << kExternalBacklightAlsStepsPref;
    ambient_light_sensor_watcher_->AddObserver(this);
  }
  display_watcher_ = display_watcher;
  display_power_setter_ = display_power_setter;
  display_watcher_->AddObserver(this);
  dbus_wrapper_ = dbus_wrapper;

  RegisterSetBrightnessHandler(
      dbus_wrapper_, kSetScreenBrightnessMethod,
      base::BindRepeating(
          &ExternalBacklightController::HandleSetBrightnessRequest,
          weak_ptr_factory_.GetWeakPtr()));
  RegisterIncreaseBrightnessHandler(
      dbus_wrapper_, kIncreaseScreenBrightnessMethod,
      base::BindRepeating(
          &ExternalBacklightController::HandleIncreaseBrightnessRequest,
          weak_ptr_factory_.GetWeakPtr()));
  RegisterDecreaseBrightnessHandler(
      dbus_wrapper_, kDecreaseScreenBrightnessMethod,
      base::BindRepeating(
          &ExternalBacklightController::HandleDecreaseBrightnessRequest,
          weak_ptr_factory_.GetWeakPtr()));
  RegisterGetBrightnessHandler(
      dbus_wrapper_, kGetScreenBrightnessPercentMethod,
      base::BindRepeating(
          &ExternalBacklightController::HandleGetBrightnessRequest,
          weak_ptr_factory_.GetWeakPtr()));
  dbus_wrapper_->ExportMethod(
      kSetExternalDisplayALSBrightnessMethod,
      base::BindRepeating(&ExternalBacklightController::
                              HandleSetExternalDisplayALSBrightnessRequest,
                          weak_ptr_factory_.GetWeakPtr()));
  dbus_wrapper_->ExportMethod(
      kGetExternalDisplayALSBrightnessMethod,
      base::BindRepeating(&ExternalBacklightController::
                              HandleGetExternalDisplayALSBrightnessRequest,
                          weak_ptr_factory_.GetWeakPtr()));

  UpdateDisplays(display_watcher_->GetDisplays());
  if (ambient_light_sensor_watcher_) {
    external_ambient_light_sensors_info_ =
        ambient_light_sensor_watcher_->GetAmbientLightSensors();
    MatchAmbientLightSensorsToDisplays();
  }
}

void ExternalBacklightController::AddObserver(
    BacklightControllerObserver* observer) {
  DCHECK(observer);
  observers_.AddObserver(observer);
}

void ExternalBacklightController::RemoveObserver(
    BacklightControllerObserver* observer) {
  DCHECK(observer);
  observers_.RemoveObserver(observer);
}

void ExternalBacklightController::HandlePowerSourceChange(PowerSource source) {
  for (auto& [path, pair] : external_als_displays_) {
    if (pair.second) {
      pair.second->HandlePowerSourceChange(source);
    }
  }
}

void ExternalBacklightController::HandleDisplayModeChange(DisplayMode mode) {}

void ExternalBacklightController::HandleSessionStateChange(SessionState state) {
  if (state == SessionState::STARTED)
    num_brightness_adjustments_in_session_ = 0;
}

void ExternalBacklightController::HandlePowerButtonPress() {}

void ExternalBacklightController::HandleLidStateChange(LidState state) {}

void ExternalBacklightController::HandleVideoActivity(bool is_fullscreen) {}

void ExternalBacklightController::HandleHoverStateChange(bool hovering) {}

void ExternalBacklightController::HandleTabletModeChange(TabletMode mode) {}

void ExternalBacklightController::HandleUserActivity(UserActivityType type) {}

void ExternalBacklightController::HandleWakeNotification() {}

void ExternalBacklightController::HandlePolicyChange(
    const PowerManagementPolicy& policy) {}

void ExternalBacklightController::HandleDisplayServiceStart() {
  display_power_setter_->SetDisplaySoftwareDimming(dimmed_for_inactivity_);
  display_power_setter_->SetDisplayPower(currently_off_
                                             ? chromeos::DISPLAY_POWER_ALL_OFF
                                             : chromeos::DISPLAY_POWER_ALL_ON,
                                         base::TimeDelta());
  NotifyObservers(BacklightBrightnessChange_Cause_OTHER);
}

void ExternalBacklightController::HandleBatterySaverModeChange(
    const BatterySaverModeState& state) {
  // TODO(sxm): Figure out how to distinguish USB-powered displays and dim here.
}

void ExternalBacklightController::SetDimmedForInactivity(bool dimmed) {
  if (dimmed != dimmed_for_inactivity_) {
    dimmed_for_inactivity_ = dimmed;
    display_power_setter_->SetDisplaySoftwareDimming(dimmed);
  }
}

void ExternalBacklightController::SetOffForInactivity(bool off) {
  if (off == off_for_inactivity_)
    return;
  off_for_inactivity_ = off;
  UpdateScreenPowerState(off ? BacklightBrightnessChange_Cause_USER_INACTIVITY
                             : BacklightBrightnessChange_Cause_USER_ACTIVITY);
}

void ExternalBacklightController::SetSuspended(bool suspended) {
  if (suspended == suspended_)
    return;
  suspended_ = suspended;
  UpdateScreenPowerState(BacklightBrightnessChange_Cause_OTHER);

  if (!suspended) {
    for (auto& [path, pair] : external_als_displays_) {
      if (pair.second) {
        pair.second->HandleResume();
      }
    }
  }
}

void ExternalBacklightController::SetShuttingDown(bool shutting_down) {
  if (shutting_down == shutting_down_)
    return;
  shutting_down_ = shutting_down;
  UpdateScreenPowerState(BacklightBrightnessChange_Cause_OTHER);
}

bool ExternalBacklightController::GetBrightnessPercent(double* percent) {
  bool success = false;
  HandleGetBrightnessRequest(percent, &success);
  return success;
}

void ExternalBacklightController::SetForcedOff(bool forced_off) {
  if (forced_off_ == forced_off)
    return;

  forced_off_ = forced_off;
  UpdateScreenPowerState(
      forced_off ? BacklightBrightnessChange_Cause_FORCED_OFF
                 : BacklightBrightnessChange_Cause_NO_LONGER_FORCED_OFF);
}

bool ExternalBacklightController::GetForcedOff() {
  return forced_off_;
}

int ExternalBacklightController::GetNumAmbientLightSensorAdjustments() const {
  return 0;
}

int ExternalBacklightController::GetNumUserAdjustments() const {
  return num_brightness_adjustments_in_session_;
}

double ExternalBacklightController::LevelToPercent(int64_t level) const {
  // This class doesn't have any knowledge of hardware backlight levels (since
  // it can simultaneously control multiple heterogeneous displays).
  NOTIMPLEMENTED();
  return 0.0;
}

int64_t ExternalBacklightController::PercentToLevel(double percent) const {
  NOTIMPLEMENTED();
  return 0;
}

void ExternalBacklightController::OnDisplaysChanged(
    const std::vector<system::DisplayInfo>& displays) {
  UpdateDisplays(displays);
  if (ambient_light_sensor_watcher_) {
    MatchAmbientLightSensorsToDisplays();
  }
}

void ExternalBacklightController::OnAmbientLightSensorsChanged(
    const std::vector<system::AmbientLightSensorInfo>& ambient_light_sensors) {
  external_ambient_light_sensors_info_ = ambient_light_sensors;
  MatchAmbientLightSensorsToDisplays();
}

void ExternalBacklightController::HandleIncreaseBrightnessRequest() {
  num_brightness_adjustments_in_session_++;
  AdjustBrightnessByPercent(kBrightnessAdjustmentPercent);
}

void ExternalBacklightController::HandleDecreaseBrightnessRequest(
    bool allow_off) {
  num_brightness_adjustments_in_session_++;
  AdjustBrightnessByPercent(-kBrightnessAdjustmentPercent);
}

void ExternalBacklightController::HandleSetBrightnessRequest(
    double percent,
    Transition transition,
    SetBacklightBrightnessRequest_Cause cause) {
  // Silently ignore requests to set to a specific percent. External displays
  // are buggy and DDC/CI is racy if the user is simultaneously adjusting the
  // brightness using physical buttons. Instead, we only support increasing and
  // decreasing the brightness.

  // However, exceptions are made for external displays with ambient light
  // sensors. Only allow setting the brightness on external displays with
  // ambient light sensors, and only if ALS-based brightness is disabled.
  if (ambient_light_sensor_watcher_ &&
      !external_display_als_brightness_enabled_) {
    for (auto& [path, pair] : external_als_displays_) {
      SetBrightnessPercentForAmbientLight(pair.first, percent);
    }
    external_display_with_ambient_light_sensor_brightness_ = percent;
    ++num_brightness_adjustments_in_session_;
  }
}

void ExternalBacklightController::HandleGetBrightnessRequest(
    double* percent_out, bool* success_out) {
  // See HandleSetBrightnessRequest.

  // However, exceptions are made for external displays with ambient light
  // sensors. Only allow getting the brightness for external displays with
  // ambient light sensors, and only if ALS-based brightness is disabled.
  if (ambient_light_sensor_watcher_ &&
      !external_display_als_brightness_enabled_) {
    *percent_out = external_display_with_ambient_light_sensor_brightness_;
    *success_out = true;
    return;
  }

  *success_out = false;
}

void ExternalBacklightController::UpdateScreenPowerState(
    BacklightBrightnessChange_Cause cause) {
  bool should_turn_off =
      off_for_inactivity_ || suspended_ || shutting_down_ || forced_off_;
  if (should_turn_off != currently_off_) {
    currently_off_ = should_turn_off;
    display_power_setter_->SetDisplayPower(should_turn_off
                                               ? chromeos::DISPLAY_POWER_ALL_OFF
                                               : chromeos::DISPLAY_POWER_ALL_ON,
                                           base::TimeDelta());
    NotifyObservers(cause);
  }
}

void ExternalBacklightController::NotifyObservers(
    BacklightBrightnessChange_Cause cause) {
  for (BacklightControllerObserver& observer : observers_)
    observer.OnBrightnessChange(currently_off_ ? 0.0 : 100.0, cause, this);
}

void ExternalBacklightController::UpdateDisplays(
    const std::vector<system::DisplayInfo>& displays) {
  ExternalDisplayMap updated_displays;
  for (const system::DisplayInfo& info : displays) {
    if (info.i2c_path.empty())
      continue;
    if (info.connector_status !=
        system::DisplayInfo::ConnectorStatus::CONNECTED)
      continue;

    auto existing_display_it = external_displays_.find(info);
    if (existing_display_it != external_displays_.end()) {
      // TODO(chromeos-power): Need to handle changed I2C paths?
      updated_displays.emplace(info, std::move(existing_display_it->second));
      continue;
    }
    auto delegate = std::make_unique<system::ExternalDisplay::RealDelegate>();
    delegate->Init(info.i2c_path);
    updated_displays.emplace(
        info, std::make_unique<system::ExternalDisplay>(std::move(delegate)));
  }
  external_displays_.swap(updated_displays);
}

void ExternalBacklightController::AdjustBrightnessByPercent(
    double percent_offset) {
  LOG(INFO) << "Adjusting brightness by " << percent_offset << "%";
  for (ExternalDisplayMap::const_iterator it = external_displays_.begin();
       it != external_displays_.end(); ++it) {
    it->second->AdjustBrightnessByPercent(percent_offset);
  }
  if (ambient_light_sensor_watcher_ &&
      !external_display_als_brightness_enabled_) {
    external_display_with_ambient_light_sensor_brightness_ += percent_offset;
  }
}

int ExternalBacklightController::CalculateAssociationScore(
    const base::FilePath& a, const base::FilePath& b) {
  std::vector<std::string> a_components = a.GetComponents();
  std::vector<std::string> b_components = b.GetComponents();

  size_t score = 0;
  while (score < a_components.size() && score < b_components.size() &&
         a_components[score] == b_components[score]) {
    score++;
  }
  return score;
}

void ExternalBacklightController::MatchAmbientLightSensorsToDisplays() {
  ExternalAmbientLightSensorDisplayMap updated_ambient_light_sensors;
  for (const auto& als_info : external_ambient_light_sensors_info_) {
    int highest_score = 0;
    system::DisplayInfo best_matching_display;
    for (const auto& [display_info, external_display] : external_displays_) {
      int score =
          CalculateAssociationScore(display_info.sys_path, als_info.iio_path);
      if (score > highest_score) {
        highest_score = score;
        best_matching_display = display_info;
      }
    }
    if (highest_score >= kMinimumAssociationScore) {
      // If ALS-based brightness is disabled, add the match but with a null
      // ExternalAmbientLightHandler.
      if (!external_display_als_brightness_enabled_) {
        updated_ambient_light_sensors.emplace(
            als_info.iio_path, std::make_pair(best_matching_display, nullptr));
        continue;
      }

      // If ALS-based brightness is enabled, and a match already exists,
      // preserve it.
      auto existing_als_it = external_als_displays_.find(als_info.iio_path);
      if (existing_als_it != external_als_displays_.end() &&
          existing_als_it->second.second) {
        updated_ambient_light_sensors.emplace(
            als_info.iio_path,
            std::make_pair(existing_als_it->second.first,
                           std::move(existing_als_it->second.second)));
        continue;
      }

      // If ALS-based brightness is enabled, and no match already exists, create
      // a new one.
      auto sensor =
          external_ambient_light_sensor_factory_->CreateSensor(als_info);
      auto handler = std::make_unique<ExternalAmbientLightHandler>(
          std::move(sensor), best_matching_display, this);
      handler->Init(external_backlight_als_steps_,
                    kExternalAmbientLightHandlerInitialBrightness,
                    kExternalAmbientLightHandlerSmoothingConstant);
      updated_ambient_light_sensors.emplace(
          als_info.iio_path,
          std::make_pair(best_matching_display, std::move(handler)));

      LOG(INFO) << "Matched ALS (" << als_info.iio_path.value()
                << ") with display (" << best_matching_display.sys_path.value()
                << ") with score " << highest_score;
    }
  }
  external_als_displays_.swap(updated_ambient_light_sensors);
}

void ExternalBacklightController::SetBrightnessPercentForAmbientLight(
    const system::DisplayInfo& display_info, double brightness_percent) {
  auto display_it = external_displays_.find(display_info);
  if (display_it != external_displays_.end()) {
    display_it->second->SetBrightness(brightness_percent);
  }
}

std::vector<std::pair<base::FilePath, system::DisplayInfo>>
ExternalBacklightController::
    GetAmbientLightSensorAndDisplayMatchesForTesting() {
  std::vector<std::pair<base::FilePath, system::DisplayInfo>> matches;
  for (const auto& [path, pair] : external_als_displays_) {
    matches.emplace_back(path, pair.first);
  }
  return matches;
}

void ExternalBacklightController::HandleSetExternalDisplayALSBrightnessRequest(
    dbus::MethodCall* method_call,
    dbus::ExportedObject::ResponseSender response_sender) {
  bool enabled = external_display_als_brightness_enabled_;
  dbus::MessageReader reader(method_call);
  if (!reader.PopBool(&enabled)) {
    LOG(ERROR) << "Unable to read " << kSetExternalDisplayALSBrightnessMethod
               << " args";
    return;
  }

  if (enabled != external_display_als_brightness_enabled_ &&
      ambient_light_sensor_watcher_) {
    external_display_als_brightness_enabled_ = enabled;
    MatchAmbientLightSensorsToDisplays();
    if (!enabled) {
      // Set displays that had ALS-based brightness enabled back to the
      // brightness percentage they had before.
      for (auto& [path, pair] : external_als_displays_) {
        SetBrightnessPercentForAmbientLight(
            pair.first, external_display_with_ambient_light_sensor_brightness_);
      }
    }
  }

  std::unique_ptr<dbus::Response> response =
      dbus::Response::FromMethodCall(method_call);
  std::move(response_sender).Run(std::move(response));
}

void ExternalBacklightController::HandleGetExternalDisplayALSBrightnessRequest(
    dbus::MethodCall* method_call,
    dbus::ExportedObject::ResponseSender response_sender) {
  bool enabled =
      external_display_als_brightness_enabled_ && ambient_light_sensor_watcher_;

  std::unique_ptr<dbus::Response> response =
      dbus::Response::FromMethodCall(method_call);
  dbus::MessageWriter(response.get()).AppendBool(enabled);
  std::move(response_sender).Run(std::move(response));
}

}  // namespace power_manager::policy
