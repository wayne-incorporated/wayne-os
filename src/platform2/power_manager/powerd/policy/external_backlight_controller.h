// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef POWER_MANAGER_POWERD_POLICY_EXTERNAL_BACKLIGHT_CONTROLLER_H_
#define POWER_MANAGER_POWERD_POLICY_EXTERNAL_BACKLIGHT_CONTROLLER_H_

#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <base/compiler_specific.h>
#include <base/observer_list.h>
#include <dbus/exported_object.h>

#include "power_manager/powerd/policy/backlight_controller.h"
#include "power_manager/powerd/policy/external_ambient_light_handler.h"
#include "power_manager/powerd/system/ambient_light_sensor_watcher_observer.h"
#include "power_manager/powerd/system/display/display_watcher_observer.h"
#include "power_manager/proto_bindings/backlight.pb.h"

namespace power_manager {

class PrefsInterface;

namespace system {
struct AmbientLightSensorInfo;
class AmbientLightSensorWatcherInterface;
class DBusWrapperInterface;
struct DisplayInfo;
class DisplayPowerSetterInterface;
class DisplayWatcherInterface;
class ExternalAmbientLightHandler;
class ExternalAmbientLightSensorFactoryInterface;
class ExternalDisplay;
}  // namespace system

namespace policy {

// Controls the brightness of an external display on machines that lack internal
// displays.
class ExternalBacklightController
    : public BacklightController,
      public system::DisplayWatcherObserver,
      public system::AmbientLightSensorWatcherObserver,
      public ExternalAmbientLightHandler::Delegate {
 public:
  ExternalBacklightController();
  ExternalBacklightController(const ExternalBacklightController&) = delete;
  ExternalBacklightController& operator=(const ExternalBacklightController&) =
      delete;

  ~ExternalBacklightController() override;

  // Initializes the object. Ownership of raw pointers remains with the caller.
  void Init(
      PrefsInterface* prefs,
      system::AmbientLightSensorWatcherInterface* ambient_light_sensor_watcher,
      system::ExternalAmbientLightSensorFactoryInterface*
          external_ambient_light_sensor_factory,
      system::DisplayWatcherInterface* display_watcher,
      system::DisplayPowerSetterInterface* display_power_setter,
      system::DBusWrapperInterface* dbus_wrapper);

  // BacklightController implementation:
  void AddObserver(BacklightControllerObserver* observer) override;
  void RemoveObserver(BacklightControllerObserver* observer) override;
  void HandlePowerSourceChange(PowerSource source) override;
  void HandleDisplayModeChange(DisplayMode mode) override;
  void HandleSessionStateChange(SessionState state) override;
  void HandlePowerButtonPress() override;
  void HandleLidStateChange(LidState state) override;
  void HandleUserActivity(UserActivityType type) override;
  void HandleVideoActivity(bool is_fullscreen) override;
  void HandleWakeNotification() override;
  void HandleHoverStateChange(bool hovering) override;
  void HandleTabletModeChange(TabletMode mode) override;
  void HandlePolicyChange(const PowerManagementPolicy& policy) override;
  void HandleDisplayServiceStart() override;
  void HandleBatterySaverModeChange(
      const BatterySaverModeState& state) override;
  void SetDimmedForInactivity(bool dimmed) override;
  void SetOffForInactivity(bool off) override;
  void SetSuspended(bool suspended) override;
  void SetShuttingDown(bool shutting_down) override;
  void SetForcedOff(bool forced_off) override;
  bool GetForcedOff() override;
  bool GetBrightnessPercent(double* percent) override;
  int GetNumAmbientLightSensorAdjustments() const override;
  int GetNumUserAdjustments() const override;
  double LevelToPercent(int64_t level) const override;
  int64_t PercentToLevel(double percent) const override;

  // system::DisplayWatcherObserver implementation:
  void OnDisplaysChanged(
      const std::vector<system::DisplayInfo>& displays) override;

  // system::AmbientLightSensorWatcherObserver implementation:
  void OnAmbientLightSensorsChanged(
      const std::vector<system::AmbientLightSensorInfo>& ambient_light_sensors)
      override;

  // ExternalAmbientLightHandler::Delegate implementation:
  void SetBrightnessPercentForAmbientLight(
      const system::DisplayInfo& display_info,
      double brightness_percent) override;

  // Get ambient light sensor to display matches. For testing.
  std::vector<std::pair<base::FilePath, system::DisplayInfo>>
  GetAmbientLightSensorAndDisplayMatchesForTesting();

 private:
  // Handlers for requests sent via D-Bus.
  void HandleIncreaseBrightnessRequest();
  void HandleDecreaseBrightnessRequest(bool allow_off);
  void HandleSetBrightnessRequest(double percent,
                                  Transition transition,
                                  SetBacklightBrightnessRequest_Cause cause);
  void HandleGetBrightnessRequest(double* percent_out, bool* success_out);

  // Turns displays on or off via |monitor_reconfigure_| as needed for
  // |off_for_inactivity_|, |suspended_|, and |shutting_down_|.
  void UpdateScreenPowerState(BacklightBrightnessChange_Cause cause);

  // Sends notifications to |observers_| about the current brightness level.
  void NotifyObservers(BacklightBrightnessChange_Cause cause);

  // Updates |external_displays_| for |displays|.
  void UpdateDisplays(const std::vector<system::DisplayInfo>& displays);

  // Adjusts |external_displays_| by |percent_offset|, a linearly-calculated
  // percent in the range [-100.0, 100.0].
  void AdjustBrightnessByPercent(double percent_offset);

  // Compute an association score between two syspaths. The score used is a
  // count of how many prefix path components they share.
  int CalculateAssociationScore(const base::FilePath& a,
                                const base::FilePath& b);

  // Tries to match any external ambient light sensors to the corresponding
  // external display.
  void MatchAmbientLightSensorsToDisplays();

  void HandleSetExternalDisplayALSBrightnessRequest(
      dbus::MethodCall* method_call,
      dbus::ExportedObject::ResponseSender response_sender);
  void HandleGetExternalDisplayALSBrightnessRequest(
      dbus::MethodCall* method_call,
      dbus::ExportedObject::ResponseSender response_sender);

  // These pointers aren't owned by this class.
  PrefsInterface* prefs_ = nullptr;
  system::AmbientLightSensorWatcherInterface* ambient_light_sensor_watcher_ =
      nullptr;
  system::ExternalAmbientLightSensorFactoryInterface*
      external_ambient_light_sensor_factory_ = nullptr;
  system::DisplayWatcherInterface* display_watcher_ = nullptr;
  system::DisplayPowerSetterInterface* display_power_setter_ = nullptr;
  system::DBusWrapperInterface* dbus_wrapper_ = nullptr;

  base::ObserverList<BacklightControllerObserver> observers_;

  bool dimmed_for_inactivity_ = false;
  bool off_for_inactivity_ = false;
  bool suspended_ = false;
  bool shutting_down_ = false;
  bool forced_off_ = false;

  // Are the external displays currently turned off?
  bool currently_off_ = false;

  // Map from DRM device directories to ExternalDisplay objects for controlling
  // the corresponding displays.
  typedef std::map<system::DisplayInfo,
                   std::unique_ptr<system::ExternalDisplay>>
      ExternalDisplayMap;
  ExternalDisplayMap external_displays_;

  // Map from IIO device directories to DisplayInfo and
  // ExternalAmbientLightHandler for reading the corresponding ALS and adjusting
  // the display brightness. The ExternalAmbientLightHandler pointer will be
  // null if ALS-based brightness control is disabled.
  typedef std::map<base::FilePath,
                   std::pair<system::DisplayInfo,
                             std::unique_ptr<ExternalAmbientLightHandler>>>
      ExternalAmbientLightSensorDisplayMap;
  ExternalAmbientLightSensorDisplayMap external_als_displays_;

  // Vector of currently connected external ambient light sensors.
  std::vector<system::AmbientLightSensorInfo>
      external_ambient_light_sensors_info_;

  // Whether or not ALS-based brightness adjustment is enabled for external
  // displays with ambient light sensors.
  bool external_display_als_brightness_enabled_ = false;
  // For external displays with ambient light sensors, the brightness percentage
  // to use when ALS-based brightness is disabled.
  double external_display_with_ambient_light_sensor_brightness_ = 100.0;

  // Number of times the user has requested that the brightness be changed in
  // the current session.
  int num_brightness_adjustments_in_session_ = 0;

  std::string external_backlight_als_steps_;

  base::WeakPtrFactory<ExternalBacklightController> weak_ptr_factory_;
};

}  // namespace policy
}  // namespace power_manager

#endif  // POWER_MANAGER_POWERD_POLICY_EXTERNAL_BACKLIGHT_CONTROLLER_H_
