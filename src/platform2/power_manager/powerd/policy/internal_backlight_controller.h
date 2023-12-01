// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef POWER_MANAGER_POWERD_POLICY_INTERNAL_BACKLIGHT_CONTROLLER_H_
#define POWER_MANAGER_POWERD_POLICY_INTERNAL_BACKLIGHT_CONTROLLER_H_

#include <stdint.h>

#include <memory>

#include <base/compiler_specific.h>
#include <base/memory/weak_ptr.h>
#include <base/observer_list.h>
#include <base/time/time.h>
#include <chromeos/dbus/service_constants.h>

#include "power_manager/powerd/policy/ambient_light_handler.h"
#include "power_manager/powerd/policy/backlight_controller.h"
#include "power_manager/proto_bindings/backlight.pb.h"

namespace power_manager {

class Clock;
class PrefsInterface;

namespace system {
class AmbientLightSensorInterface;
class BacklightInterface;
class DBusWrapperInterface;
class DisplayPowerSetterInterface;
}  // namespace system

namespace policy {

// Controls the internal backlight on devices with built-in displays.
//
// In the context of this class, "percent" refers to a double-precision
// brightness percentage in the range [0.0, 100.0] (where 0 indicates a
// fully-off backlight), while "level" refers to a 64-bit hardware-specific
// brightness in the range [0, max-brightness-per-sysfs].
class InternalBacklightController : public BacklightController,
                                    public AmbientLightHandler::Delegate {
 public:
  // Maximum number of brightness adjustment steps.
  static const int64_t kMaxBrightnessSteps;

  // Percent corresponding to |min_visible_level_|, which takes the role of the
  // lowest brightness step before the screen is turned off.
  static const double kMinVisiblePercent;

  // Minimum number of brightness levels needed before we use a non-linear
  // mapping between levels and percents.
  static const double kMinLevelsForNonLinearMapping;

  // Minimum brightness, as a fraction of the maximum level in the range [0.0,
  // 1.0], that is used as the bottom step before turning the backlight off
  // entirely.  This is arbitrarily chosen but seems to be a reasonable
  // marginally-visible brightness for a darkened room on current devices:
  // http://crosbug.com/24569. A custom level can be set via the
  // kMinVisibleBacklightLevelPref setting. This is a fraction of the
  // driver-supplied maximum level rather than a percent so it won't change if
  // kDefaultLevelToPercentExponent is modified.
  static const double kDefaultMinVisibleBrightnessFraction;

  // If an ambient light reading hasn't been seen after this many seconds,
  // give up on waiting for the sensor to be initialized and just set
  // |use_ambient_light_| to false.
  static constexpr base::TimeDelta kAmbientLightSensorTimeout =
      base::Seconds(10);

  InternalBacklightController();
  InternalBacklightController(const InternalBacklightController&) = delete;
  InternalBacklightController& operator=(const InternalBacklightController&) =
      delete;

  ~InternalBacklightController() override;

  Clock* clock() { return clock_.get(); }

  // Initializes the object. Ownership of the passed-in pointers remains with
  // the caller.
  void Init(system::BacklightInterface* backlight,
            PrefsInterface* prefs,
            system::AmbientLightSensorInterface* sensor,
            system::DisplayPowerSetterInterface* display_power_setter,
            system::DBusWrapperInterface* dbus_wrapper,
            LidState initial_lid_state);

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

  // AmbientLightHandler::Delegate implementation:
  void SetBrightnessPercentForAmbientLight(
      double brightness_percent,
      AmbientLightHandler::BrightnessChangeCause cause) override;
  void OnColorTemperatureChanged(int color_temperature) override;
  void ReportAmbientLightOnResumeMetrics(int lux) override;
  bool IsUsingAmbientLight() const override;

  void RegisterAmbientLightResumeMetricsHandler(
      AmbientLightOnResumeMetricsCallback callback) override;

 private:
  // Snaps |percent| to the nearest step, as defined by |step_percent_|.
  double SnapBrightnessPercentToNearestStep(double percent) const;

  // Returns either |ac_explicit_brightness_percent_| or
  // |battery_explicit_brightness_percent_| depending on |power_source_|.
  double GetExplicitBrightnessPercent() const;

  // Returns the brightness percent that should be used when the system is
  // in an undimmed state (|ambient_light_brightness_percent_| if
  // |use_ambient_light_| is true or a user- or policy-set level otherwise).
  double GetUndimmedBrightnessPercent() const;

  // Handlers for requests sent via D-Bus.
  void HandleIncreaseBrightnessRequest();
  void HandleDecreaseBrightnessRequest(bool allow_off);
  void HandleSetBrightnessRequest(double percent,
                                  Transition transition,
                                  SetBacklightBrightnessRequest_Cause cause);
  void HandleGetBrightnessRequest(double* percent_out, bool* success_out);

  // Increases the explicitly-set brightness to the minimum visible level if
  // it's currently set to zero. Note that the brightness is left unchanged if
  // an external display is connected to avoid resizing the desktop, or if the
  // brightness was set to zero via a policy.
  void EnsureUserBrightnessIsNonzero(BacklightBrightnessChange_Cause cause);

  // Disables ambient light adjustments, updates the
  // |*_explicit_brightness_percent_| members, and calls UpdateState().
  void SetExplicitBrightnessPercent(double ac_percent,
                                    double battery_percent,
                                    Transition transition,
                                    BacklightBrightnessChange_Cause cause);

  // Updates the system's backlight brightness and display power after examining
  // the current state (as described by |power_source_|,
  // |dimmed_for_inactivity_|, |*_brightness_percent_|, etc.). Also updates
  // |current_level_| and |display_power_state_| and notifies |observers_| about
  // the change. This should be called whenever any member variables comprising
  // the state are updated.
  //
  // |adjust_transition| is used when making a normal brightness change (i.e.
  // without changing the display power) but can be omitted otherwise.
  void UpdateState(BacklightBrightnessChange_Cause cause,
                   Transition adjust_transition = Transition::FAST);

  // Not owned by this class.
  system::BacklightInterface* backlight_ = nullptr;
  PrefsInterface* prefs_ = nullptr;
  system::DisplayPowerSetterInterface* display_power_setter_ = nullptr;
  system::DBusWrapperInterface* dbus_wrapper_ = nullptr;

  std::unique_ptr<AmbientLightHandler> ambient_light_handler_;
  std::unique_ptr<Clock> clock_;

  // Observers for changes to the brightness level.
  base::ObserverList<BacklightControllerObserver> observers_;

  // Information describing the current state of the system.
  PowerSource power_source_ = PowerSource::BATTERY;
  DisplayMode display_mode_ = DisplayMode::NORMAL;
  LidState lid_state_ = LidState::NOT_PRESENT;
  bool dimmed_for_inactivity_ = false;
  bool off_for_inactivity_ = false;
  bool suspended_ = false;
  bool shutting_down_ = false;
  bool forced_off_ = false;
  bool battery_saver_ = false;

  // Time at which Init() was called.
  base::TimeTicks init_time_;

  // Indicates whether SetBrightnessPercentForAmbientLight() and
  // HandlePowerSourceChange() have been called yet.
  bool got_ambient_light_brightness_percent_ = false;
  bool got_power_source_ = false;

  // Has UpdateState() already set the initial state?
  bool already_set_initial_state_ = false;

  // Number of ambient-light- and user-triggered brightness adjustments in the
  // current session.
  int als_adjustment_count_ = 0;
  int user_adjustment_count_ = 0;

  // Ambient-light-sensor-derived brightness percent supplied by
  // |ambient_light_handler_|.
  double ambient_light_brightness_percent_ = 100.0;

  // Ambient Light Sensor On Resume metrics reporting callback;
  AmbientLightOnResumeMetricsCallback ambient_light_metrics_callback_;

  // User- or policy-set brightness percent when on AC or battery power.
  double ac_explicit_brightness_percent_ = 100.0;
  double battery_explicit_brightness_percent_ = 100.0;

  // True if the most-recently-received policy message requested a specific
  // brightness and no user adjustments have been made since then.
  bool using_policy_brightness_ = false;

  // True if the brightness should be forced to be nonzero in response to user
  // activity.
  bool force_nonzero_brightness_for_user_activity_ = true;

  // Maximum raw brightness level for |backlight_| (0 is assumed to be the
  // minimum, with the backlight turned off).
  int64_t max_level_ = 0;

  // Minimum raw brightness level that we'll stop at before turning the
  // backlight off entirely when adjusting the brightness down.  Note that we
  // can still quickly animate through lower (still technically visible) levels
  // while transitioning to the off state; this is the minimum level that we'll
  // use in the steady state while the backlight is on.
  int64_t min_visible_level_ = 0;

  // Indicates whether transitions between 0 and |min_visible_level_| must be
  // instant, i.e. the brightness may not smoothly transition between those
  // levels.
  bool instant_transitions_below_min_level_ = false;

  // If true, then suggestions from |ambient_light_handler_| are used. False if
  // |ambient_light_handler_| is null or the user has manually set the
  // brightness.
  bool use_ambient_light_ = true;

  // Percentage by which we offset the brightness in response to increase and
  // decrease requests.
  double step_percent_ = 1.0;

  // Percentage, in the range [0.0, 100.0], to which we dim the backlight on
  // idle. (Initialized to a const value in c'tor.)
  double dimmed_brightness_percent_;

  // Brightness level fractions (e.g. 140/200) are raised to this power when
  // converting them to percents.  A value below 1.0 gives us more granularity
  // at the lower end of the range and less at the upper end. (Initialized to a
  // const value in c'tor.)
  double level_to_percent_exponent_;

  // Percentage, in the range [0.0, 100.0], to which we dim the backlight when
  // battery saver is enabled.
  double battery_saver_brightness_percent_;

  // |backlight_|'s current brightness level (or the level to which it's
  // transitioning).
  int64_t current_level_ = 0;

  // Most-recently-requested display power state.
  chromeos::DisplayPowerState display_power_state_ =
      chromeos::DISPLAY_POWER_ALL_ON;

  // Screen off delay when user sets brightness to 0.
  base::TimeDelta turn_off_screen_timeout_;

  base::WeakPtrFactory<InternalBacklightController> weak_ptr_factory_;
};

}  // namespace policy
}  // namespace power_manager

#endif  // POWER_MANAGER_POWERD_POLICY_INTERNAL_BACKLIGHT_CONTROLLER_H_
