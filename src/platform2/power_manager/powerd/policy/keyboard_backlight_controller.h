// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef POWER_MANAGER_POWERD_POLICY_KEYBOARD_BACKLIGHT_CONTROLLER_H_
#define POWER_MANAGER_POWERD_POLICY_KEYBOARD_BACKLIGHT_CONTROLLER_H_

#include <stdint.h>

#include <memory>
#include <string>
#include <vector>

#include <base/memory/weak_ptr.h>
#include <base/observer_list.h>
#include <base/time/time.h>
#include <base/timer/timer.h>

#include "power_manager/common/power_constants.h"
#include "power_manager/powerd/policy/ambient_light_handler.h"
#include "power_manager/powerd/policy/backlight_controller.h"
#include "power_manager/powerd/policy/backlight_controller_observer.h"
#include "power_manager/powerd/system/backlight_observer.h"

namespace power_manager {

class Clock;
class PrefsInterface;

namespace system {
class AmbientLightSensorInterface;
class BacklightInterface;
class DBusWrapperInterface;
}  // namespace system

namespace policy {

class KeyboardBacklightControllerTest;

// Controls the keyboard backlight for devices with such a backlight.
class KeyboardBacklightController : public BacklightController,
                                    public AmbientLightHandler::Delegate,
                                    public system::BacklightObserver {
 public:
  KeyboardBacklightController();
  KeyboardBacklightController(const KeyboardBacklightController&) = delete;
  KeyboardBacklightController& operator=(const KeyboardBacklightController&) =
      delete;

  ~KeyboardBacklightController() override;

  // Initializes the object. Ownership of passed-in pointers remains with the
  // caller. |sensor| may be NULL.
  void Init(system::BacklightInterface* backlight,
            PrefsInterface* prefs,
            system::AmbientLightSensorInterface* sensor,
            system::DBusWrapperInterface* dbus_wrapper,
            LidState initial_lid_state,
            TabletMode initial_tablet_mode);

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

  // system::BacklightObserver implementation:
  void OnBacklightDeviceChanged(system::BacklightInterface* backlight) override;

  // Backlight brightness percent to use when the screen is dimmed.
  static constexpr double kDimPercent = 10.0;

  // This is how long after a video playing message is received we should wait
  // until reverting to the not playing state. If another message is received in
  // this interval the timeout is reset. The browser should be sending these
  // messages ~5 seconds when video is playing.
  static constexpr base::TimeDelta kVideoTimeoutInterval = base::Seconds(7);

 private:
  // Indicates when certain functions should send signals about brightness
  // changes.
  enum class SignalBehavior {
    kIfChanged,
    kAlways,
  };

  // Handles |video_timer_| firing, indicating that video activity has stopped.
  void HandleVideoTimeout();

  // Returns true if hovering is active or if user activity or hovering was
  // observed recently enough that the backlight should be kept on.
  bool RecentlyHoveringOrUserActive() const;

  // Stops or starts |turn_off_timer_| as needed based on the current values of
  // |hovering_|, |last_hover_time_|, and |last_user_activity_time_|.
  void UpdateTurnOffTimer();

  // Handlers for requests sent via D-Bus.
  void HandleIncreaseBrightnessRequest();
  void HandleDecreaseBrightnessRequest(bool allow_off);
  void HandleGetBrightnessRequest(double* percent_out, bool* success_out);
  void HandleSetBrightnessRequest(double percent,
                                  Transition transition,
                                  SetBacklightBrightnessRequest_Cause cause);
  void HandleToggleKeyboardBacklightRequest();

  // Updates the current brightness after assessing the current state (based on
  // |dimmed_for_inactivity_|, |off_for_inactivity_|, etc.). Should be called
  // whenever the state changes. |transition|, |cause|, and |signal_behavior|
  // are passed to ApplyBrightnessPercent(). Returns true if the brightness was
  // changed and false otherwise.
  bool UpdateState(Transition transition,
                   BacklightBrightnessChange_Cause cause,
                   SignalBehavior signal_behavior = SignalBehavior::kIfChanged);

  // Returns true if we want ApplyBrightnessPercent() to bypass its test for
  // whether the brightness percentage has actually changed from
  // current_percent_.  This is for cases where the percentage hasn't
  // changed but we still need to officially signal a brightness change.
  bool BypassBrightnessPercentageHasChangedTest(
      Transition transition, BacklightBrightnessChange_Cause cause);

  // Sets the backlight's brightness to |percent| over |transition|.
  //
  // If |signal_behavior| is |SignalBehavior::kIfChanged|, sends a signal and
  // notifies observers if the brightness was changed. If
  // |SignalBehavior::kAlways|, always notifies observers. The latter may be
  // useful for changes made in response to user actions --- UI elements may
  // wish to show the "new" state even if it is unchanged, so show the user that
  // nothing was done.
  //
  // Returns true if the brightness was changed.
  bool ApplyBrightnessPercent(double percent,
                              Transition transition,
                              BacklightBrightnessChange_Cause cause,
                              SignalBehavior signal_behavior);

  // Returns true if the |user_steps_| is valid; otherwise returns false.
  bool ValidateUserSteps(std::string* err_msg);

  // Calculates scaled percentages in |user_steps_| from raw percentages.
  void ScaleUserSteps();

  // Calculates raw percentages to scaled percentages in |user_steps_|.
  double RawPercentToPercent(double raw_percent) const;

  // Calculates scaled percentages in |user_steps_| to raw percentages.
  double PercentToRawPercent(double percent) const;

  // Converts a percent brightness into an index of the closest value in
  // `user_steps_`.
  ssize_t PercentToUserStepIndex(double percent) const;

  // A default backlight brightness, represented as a percent in the range
  // (0.0, 100.0]
  //
  // `startup_brightness_percent` is the brightness of the keyboard at the time
  // powerd started.
  //
  // Guaranteed to be strictly positive (i.e., not off).
  double DefaultBrightnessPercent(double startup_brightness_percent) const;

  // Set the backlight brightness to the given percentage value in the range
  // [0, 100].
  //
  // This function also tracks the previously set value, required if the
  // user toggles the backlight from off to on.
  void UpdateUserBrightnessPercent(double brightness);

  // Handle activity (such as user activity, AC plug/unplug events, etc) that
  // should cause the backlight to be turned on temporarily.
  void HandleActivity(BacklightBrightnessChange_Cause cause);

  mutable std::unique_ptr<Clock> clock_;

  // Not owned by this class.
  system::BacklightInterface* backlight_ = nullptr;
  PrefsInterface* prefs_ = nullptr;
  system::DBusWrapperInterface* dbus_wrapper_ = nullptr;

  // May be NULL if no ambient light sensor is present.
  std::unique_ptr<AmbientLightHandler> ambient_light_handler_;

  // Observers to notify about changes.
  base::ObserverList<BacklightControllerObserver> observers_;

  // True if the system is capable of detecting whether the user's hands are
  // hovering over the touchpad.
  bool supports_hover_ = false;

  SessionState session_state_ = SessionState::STOPPED;
  LidState lid_state_ = LidState::NOT_PRESENT;
  TabletMode tablet_mode_ = TabletMode::UNSUPPORTED;
  std::optional<PowerSource> power_source_;  // nullopt for unknown

  bool dimmed_for_inactivity_ = false;
  bool off_for_inactivity_ = false;
  bool suspended_ = false;
  bool shutting_down_ = false;
  bool forced_off_ = false;
  bool hovering_ = false;

  // Is a fullscreen video currently being played?
  bool fullscreen_video_playing_ = false;

  // Current percentage that |backlight_| is set to (or possibly in the process
  // of transitioning to), in the range [0.0, 100.0].
  double current_percent_ = 0.0;

  // List of percentages that the user can select from for setting the
  // brightness. Values are in the range [0.0, 100], and guaranteed to
  // be in strictly increasing order. Index 0 is guaranteed to be
  // 0 ("off"). Populated from a preference.
  std::vector<double> user_steps_;

  // Current user-selected brightness in the range [0.0, 100], or std::nullopt
  // if |automated_percent_| should be used instead.
  //
  // Update with |UpdateUserBrightness| to ensure
  // |last_positive_user_brightness_percent_| stays in sync.
  std::optional<double> user_brightness_percent_;

  // The most recent non-zero user-set backlight brightness.
  //
  // Used when the backlight is toggled from off to on: we restore the
  // user's previous brightness value.
  double last_positive_user_brightness_percent_ = -1;

  // Min, min visible and max percentages used to calculate scaled percentages
  // in |user_steps_| from raw percentages. This is populated from a preference.
  double min_raw_percent_ = -1;
  double min_visible_raw_percent = -1;
  double max_raw_percent_ = -1;

  // Backlight brightness in the range [0.0, 100.0] to use when the ambient
  // light sensor is controlling the brightness. This is set by
  // |ambient_light_handler_|. If no ambient light sensor is present, it is
  // initialized from kKeyboardBacklightNoAlsBrightnessPref.
  double automated_percent_ = 100.0;

  // Time at which the user's hands stopped hovering over the touchpad. Unset if
  // |hovering_| is true or |supports_hover_| is false.
  base::TimeTicks last_hover_time_;

  // Time at which user activity was last observed.
  base::TimeTicks last_user_activity_time_;

  // Duration the backlight should remain on after hovering stops (on systems
  // that support hover detection) or after user activity (otherwise).
  base::TimeDelta keep_on_delay_;

  // Like |keep_on_delay_|, but used while fullscreen video is playing.
  base::TimeDelta keep_on_during_video_delay_;

  // Runs UpdateState() |keep_on_delay_| or |keep_on_during_video_delay_| after
  // the user's hands stop hovering over the touchpad (or after user activity is
  // last observed, if hover is not supported).
  base::OneShotTimer turn_off_timer_;

  // Runs HandleVideoTimeout().
  base::OneShotTimer video_timer_;

  // Counters for stat tracking.
  int num_als_adjustments_ = 0;
  int num_user_adjustments_ = 0;

  base::WeakPtrFactory<KeyboardBacklightController> weak_ptr_factory_;
};

}  // namespace policy
}  // namespace power_manager

#endif  // POWER_MANAGER_POWERD_POLICY_KEYBOARD_BACKLIGHT_CONTROLLER_H_
