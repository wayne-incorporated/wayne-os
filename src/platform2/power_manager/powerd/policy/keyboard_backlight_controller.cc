// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/powerd/policy/keyboard_backlight_controller.h"

#include <algorithm>
#include <cmath>
#include <cstdlib>
#include <functional>
#include <limits>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/check_op.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/notreached.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <chromeos/dbus/service_constants.h>
#include <dbus/power_manager/dbus-constants.h>

#include "power_manager/common/clock.h"
#include "power_manager/common/power_constants.h"
#include "power_manager/common/prefs.h"
#include "power_manager/common/tracing.h"
#include "power_manager/common/util.h"
#include "power_manager/powerd/system/backlight_interface.h"
#include "power_manager/proto_bindings/backlight.pb.h"

namespace power_manager::policy {

namespace {

// Maximum valid value for scaled percentages.
const double kMaxPercent = 100.0;

// Minimum valid value for scaled percentages.
const double kMinPercent = 0.0;

// Second minimum step in scaled percentages.
const double kMinVisiblePercent = 10.0;

// Returns the total duration for |style|.
base::TimeDelta GetTransitionDuration(
    BacklightController::Transition transition) {
  switch (transition) {
    case BacklightController::Transition::INSTANT:
      return base::TimeDelta();
    case BacklightController::Transition::FAST:
      return kFastBacklightTransition;
    case BacklightController::Transition::SLOW:
      return kSlowBacklightTransition;
  }
  NOTREACHED() << "Unhandled transition style " << static_cast<int>(transition);
  return base::TimeDelta();
}

// Map a |SetBacklightBrightnessRequest_Cause| to an equivalent
// |BacklightBrightnessChange_Cause|.
BacklightBrightnessChange_Cause ToBacklightBrightnessChangeCause(
    SetBacklightBrightnessRequest_Cause cause) {
  switch (cause) {
    case SetBacklightBrightnessRequest_Cause_USER_REQUEST:
      return BacklightBrightnessChange_Cause_USER_REQUEST;
    case SetBacklightBrightnessRequest_Cause_MODEL:
      return BacklightBrightnessChange_Cause_MODEL;
    default:
      return BacklightBrightnessChange_Cause_OTHER;
  }
}

}  // namespace

KeyboardBacklightController::KeyboardBacklightController()
    : clock_(std::make_unique<Clock>()), weak_ptr_factory_(this) {}

KeyboardBacklightController::~KeyboardBacklightController() {
  if (backlight_)
    backlight_->RemoveObserver(this);
}

void KeyboardBacklightController::Init(
    system::BacklightInterface* backlight,
    PrefsInterface* prefs,
    system::AmbientLightSensorInterface* sensor,
    system::DBusWrapperInterface* dbus_wrapper,
    LidState initial_lid_state,
    TabletMode initial_tablet_mode) {
  backlight_ = backlight;
  backlight_->AddObserver(this);

  prefs_ = prefs;
  lid_state_ = initial_lid_state;
  tablet_mode_ = initial_tablet_mode;

  dbus_wrapper_ = dbus_wrapper;
  RegisterIncreaseBrightnessHandler(
      dbus_wrapper_, kIncreaseKeyboardBrightnessMethod,
      base::BindRepeating(
          &KeyboardBacklightController::HandleIncreaseBrightnessRequest,
          weak_ptr_factory_.GetWeakPtr()));
  RegisterDecreaseBrightnessHandler(
      dbus_wrapper_, kDecreaseKeyboardBrightnessMethod,
      base::BindRepeating(
          &KeyboardBacklightController::HandleDecreaseBrightnessRequest,
          weak_ptr_factory_.GetWeakPtr()));
  RegisterGetBrightnessHandler(
      dbus_wrapper_, kGetKeyboardBrightnessPercentMethod,
      base::BindRepeating(
          &KeyboardBacklightController::HandleGetBrightnessRequest,
          weak_ptr_factory_.GetWeakPtr()));
  RegisterSetBrightnessHandler(
      dbus_wrapper_, kSetKeyboardBrightnessMethod,
      base::BindRepeating(
          &KeyboardBacklightController::HandleSetBrightnessRequest,
          weak_ptr_factory_.GetWeakPtr()));
  RegisterToggleKeyboardBacklightHandler(
      dbus_wrapper_, kToggleKeyboardBacklightMethod,
      base::BindRepeating(
          &KeyboardBacklightController::HandleToggleKeyboardBacklightRequest,
          weak_ptr_factory_.GetWeakPtr()));

  if (sensor) {
    ambient_light_handler_ =
        std::make_unique<AmbientLightHandler>(sensor, this);
    ambient_light_handler_->set_name("keyboard");
  }

  prefs_->GetBool(kDetectHoverPref, &supports_hover_);

  int64_t delay_ms = 0;
  CHECK(prefs->GetInt64(kKeyboardBacklightKeepOnMsPref, &delay_ms));
  keep_on_delay_ = base::Milliseconds(delay_ms);
  CHECK(prefs->GetInt64(kKeyboardBacklightKeepOnDuringVideoMsPref, &delay_ms));
  keep_on_during_video_delay_ = base::Milliseconds(delay_ms);

  // Read the user-settable brightness steps (one per line).
  std::string input_str;
  if (!prefs_->GetString(kKeyboardBacklightUserStepsPref, &input_str))
    LOG(FATAL) << "Failed to read pref " << kKeyboardBacklightUserStepsPref;
  std::vector<std::string> lines = base::SplitString(
      input_str, "\n", base::KEEP_WHITESPACE, base::SPLIT_WANT_ALL);
  for (const std::string& line : lines) {
    double new_step = 0.0;
    if (!base::StringToDouble(line, &new_step))
      LOG(FATAL) << "Invalid line in pref " << kKeyboardBacklightUserStepsPref
                 << ": \"" << line << "\"";
    user_steps_.push_back(new_step);
  }

  // Validate raw percentages in |user_steps_|.
  std::string err_msg;
  CHECK(ValidateUserSteps(&err_msg)) << err_msg;

  // Initialize |min_raw_percent_|, |min_visible_raw_percent| and
  // |max_raw_percent_| and calculate scaled percentages.
  ScaleUserSteps();

  if (backlight_->DeviceExists()) {
    const int64_t current_level = backlight_->GetCurrentBrightnessLevel();
    current_percent_ = LevelToPercent(current_level);
    LOG(INFO) << "Backlight has range [0, "
              << backlight_->GetMaxBrightnessLevel() << "] with initial level "
              << current_level;
  }

  // Set the initial level of the backlight brightness, used for systems without
  // an ALS, or systems with an ALS prior to our first reading.
  automated_percent_ = DefaultBrightnessPercent(current_percent_);

  // Set manual control off, and the default brightness if the user toggles the
  // backlight from off to on prior to making any other manual adjustment.
  user_brightness_percent_ = std::nullopt;
  last_positive_user_brightness_percent_ = automated_percent_;

  // Configure the ALS for systems that have it.
  if (ambient_light_handler_.get()) {
    std::string pref_value;
    CHECK(prefs_->GetString(kKeyboardBacklightAlsStepsPref, &pref_value))
        << "Unable to read pref " << kKeyboardBacklightAlsStepsPref;

    double als_smoothing_constant;
    CHECK(prefs_->GetDouble(kAlsSmoothingConstantPref, &als_smoothing_constant))
        << "Failed to read pref " << kAlsSmoothingConstantPref;
    ambient_light_handler_->Init(pref_value, current_percent_,
                                 als_smoothing_constant);
  }

  // Slowly turn off the backlight.
  UpdateState(Transition::SLOW, BacklightBrightnessChange_Cause_OTHER);
}

void KeyboardBacklightController::AddObserver(
    BacklightControllerObserver* observer) {
  DCHECK(observer);
  observers_.AddObserver(observer);
}

void KeyboardBacklightController::RemoveObserver(
    BacklightControllerObserver* observer) {
  DCHECK(observer);
  observers_.RemoveObserver(observer);
}

void KeyboardBacklightController::HandlePowerSourceChange(PowerSource source) {
  // The first time we are notified about a power source, simply record it.
  if (!power_source_.has_value()) {
    power_source_ = source;
    return;
  }

  // We may receive notifications for a "change" to the same power source.
  // Ignore such notifications.
  if (power_source_ == source) {
    return;
  }
  power_source_ = source;

  // Treat a power source change similar to user activity.
  HandleActivity(
      source == PowerSource::AC
          ? BacklightBrightnessChange_Cause_EXTERNAL_POWER_CONNECTED
          : BacklightBrightnessChange_Cause_EXTERNAL_POWER_DISCONNECTED);
}

void KeyboardBacklightController::HandleDisplayModeChange(DisplayMode mode) {}

void KeyboardBacklightController::HandleSessionStateChange(SessionState state) {
  session_state_ = state;
  if (state == SessionState::STARTED) {
    num_als_adjustments_ = 0;
    num_user_adjustments_ = 0;
  }
}

void KeyboardBacklightController::HandlePowerButtonPress() {}

void KeyboardBacklightController::HandleLidStateChange(LidState state) {
  if (state == lid_state_)
    return;

  lid_state_ = state;
  UpdateState(
      lid_state_ == LidState::CLOSED ? Transition::INSTANT : Transition::FAST,
      BacklightBrightnessChange_Cause_OTHER);
}

void KeyboardBacklightController::HandleUserActivity(UserActivityType type) {
  HandleActivity(BacklightBrightnessChange_Cause_USER_ACTIVITY);
}

void KeyboardBacklightController::HandleVideoActivity(bool is_fullscreen) {
  // Ignore fullscreen video that's reported when the user isn't logged in;
  // it may be triggered by animations on the login screen.
  if (is_fullscreen && session_state_ == SessionState::STOPPED)
    is_fullscreen = false;

  if (is_fullscreen != fullscreen_video_playing_) {
    VLOG(1) << "Fullscreen video "
            << (is_fullscreen ? "started" : "went non-fullscreen");
    fullscreen_video_playing_ = is_fullscreen;
    UpdateTurnOffTimer();
    UpdateState(Transition::SLOW,
                BacklightBrightnessChange_Cause_USER_ACTIVITY);
  }

  video_timer_.Stop();
  if (is_fullscreen) {
    video_timer_.Start(FROM_HERE, kVideoTimeoutInterval, this,
                       &KeyboardBacklightController::HandleVideoTimeout);
  }
}

void KeyboardBacklightController::HandleWakeNotification() {}

void KeyboardBacklightController::HandleHoverStateChange(bool hovering) {
  if (!supports_hover_ || hovering == hovering_)
    return;

  hovering_ = hovering;

  turn_off_timer_.Stop();
  if (!hovering_) {
    // If the user stopped hovering, start a timer to turn the backlight off in
    // a little while.
    last_hover_time_ = clock_->GetCurrentTime();
    UpdateTurnOffTimer();
  } else {
    last_hover_time_ = base::TimeTicks();
  }

  UpdateState(hovering_ ? Transition::FAST : Transition::SLOW,
              BacklightBrightnessChange_Cause_USER_ACTIVITY);
}

void KeyboardBacklightController::HandleTabletModeChange(TabletMode mode) {
  if (mode == tablet_mode_)
    return;

  tablet_mode_ = mode;
  UpdateState(Transition::FAST, BacklightBrightnessChange_Cause_OTHER);
}

void KeyboardBacklightController::HandlePolicyChange(
    const PowerManagementPolicy& policy) {}

void KeyboardBacklightController::HandleDisplayServiceStart() {}

void KeyboardBacklightController::HandleBatterySaverModeChange(
    const BatterySaverModeState& state) {
  TRACE_EVENT("power",
              "KeyboardBacklightController::HandleBatterySaverModeChange");
  forced_off_ = state.enabled();
  UpdateState(Transition::SLOW,
              BacklightBrightnessChange_Cause_BATTERY_SAVER_STATE_CHANGED);
}

void KeyboardBacklightController::SetDimmedForInactivity(bool dimmed) {
  if (dimmed == dimmed_for_inactivity_)
    return;
  dimmed_for_inactivity_ = dimmed;
  UpdateState(Transition::SLOW,
              BacklightBrightnessChange_Cause_USER_INACTIVITY);
}

void KeyboardBacklightController::SetOffForInactivity(bool off) {
  if (off == off_for_inactivity_)
    return;
  off_for_inactivity_ = off;
  UpdateState(Transition::SLOW,
              BacklightBrightnessChange_Cause_USER_INACTIVITY);
}

void KeyboardBacklightController::SetSuspended(bool suspended) {
  if (suspended == suspended_)
    return;
  suspended_ = suspended;
  UpdateState(suspended ? Transition::INSTANT : Transition::FAST,
              BacklightBrightnessChange_Cause_OTHER);

  if (!suspended && ambient_light_handler_.get())
    ambient_light_handler_->HandleResume();
}

void KeyboardBacklightController::SetShuttingDown(bool shutting_down) {
  if (shutting_down == shutting_down_)
    return;
  shutting_down_ = shutting_down;
  UpdateState(Transition::INSTANT, BacklightBrightnessChange_Cause_OTHER);
}

void KeyboardBacklightController::SetForcedOff(bool forced_off) {
  if (forced_off_ == forced_off)
    return;
  forced_off_ = forced_off;
  UpdateState(Transition::INSTANT,
              forced_off
                  ? BacklightBrightnessChange_Cause_FORCED_OFF
                  : BacklightBrightnessChange_Cause_NO_LONGER_FORCED_OFF);
}

bool KeyboardBacklightController::GetForcedOff() {
  return forced_off_;
}

bool KeyboardBacklightController::GetBrightnessPercent(double* percent) {
  DCHECK(percent);
  *percent = current_percent_;
  return true;
}

int KeyboardBacklightController::GetNumAmbientLightSensorAdjustments() const {
  return num_als_adjustments_;
}

int KeyboardBacklightController::GetNumUserAdjustments() const {
  return num_user_adjustments_;
}

double KeyboardBacklightController::LevelToPercent(int64_t level) const {
  const int64_t max_level = backlight_->GetMaxBrightnessLevel();
  if (max_level == 0)
    return -1.0;
  level = std::max(std::min(level, max_level), static_cast<int64_t>(0));
  double raw_percent =
      static_cast<double>(level) * 100.0 / static_cast<double>(max_level);
  return RawPercentToPercent(raw_percent);
}

int64_t KeyboardBacklightController::PercentToLevel(double percent) const {
  const int64_t max_level = backlight_->GetMaxBrightnessLevel();
  if (max_level == 0)
    return -1;
  double raw_percent = PercentToRawPercent(util::ClampPercent(percent));
  return lround(static_cast<double>(max_level) * raw_percent / 100.0);
}

void KeyboardBacklightController::SetBrightnessPercentForAmbientLight(
    double brightness_percent,
    AmbientLightHandler::BrightnessChangeCause cause) {
  automated_percent_ = brightness_percent;

  // Determine the cause of the change. If it is an ambient light change,
  // perform a slow transition to the new value. If it is change because power
  // was connected/disconnected, we instead perform a fast transition to the new
  // brightness.
  const bool ambient_light_changed =
      cause == AmbientLightHandler::BrightnessChangeCause::AMBIENT_LIGHT;
  const Transition transition =
      ambient_light_changed ? Transition::SLOW : Transition::FAST;
  const BacklightBrightnessChange_Cause backlight_cause =
      AmbientLightHandler::ToProtobufCause(cause);

  // Calculate and update to a new brightness if required.
  bool update_made = UpdateState(transition, backlight_cause);

  // Track number of ALS adjustments.
  if (ambient_light_changed && update_made) {
    num_als_adjustments_++;
  }
}

void KeyboardBacklightController::OnColorTemperatureChanged(
    int color_temperature) {}

void KeyboardBacklightController::OnBacklightDeviceChanged(
    system::BacklightInterface* backlight) {
  DCHECK_EQ(backlight, backlight_);
  if (backlight_->DeviceExists()) {
    const int64_t level = PercentToLevel(current_percent_);
    LOG(INFO) << "Restoring brightness " << level << " (" << current_percent_
              << "%) to backlight with range [0, "
              << backlight_->GetMaxBrightnessLevel() << "] and initial level "
              << backlight_->GetCurrentBrightnessLevel();
    backlight_->SetBrightnessLevel(level,
                                   GetTransitionDuration(Transition::FAST));
  }
}

void KeyboardBacklightController::HandleVideoTimeout() {
  TRACE_EVENT("power", "KeyboardBacklightController::HandleVideoTimeout");
  if (fullscreen_video_playing_)
    VLOG(1) << "Fullscreen video stopped";
  fullscreen_video_playing_ = false;
  UpdateState(Transition::FAST, BacklightBrightnessChange_Cause_OTHER);
  UpdateTurnOffTimer();
}

bool KeyboardBacklightController::RecentlyHoveringOrUserActive() const {
  if (hovering_)
    return true;

  const base::TimeTicks now = clock_->GetCurrentTime();
  const base::TimeDelta delay =
      fullscreen_video_playing_ ? keep_on_during_video_delay_ : keep_on_delay_;
  return (!last_hover_time_.is_null() && (now - last_hover_time_ < delay)) ||
         (!last_user_activity_time_.is_null() &&
          (now - last_user_activity_time_ < delay));
}

ssize_t KeyboardBacklightController::PercentToUserStepIndex(
    double percent) const {
  CHECK(!user_steps_.empty());

  // Find the step nearest to the given percent.
  ssize_t result = -1;
  double percent_delta = std::numeric_limits<double>::max();
  for (ssize_t i = 0; i < user_steps_.size(); i++) {
    double current_delta = fabs(percent - user_steps_[i]);
    if (current_delta < percent_delta) {
      percent_delta = current_delta;
      result = i;
    }
  }
  CHECK_NE(result, -1) << "Failed to find brightness step for " << percent
                       << "%";

  return result;
}

double KeyboardBacklightController::DefaultBrightnessPercent(
    double startup_brightness_percent) const {
  // Get a default brightness, as a percent.
  //
  // For systems without an ALS, we just use the default brightness setting.
  //
  // For systems with an ALS (which don't have a concept of a "default
  // brightness"), we simply use the backlight's initial brightness. If it
  // happens to be zero, it will be bumped up below.
  double default_percent = startup_brightness_percent;
  if (ambient_light_handler_.get() == nullptr) {
    prefs_->GetDouble(kKeyboardBacklightNoAlsBrightnessPref, &default_percent);
  }

  // Return the configured brightness, ensuring we are at least kDimPercent.
  return std::max(default_percent, kDimPercent);
}

void KeyboardBacklightController::UpdateUserBrightnessPercent(double percent) {
  CHECK(percent >= kMinPercent && percent <= kMaxPercent);
  user_brightness_percent_ = percent;
  if (user_brightness_percent_ > 0) {
    last_positive_user_brightness_percent_ = percent;
  }
}

void KeyboardBacklightController::UpdateTurnOffTimer() {
  turn_off_timer_.Stop();

  // The timer shouldn't start until hovering stops.
  if (hovering_)
    return;

  // Determine how much time is left.
  const base::TimeTicks timeout_start =
      std::max(last_hover_time_, last_user_activity_time_);
  if (timeout_start.is_null())
    return;

  const base::TimeDelta full_delay =
      fullscreen_video_playing_ ? keep_on_during_video_delay_ : keep_on_delay_;
  const base::TimeDelta remaining_delay =
      full_delay - (clock_->GetCurrentTime() - timeout_start);
  if (remaining_delay <= base::Milliseconds(0))
    return;

  turn_off_timer_.Start(
      FROM_HERE, remaining_delay,
      base::BindRepeating(
          base::IgnoreResult(&KeyboardBacklightController::UpdateState),
          base::Unretained(this), Transition::SLOW,
          BacklightBrightnessChange_Cause_OTHER, SignalBehavior::kIfChanged));
}

void KeyboardBacklightController::HandleIncreaseBrightnessRequest() {
  LOG(INFO) << "Got user-triggered request to increase brightness";
  if (!backlight_->DeviceExists())
    return;

  // If this is the first time the backlight was manually controlled, use the
  // current backlight brightness as our starting point.
  if (!user_brightness_percent_.has_value()) {
    UpdateUserBrightnessPercent(current_percent_);
  }

  // Increase the brightness by one step.
  //
  // The current user-selected brightness may not match a step exactly: in that
  // case, we simply select the closest step to the current step, and then
  // increase that by one. This may lead us to skipping a step (e.g., if we
  // round the manual brightness 59% up to 60%, and then increase to the next
  // user step at 80%), but ensures that any brightness increase is non-trivial
  // (e.g., avoids a trivial increase from the custom brightness 59% to the next
  // user step at 60%.)
  ssize_t current_step =
      PercentToUserStepIndex(user_brightness_percent_.value());
  if (current_step < static_cast<int>(user_steps_.size()) - 1) {
    current_step++;
  }
  UpdateUserBrightnessPercent(user_steps_[current_step]);
  num_user_adjustments_++;

  // Update to the new state.
  //
  // If we don't actually change the brightness, still emit a signal so the UI
  // can show the user that nothing changed.
  UpdateState(Transition::FAST, BacklightBrightnessChange_Cause_USER_REQUEST,
              SignalBehavior::kAlways);
}

void KeyboardBacklightController::HandleDecreaseBrightnessRequest(
    bool allow_off) {
  LOG(INFO) << "Got user-triggered request to decrease brightness";
  if (!backlight_->DeviceExists())
    return;

  // If this is the first time the backlight was manually controlled, use the
  // current backlight brightness as our starting point.
  if (!user_brightness_percent_.has_value()) {
    UpdateUserBrightnessPercent(current_percent_);
  }

  // Decrease the brightness by one step.
  //
  // We select the user step closest to the current brightness, and then drop
  // one below that. See comment above in `HandleIncreaseBrightnessRequest` for
  // rationale.
  ssize_t current_step =
      PercentToUserStepIndex(user_brightness_percent_.value());
  if (current_step > (allow_off ? 0 : 1)) {
    current_step--;
  }
  UpdateUserBrightnessPercent(user_steps_[current_step]);
  num_user_adjustments_++;

  // Update to the new state.
  //
  // If we don't actually change the brightness, still emit a signal so the UI
  // can show the user that nothing changed.
  UpdateState(Transition::FAST, BacklightBrightnessChange_Cause_USER_REQUEST,
              SignalBehavior::kAlways);
}

void KeyboardBacklightController::HandleGetBrightnessRequest(
    double* percent_out, bool* success_out) {
  *percent_out = current_percent_;
  *success_out = true;
}

void KeyboardBacklightController::HandleSetBrightnessRequest(
    double percent,
    Transition transition,
    SetBacklightBrightnessRequest_Cause cause) {
  // Ensure |percent| is a valid value, and in [0, 100.0].
  percent = util::ClampPercent(percent);

  // Values between 0 and kDimPercent are clamped down to zero.
  if (percent < kDimPercent) {
    percent = 0;
  }

  // If the underlying cause of the request was user triggered, account
  // for it in our metrics.
  bool user_triggered =
      (cause == SetBacklightBrightnessRequest_Cause_USER_REQUEST);
  if (user_triggered) {
    num_user_adjustments_++;
  }

  // Update to the user-selected percent.
  //
  // If the change was user-triggered, we always send a notification
  // to ensure that the UI reflects the (possibly unchanged) user setting.
  UpdateUserBrightnessPercent(percent);
  UpdateState(
      transition, ToBacklightBrightnessChangeCause(cause),
      user_triggered ? SignalBehavior::kAlways : SignalBehavior::kIfChanged);
}

void KeyboardBacklightController::HandleToggleKeyboardBacklightRequest() {
  LOG(INFO) << "Got user-triggered request to toggle keyboard backlight";

  // Toggle the state of the backlight.
  //
  // The backlight might be on either because it has been automatically set to
  // that value, or the user has explicitly set it. In both cases, we want to
  // turn it off.
  //
  // The backlight might be off for several reasons too: the user might have
  // toggled it off, explicitly decreased the brightness to 0, or turned
  // off due to inactivity. In all these cases, we want to turn it on.
  if (current_percent_ > 0) {
    // Turn off the backlight.
    UpdateUserBrightnessPercent(/*brightness=*/0);
    UpdateState(Transition::INSTANT,
                BacklightBrightnessChange_Cause_USER_TOGGLED_OFF,
                SignalBehavior::kAlways);
  } else {
    // Turn on the backlight, restoring it either to its previous value, or
    // moving it to a default value.
    DCHECK_GT(last_positive_user_brightness_percent_, 0)
        << "Previous user-set backlight brightness value "
        << last_positive_user_brightness_percent_ << " not a positive value.";
    UpdateUserBrightnessPercent(
        std::max(last_positive_user_brightness_percent_, kDimPercent));
    UpdateState(Transition::INSTANT,
                BacklightBrightnessChange_Cause_USER_TOGGLED_ON,
                SignalBehavior::kAlways);
  }

  num_user_adjustments_++;
}

bool KeyboardBacklightController::UpdateState(
    Transition transition,
    BacklightBrightnessChange_Cause cause,
    SignalBehavior signal_behavior) {
  TRACE_EVENT("power", "KeyboardBacklightController::UpdateState", "transition",
              transition, "cause", cause, "signal_behavior", signal_behavior);
  // Force the backlight off immediately in several special cases.
  if (forced_off_ || shutting_down_ || suspended_ ||
      lid_state_ == LidState::CLOSED || tablet_mode_ == TabletMode::ON)
    return ApplyBrightnessPercent(0.0, transition, cause, signal_behavior);

  // If the user has asked for a specific brightness level, use it unless the
  // user is inactive.
  if (user_brightness_percent_.has_value()) {
    double percent = *user_brightness_percent_;
    if ((off_for_inactivity_ || dimmed_for_inactivity_) && !hovering_)
      percent = off_for_inactivity_ ? 0.0 : std::min(kDimPercent, percent);
    return ApplyBrightnessPercent(percent, transition, cause, signal_behavior);
  }

  // If requested, force the backlight on if the user is currently or was
  // recently active and off otherwise.
  double percent = RecentlyHoveringOrUserActive() ? automated_percent_ : 0.0;
  return ApplyBrightnessPercent(percent, transition, cause, signal_behavior);
}

bool KeyboardBacklightController::ApplyBrightnessPercent(
    double percent,
    Transition transition,
    BacklightBrightnessChange_Cause cause,
    SignalBehavior signal_behavior) {
  const int64_t level = PercentToLevel(percent);

  // If the new level is the same as the existing level, we are not
  // mid-transition, and we don't need to send a signal, then there's nothing we
  // need to do.
  //
  // If we are mid-transition, we may need to speed up or slow down to the
  // target value, so may still need to perform an update.
  if (!backlight_->TransitionInProgress() &&
      level == PercentToLevel(current_percent_) &&
      signal_behavior != SignalBehavior::kAlways) {
    return false;
  }

  if (!backlight_->DeviceExists()) {
    // If the underlying device doesn't exist, save the new percent for later.
    current_percent_ = percent;
    return false;
  }

  base::TimeDelta interval = GetTransitionDuration(transition);
  LOG(INFO) << "Setting brightness to " << level << " (" << percent
            << "%) over " << interval.InMilliseconds() << " ms";
  if (!backlight_->SetBrightnessLevel(level, interval)) {
    LOG(ERROR) << "Failed to set brightness";
    return false;
  }

  current_percent_ = percent;
  EmitBrightnessChangedSignal(dbus_wrapper_, kKeyboardBrightnessChangedSignal,
                              percent, cause);

  for (BacklightControllerObserver& observer : observers_)
    observer.OnBrightnessChange(percent, cause, this);
  return true;
}

bool KeyboardBacklightController::ValidateUserSteps(std::string* err_msg) {
  if (user_steps_.empty()) {
    *err_msg = base::StringPrintf("No user brightness steps defined in %s",
                                  kKeyboardBacklightUserStepsPref);
    return false;
  }

  if (user_steps_[0] != 0.0) {
    *err_msg =
        base::StringPrintf("%s starts at %f instead of 0.0",
                           kKeyboardBacklightUserStepsPref, user_steps_[0]);
    return false;
  }

  for (const double& step : user_steps_)
    if (step < 0.0 || step > 100.0) {
      *err_msg = base::StringPrintf("%s step %f is outside [0.0, 100.0]",
                                    kKeyboardBacklightUserStepsPref, step);
      return false;
    }

  if (user_steps_.end() != std::adjacent_find(user_steps_.begin(),
                                              user_steps_.end(),
                                              std::greater_equal<double>())) {
    *err_msg = base::StringPrintf("%s is not strictly increasing",
                                  kKeyboardBacklightUserStepsPref);
    return false;
  }

  return true;
}

void KeyboardBacklightController::ScaleUserSteps() {
  size_t num_steps = user_steps_.size();

  if (num_steps < 3) {
    LOG(INFO) << "Not scaling user steps because there are too few steps";
    return;
  }

  // |user_steps_| is in strictly increasing order.
  min_raw_percent_ = user_steps_[0];
  max_raw_percent_ = user_steps_[num_steps - 1];
  min_visible_raw_percent = user_steps_[1];

  for (size_t i = 0; i < num_steps; i++) {
    user_steps_[i] = RawPercentToPercent(user_steps_[i]);
  }
}

double KeyboardBacklightController::RawPercentToPercent(
    double raw_percent) const {
  if (user_steps_.size() < 3)
    return raw_percent;

  raw_percent =
      std::max(std::min(raw_percent, max_raw_percent_), min_raw_percent_);

  if (raw_percent == min_visible_raw_percent)
    return kMinVisiblePercent;
  else if (raw_percent > min_visible_raw_percent)
    return (raw_percent - min_visible_raw_percent) /
               (max_raw_percent_ - min_visible_raw_percent) *
               (kMaxPercent - kMinVisiblePercent) +
           kMinVisiblePercent;
  else  // raw_percent < min_visible_raw_percent
    return (raw_percent - min_raw_percent_) /
               (min_visible_raw_percent - min_raw_percent_) *
               (kMinVisiblePercent - kMinPercent) +
           kMinPercent;
}

double KeyboardBacklightController::PercentToRawPercent(double percent) const {
  if (user_steps_.size() < 3)
    return percent;

  percent = util::ClampPercent(percent);

  if (percent == kMinVisiblePercent)
    return min_visible_raw_percent;
  else if (percent > kMinVisiblePercent)
    return (percent - kMinVisiblePercent) / (kMaxPercent - kMinVisiblePercent) *
               (max_raw_percent_ - min_visible_raw_percent) +
           min_visible_raw_percent;
  else  // percent < kMinVisiblePercent
    return (percent - kMinPercent) / (kMinVisiblePercent - kMinPercent) *
               (min_visible_raw_percent - min_raw_percent_) +
           min_raw_percent_;
}

void KeyboardBacklightController::HandleActivity(
    BacklightBrightnessChange_Cause cause) {
  last_user_activity_time_ = clock_->GetCurrentTime();
  UpdateTurnOffTimer();
  UpdateState(Transition::FAST, cause);
}

}  // namespace power_manager::policy
