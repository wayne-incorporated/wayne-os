// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/powerd/policy/internal_backlight_controller.h"

#include <sys/time.h>

#include <algorithm>
#include <cmath>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/check_op.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <dbus/message.h>

#include "power_manager/common/clock.h"
#include "power_manager/common/power_constants.h"
#include "power_manager/common/prefs.h"
#include "power_manager/powerd/policy/backlight_controller_observer.h"
#include "power_manager/powerd/system/backlight_interface.h"
#include "power_manager/powerd/system/dbus_wrapper.h"
#include "power_manager/powerd/system/display/display_power_setter.h"
#include "power_manager/proto_bindings/policy.pb.h"

namespace power_manager::policy {

namespace {

// Maximum valid value for percentages.
const double kMaxPercent = 100.0;

// When going into the idle-induced dim state, the backlight dims to this
// fraction (in the range [0.0, 1.0]) of its maximum brightness level.  This is
// a fraction rather than a percent so it won't change if
// kDefaultLevelToPercentExponent is modified.
const double kDimmedBrightnessFraction = 0.1;

// Value for |level_to_percent_exponent_|, assuming that at least
// |kMinLevelsForNonLinearScale| brightness levels are available -- if not, we
// just use 1.0 to give us a linear scale.
const double kDefaultLevelToPercentExponent = 0.5;

// Default brightness ratio used for battery saver.
// TODO(sxm): Implement downstream model-level brightness overrides.
const double kDefaultBatterySaverBrightnessFraction = 0.2;

// Returns the animation duration for |transition|.
base::TimeDelta TransitionToTimeDelta(
    BacklightController::Transition transition) {
  switch (transition) {
    case BacklightController::Transition::INSTANT:
      return base::TimeDelta();
    case BacklightController::Transition::FAST:
      return kFastBacklightTransition;
    case BacklightController::Transition::SLOW:
      return kSlowBacklightTransition;
  }
}

// Clamps |percent| to fit between kMinVisiblePercent and 100.
double ClampPercentToVisibleRange(double percent) {
  return std::min(
      kMaxPercent,
      std::max(InternalBacklightController::kMinVisiblePercent, percent));
}

// Reads |pref_name| from |prefs| and returns the desired initial brightness
// percent corresponding to |backlight_nits|, the backlight's actual maximum
// luminance. Crashes on failure.
//
// The pref's value should consist of one or more lines, each containing either
// a single double brightness percentage or a space-separated "<double-percent>
// <int64_t-max-level>" pair. The percentage from the first line either using
// the single-value format or matching |backlight_nits| will be returned.
//
// For example,
//
// 60.0 300
// 50.0 400
// 40.0
//
// indicates that 60% should be used if the maximum luminance is 300, 50% should
// be used if it's 400, and 40% should be used otherwise.
//
// Note that this method will crash if no matching lines are found.
double GetInitialBrightnessPercent(PrefsInterface* prefs,
                                   const std::string& pref_name,
                                   int64_t backlight_nits) {
  DCHECK(prefs);
  std::string pref_value;
  CHECK(prefs->GetString(pref_name, &pref_value))
      << "Unable to read pref " << pref_name;

  std::vector<std::string> lines = base::SplitString(
      pref_value, "\n", base::KEEP_WHITESPACE, base::SPLIT_WANT_ALL);
  for (const std::string& line : lines) {
    std::vector<std::string> parts =
        base::SplitString(line, base::kWhitespaceASCII, base::KEEP_WHITESPACE,
                          base::SPLIT_WANT_NONEMPTY);
    CHECK(parts.size() == 1U || parts.size() == 2U)
        << "Unable to parse \"" << line << "\" from pref " << pref_name;

    double percent = 0.0;
    CHECK(base::StringToDouble(parts[0], &percent) && percent >= 0.0 &&
          percent <= 100.0)
        << "Unable to parse \"" << parts[0] << "\" from pref " << pref_name
        << " as double in [0.0, 100.0]";
    if (parts.size() == 1U)
      return percent;

    int64_t nits = -1;
    CHECK(base::StringToInt64(parts[1], &nits))
        << "Unable to parse \"" << parts[1] << "\" from pref " << pref_name;
    if (nits == backlight_nits)
      return percent;
  }

  LOG(FATAL) << "Unable to find initial brightness percentage in pref "
             << pref_name << " for " << backlight_nits << " nits";
  return kMaxPercent;
}

}  // namespace

const int64_t InternalBacklightController::kMaxBrightnessSteps = 16;
const double InternalBacklightController::kMinVisiblePercent =
    kMaxPercent / kMaxBrightnessSteps;
const double InternalBacklightController::kMinLevelsForNonLinearMapping = 100;
const double InternalBacklightController::kDefaultMinVisibleBrightnessFraction =
    0.0065;

InternalBacklightController::InternalBacklightController()
    : clock_(new Clock),
      dimmed_brightness_percent_(kDimmedBrightnessFraction * 100.0),
      level_to_percent_exponent_(kDefaultLevelToPercentExponent),
      battery_saver_brightness_percent_(kDefaultBatterySaverBrightnessFraction *
                                        100.0),
      weak_ptr_factory_(this) {}

InternalBacklightController::~InternalBacklightController() = default;

void InternalBacklightController::Init(
    system::BacklightInterface* backlight,
    PrefsInterface* prefs,
    system::AmbientLightSensorInterface* sensor,
    system::DisplayPowerSetterInterface* display_power_setter,
    system::DBusWrapperInterface* dbus_wrapper,
    LidState initial_lid_state) {
  backlight_ = backlight;
  prefs_ = prefs;
  display_power_setter_ = display_power_setter;
  dbus_wrapper_ = dbus_wrapper;
  lid_state_ = initial_lid_state;

  max_level_ = backlight_->GetMaxBrightnessLevel();
  current_level_ = backlight_->GetCurrentBrightnessLevel();

  auto real_max_level = static_cast<double>(max_level_);

  if (!prefs_->GetInt64(kMinVisibleBacklightLevelPref, &min_visible_level_)) {
    min_visible_level_ = static_cast<int64_t>(
        lround(kDefaultMinVisibleBrightnessFraction * real_max_level));
  }
  min_visible_level_ = std::min(
      std::max(min_visible_level_, static_cast<int64_t>(1)), max_level_);

  const double initial_percent = LevelToPercent(current_level_);
  ambient_light_brightness_percent_ = initial_percent;

  int64_t max_nits = 0;
  prefs_->GetInt64(kInternalBacklightMaxNitsPref, &max_nits);
  ac_explicit_brightness_percent_ = GetInitialBrightnessPercent(
      prefs_, kInternalBacklightNoAlsAcBrightnessPref, max_nits);
  battery_explicit_brightness_percent_ = GetInitialBrightnessPercent(
      prefs_, kInternalBacklightNoAlsBatteryBrightnessPref, max_nits);

  prefs_->GetBool(kInstantTransitionsBelowMinLevelPref,
                  &instant_transitions_below_min_level_);

  if (sensor) {
    ambient_light_handler_ =
        std::make_unique<AmbientLightHandler>(sensor, this);
    ambient_light_handler_->set_name("panel");
    std::string pref_value;
    CHECK(prefs_->GetString(kInternalBacklightAlsStepsPref, &pref_value))
        << "Failed to read pref " << kInternalBacklightAlsStepsPref;

    double als_smoothing_constant;
    CHECK(prefs_->GetDouble(kAlsSmoothingConstantPref, &als_smoothing_constant))
        << "Failed to read pref " << kAlsSmoothingConstantPref;
    ambient_light_handler_->Init(pref_value, initial_percent,
                                 als_smoothing_constant);
  } else {
    use_ambient_light_ = false;
  }

  int64_t turn_off_screen_timeout_ms = 0;
  prefs_->GetInt64(kTurnOffScreenTimeoutMsPref, &turn_off_screen_timeout_ms);
  turn_off_screen_timeout_ = base::Milliseconds(turn_off_screen_timeout_ms);

  if (max_level_ == min_visible_level_ || kMaxBrightnessSteps == 1) {
    step_percent_ = kMaxPercent;
  } else {
    // 1 is subtracted from kMaxBrightnessSteps to account for the step between
    // |min_brightness_level_| and 0.
    step_percent_ =
        (kMaxPercent - kMinVisiblePercent) /
        static_cast<double>(
            std::min(kMaxBrightnessSteps - 1, max_level_ - min_visible_level_));
  }
  CHECK_GT(step_percent_, 0.0);

  system::BacklightInterface::BrightnessScale brightness_scale =
      backlight_->GetBrightnessScale();
  switch (brightness_scale) {
    case system::BacklightInterface::BrightnessScale::kLinear:
      level_to_percent_exponent_ = kDefaultLevelToPercentExponent;
      break;
    case system::BacklightInterface::BrightnessScale::kNonLinear:
      level_to_percent_exponent_ = 1.0;
      break;
    default:
      level_to_percent_exponent_ =
          real_max_level >= kMinLevelsForNonLinearMapping
              ? kDefaultLevelToPercentExponent
              : 1.0;
  }

  dimmed_brightness_percent_ = ClampPercentToVisibleRange(
      LevelToPercent(lround(kDimmedBrightnessFraction * real_max_level)));

  battery_saver_brightness_percent_ = ClampPercentToVisibleRange(LevelToPercent(
      lround(kDefaultBatterySaverBrightnessFraction * real_max_level)));

  RegisterIncreaseBrightnessHandler(
      dbus_wrapper_, kIncreaseScreenBrightnessMethod,
      base::BindRepeating(
          &InternalBacklightController::HandleIncreaseBrightnessRequest,
          weak_ptr_factory_.GetWeakPtr()));
  RegisterDecreaseBrightnessHandler(
      dbus_wrapper_, kDecreaseScreenBrightnessMethod,
      base::BindRepeating(
          &InternalBacklightController::HandleDecreaseBrightnessRequest,
          weak_ptr_factory_.GetWeakPtr()));
  RegisterSetBrightnessHandler(
      dbus_wrapper_, kSetScreenBrightnessMethod,
      base::BindRepeating(
          &InternalBacklightController::HandleSetBrightnessRequest,
          weak_ptr_factory_.GetWeakPtr()));
  RegisterGetBrightnessHandler(
      dbus_wrapper_, kGetScreenBrightnessPercentMethod,
      base::BindRepeating(
          &InternalBacklightController::HandleGetBrightnessRequest,
          weak_ptr_factory_.GetWeakPtr()));

  init_time_ = clock_->GetCurrentTime();
  LOG(INFO) << "Backlight has range [0, " << max_level_ << "] with "
            << step_percent_ << "% step and minimum-visible level of "
            << min_visible_level_ << "; current level is " << current_level_
            << " (" << LevelToPercent(current_level_) << "%)";
}

void InternalBacklightController::AddObserver(
    BacklightControllerObserver* observer) {
  DCHECK(observer);
  observers_.AddObserver(observer);
}

void InternalBacklightController::RemoveObserver(
    BacklightControllerObserver* observer) {
  DCHECK(observer);
  observers_.RemoveObserver(observer);
}

void InternalBacklightController::HandlePowerSourceChange(PowerSource source) {
  if (got_power_source_ && power_source_ == source)
    return;

  VLOG(1) << "Power source changed to " << PowerSourceToString(source);

  const bool on_ac = source == PowerSource::AC;

  // Ensure that the screen isn't dimmed in response to a transition to AC
  // or brightened in response to a transition to battery.
  if (got_power_source_) {
    const bool battery_exceeds_ac =
        battery_explicit_brightness_percent_ > ac_explicit_brightness_percent_;
    if (on_ac && battery_exceeds_ac)
      ac_explicit_brightness_percent_ = battery_explicit_brightness_percent_;
    else if (!on_ac && battery_exceeds_ac)
      battery_explicit_brightness_percent_ = ac_explicit_brightness_percent_;
  }

  power_source_ = source;
  got_power_source_ = true;
  UpdateState(
      on_ac ? BacklightBrightnessChange_Cause_EXTERNAL_POWER_CONNECTED
            : BacklightBrightnessChange_Cause_EXTERNAL_POWER_DISCONNECTED);
  if (ambient_light_handler_)
    ambient_light_handler_->HandlePowerSourceChange(source);
}

void InternalBacklightController::HandleDisplayModeChange(DisplayMode mode) {
  if (display_mode_ == mode)
    return;

  display_mode_ = mode;

  // If there's no external display now, make sure that the panel is on.
  if (display_mode_ == DisplayMode::NORMAL)
    EnsureUserBrightnessIsNonzero(BacklightBrightnessChange_Cause_OTHER);
}

void InternalBacklightController::HandleSessionStateChange(SessionState state) {
  EnsureUserBrightnessIsNonzero(BacklightBrightnessChange_Cause_OTHER);
  if (state == SessionState::STARTED) {
    als_adjustment_count_ = 0;
    user_adjustment_count_ = 0;
  }
}

void InternalBacklightController::HandlePowerButtonPress() {
  EnsureUserBrightnessIsNonzero(BacklightBrightnessChange_Cause_USER_ACTIVITY);
}

void InternalBacklightController::HandleLidStateChange(LidState state) {
  lid_state_ = state;
  UpdateState(BacklightBrightnessChange_Cause_OTHER);
}

void InternalBacklightController::HandleUserActivity(UserActivityType type) {
  // Don't increase the brightness automatically when the user hits a brightness
  // key: if they hit brightness-up, HandleIncreaseBrightnessRequest() will be
  // called soon anyway; if they hit brightness-down, the screen shouldn't get
  // turned back on. Also ignore volume keys.
  if (type != USER_ACTIVITY_BRIGHTNESS_UP_KEY_PRESS &&
      type != USER_ACTIVITY_BRIGHTNESS_DOWN_KEY_PRESS &&
      type != USER_ACTIVITY_VOLUME_UP_KEY_PRESS &&
      type != USER_ACTIVITY_VOLUME_DOWN_KEY_PRESS &&
      type != USER_ACTIVITY_VOLUME_MUTE_KEY_PRESS)
    EnsureUserBrightnessIsNonzero(
        BacklightBrightnessChange_Cause_USER_ACTIVITY);
}

void InternalBacklightController::HandleVideoActivity(bool is_fullscreen) {}

void InternalBacklightController::HandleWakeNotification() {
  // Increase the brightness of the display, even though the user might have set
  // it to zero, as this notification is waking up the device to get the user's
  // attention.
  EnsureUserBrightnessIsNonzero(
      BacklightBrightnessChange_Cause_WAKE_NOTIFICATION);
}

void InternalBacklightController::HandleHoverStateChange(bool hovering) {}

void InternalBacklightController::HandleTabletModeChange(TabletMode mode) {}

void InternalBacklightController::HandlePolicyChange(
    const PowerManagementPolicy& policy) {
  bool got_policy_brightness = false;

  double ac_brightness = ac_explicit_brightness_percent_;
  if (policy.has_ac_brightness_percent()) {
    LOG(INFO) << "Got policy-triggered request to set AC brightness to "
              << policy.ac_brightness_percent() << "%";
    ac_brightness = policy.ac_brightness_percent();
    got_policy_brightness = true;
  }
  double battery_brightness = battery_explicit_brightness_percent_;
  if (policy.has_battery_brightness_percent()) {
    LOG(INFO) << "Got policy-triggered request to set battery brightness to "
              << policy.battery_brightness_percent() << "%";
    battery_brightness = policy.battery_brightness_percent();
    got_policy_brightness = true;
  }

  using_policy_brightness_ = got_policy_brightness;
  if (got_policy_brightness) {
    SetExplicitBrightnessPercent(ac_brightness, battery_brightness,
                                 Transition::FAST,
                                 BacklightBrightnessChange_Cause_OTHER);
  }
  force_nonzero_brightness_for_user_activity_ =
      policy.has_force_nonzero_brightness_for_user_activity()
          ? policy.force_nonzero_brightness_for_user_activity()
          : true;
}

void InternalBacklightController::HandleDisplayServiceStart() {
  display_power_setter_->SetDisplayPower(display_power_state_,
                                         base::TimeDelta());
}

void InternalBacklightController::HandleBatterySaverModeChange(
    const BatterySaverModeState& state) {
  // TODO(sxm): Dimmed brightness levels might be too dark on low-nit screens.
  battery_saver_ = state.enabled();
  UpdateState(BacklightBrightnessChange_Cause_BATTERY_SAVER_STATE_CHANGED);
}

void InternalBacklightController::SetDimmedForInactivity(bool dimmed) {
  if (dimmed_for_inactivity_ == dimmed)
    return;

  VLOG(1) << (dimmed ? "Dimming" : "No longer dimming") << " for inactivity";
  dimmed_for_inactivity_ = dimmed;
  UpdateState(dimmed ? BacklightBrightnessChange_Cause_USER_INACTIVITY
                     : BacklightBrightnessChange_Cause_USER_ACTIVITY,
              dimmed ? Transition::FAST : Transition::INSTANT);
}

void InternalBacklightController::SetOffForInactivity(bool off) {
  if (off_for_inactivity_ == off)
    return;

  VLOG(1) << (off ? "Turning backlight off" : "No longer keeping backlight off")
          << " for inactivity";
  off_for_inactivity_ = off;
  UpdateState(off ? BacklightBrightnessChange_Cause_USER_INACTIVITY
                  : BacklightBrightnessChange_Cause_USER_ACTIVITY);
}

void InternalBacklightController::SetSuspended(bool suspended) {
  if (suspended_ == suspended)
    return;

  VLOG(1) << (suspended ? "Suspending" : "Unsuspending") << " backlight";
  suspended_ = suspended;
  UpdateState(BacklightBrightnessChange_Cause_OTHER);

  if (!suspended && ambient_light_handler_)
    ambient_light_handler_->HandleResume();
}

void InternalBacklightController::SetShuttingDown(bool shutting_down) {
  if (shutting_down_ == shutting_down)
    return;

  if (shutting_down)
    VLOG(1) << "Preparing backlight for shutdown";
  else
    LOG(WARNING) << "Exiting shutting-down state";
  shutting_down_ = shutting_down;
  UpdateState(BacklightBrightnessChange_Cause_OTHER);
}

void InternalBacklightController::SetForcedOff(bool forced_off) {
  if (forced_off_ == forced_off)
    return;

  VLOG(1) << (forced_off ? "Forcing" : "Not forcing") << " backlight off";
  forced_off_ = forced_off;
  UpdateState(forced_off
                  ? BacklightBrightnessChange_Cause_FORCED_OFF
                  : BacklightBrightnessChange_Cause_NO_LONGER_FORCED_OFF);
}

bool InternalBacklightController::GetForcedOff() {
  return forced_off_;
}

bool InternalBacklightController::GetBrightnessPercent(double* percent) {
  DCHECK(percent);
  *percent = LevelToPercent(current_level_);
  return true;
}

int InternalBacklightController::GetNumAmbientLightSensorAdjustments() const {
  return als_adjustment_count_;
}

int InternalBacklightController::GetNumUserAdjustments() const {
  return user_adjustment_count_;
}

double InternalBacklightController::LevelToPercent(int64_t raw_level) const {
  // If the passed-in level is below the minimum visible level, just map it
  // linearly into [0, kMinVisiblePercent).
  if (raw_level < min_visible_level_)
    return kMinVisiblePercent * static_cast<double>(raw_level) /
           static_cast<double>(min_visible_level_);

  // Since we're at or above the minimum level, we know that we're at 100% if
  // the min and max are equal.
  if (min_visible_level_ == max_level_)
    return 100.0;

  double linear_fraction = static_cast<double>(raw_level - min_visible_level_) /
                           static_cast<double>(max_level_ - min_visible_level_);
  return kMinVisiblePercent +
         (kMaxPercent - kMinVisiblePercent) *
             pow(linear_fraction, level_to_percent_exponent_);
}

int64_t InternalBacklightController::PercentToLevel(double percent) const {
  if (percent < kMinVisiblePercent)
    return lround(static_cast<double>(min_visible_level_) * percent /
                  kMinVisiblePercent);

  if (percent == kMaxPercent)
    return max_level_;

  double linear_fraction =
      (percent - kMinVisiblePercent) / (kMaxPercent - kMinVisiblePercent);
  return lround(static_cast<double>(min_visible_level_) +
                static_cast<double>(max_level_ - min_visible_level_) *
                    pow(linear_fraction, 1.0 / level_to_percent_exponent_));
}

void InternalBacklightController::SetBrightnessPercentForAmbientLight(
    double brightness_percent,
    AmbientLightHandler::BrightnessChangeCause cause) {
  ambient_light_brightness_percent_ = brightness_percent;
  got_ambient_light_brightness_percent_ = true;

  if (!use_ambient_light_)
    return;

  // If powerd hasn't started controlling the backlight yet, don't blame ambient
  // light for any brightness change that UpdateState() may end up making.
  const BacklightBrightnessChange_Cause backlight_cause =
      already_set_initial_state_ ? AmbientLightHandler::ToProtobufCause(cause)
                                 : BacklightBrightnessChange_Cause_OTHER;

  // This method is also called for power source changes while
  // AmbientLightHandler is controlling the brightness. Perform a fast
  // transition in that case.
  const bool ambient_light_changed =
      backlight_cause == BacklightBrightnessChange_Cause_AMBIENT_LIGHT_CHANGED;
  const Transition transition =
      ambient_light_changed ? Transition::SLOW : Transition::FAST;

  const int64_t old_level = current_level_;
  UpdateState(backlight_cause, transition);
  if (ambient_light_changed && current_level_ != old_level)
    als_adjustment_count_++;
}

void InternalBacklightController::OnColorTemperatureChanged(
    int color_temperature) {
  dbus::Signal signal(kPowerManagerInterface,
                      kAmbientColorTemperatureChangedSignal);
  dbus::MessageWriter(&signal).AppendInt32(color_temperature);
  dbus_wrapper_->EmitSignal(&signal);
}

bool InternalBacklightController::IsUsingAmbientLight() const {
  return use_ambient_light_;
}

void InternalBacklightController::ReportAmbientLightOnResumeMetrics(int lux) {
  // Ignore the ambient light sensor reading if the lid is closed.
  if (LidState::CLOSED == lid_state_) {
    return;
  }

  if (ambient_light_metrics_callback_) {
    ambient_light_metrics_callback_.Run(lux);
  }
}

void InternalBacklightController::RegisterAmbientLightResumeMetricsHandler(
    AmbientLightOnResumeMetricsCallback callback) {
  ambient_light_metrics_callback_ = std::move(callback);
}

double InternalBacklightController::SnapBrightnessPercentToNearestStep(
    double percent) const {
  return round(percent / step_percent_) * step_percent_;
}

double InternalBacklightController::GetExplicitBrightnessPercent() const {
  return power_source_ == PowerSource::AC
             ? ac_explicit_brightness_percent_
             : battery_explicit_brightness_percent_;
}

double InternalBacklightController::GetUndimmedBrightnessPercent() const {
  if (use_ambient_light_)
    return ClampPercentToVisibleRange(ambient_light_brightness_percent_);

  const double percent = GetExplicitBrightnessPercent();
  return percent <= kEpsilon ? 0.0 : ClampPercentToVisibleRange(percent);
}

void InternalBacklightController::HandleIncreaseBrightnessRequest() {
  double old_percent = GetUndimmedBrightnessPercent();
  double new_percent =
      (old_percent < kMinVisiblePercent - kEpsilon)
          ? kMinVisiblePercent
          : ClampPercentToVisibleRange(SnapBrightnessPercentToNearestStep(
                old_percent + step_percent_));

  // If we don't actually change the brightness, emit a signal so the UI can
  // show the user that nothing changed.
  const double current_percent = LevelToPercent(current_level_);
  HandleSetBrightnessRequest(new_percent, Transition::FAST,
                             SetBacklightBrightnessRequest_Cause_USER_REQUEST);
  if (LevelToPercent(current_level_) == current_percent) {
    EmitBrightnessChangedSignal(dbus_wrapper_, kScreenBrightnessChangedSignal,
                                current_percent,
                                BacklightBrightnessChange_Cause_USER_REQUEST);
  }
}

void InternalBacklightController::HandleDecreaseBrightnessRequest(
    bool allow_off) {
  // Lower the backlight to the next step, turning it off if it was already at
  // the minimum visible level.
  double old_percent = GetUndimmedBrightnessPercent();
  double new_percent =
      old_percent <= kMinVisiblePercent + kEpsilon
          ? 0.0
          : ClampPercentToVisibleRange(SnapBrightnessPercentToNearestStep(
                old_percent - step_percent_));

  if (!allow_off && new_percent <= kEpsilon) {
    user_adjustment_count_++;
    return;
  }

  // If we don't actually change the brightness, emit a signal so the UI can
  // show the user that nothing changed.
  const double current_percent = LevelToPercent(current_level_);
  HandleSetBrightnessRequest(new_percent, Transition::FAST,
                             SetBacklightBrightnessRequest_Cause_USER_REQUEST);
  if (LevelToPercent(current_level_) == current_percent) {
    EmitBrightnessChangedSignal(dbus_wrapper_, kScreenBrightnessChangedSignal,
                                current_percent,
                                BacklightBrightnessChange_Cause_USER_REQUEST);
  }
}

void InternalBacklightController::HandleSetBrightnessRequest(
    double percent,
    Transition transition,
    SetBacklightBrightnessRequest_Cause cause) {
  BacklightBrightnessChange_Cause change_cause =
      BacklightBrightnessChange_Cause_OTHER;
  const char* cause_str = "unknown";
  switch (cause) {
    case SetBacklightBrightnessRequest_Cause_USER_REQUEST:
      cause_str = "user-triggered";
      change_cause = BacklightBrightnessChange_Cause_USER_REQUEST;
      break;
    case SetBacklightBrightnessRequest_Cause_MODEL:
      cause_str = "model-triggered";
      change_cause = BacklightBrightnessChange_Cause_MODEL;
      break;
  }

  LOG(INFO) << "Got " << cause_str << " request to set brightness to "
            << percent << "%";
  if (cause == SetBacklightBrightnessRequest_Cause_USER_REQUEST)
    user_adjustment_count_++;
  using_policy_brightness_ = false;

  // When the user explicitly requests a specific brightness level, use it for
  // both AC and battery power.
  SetExplicitBrightnessPercent(percent, percent, transition, change_cause);
}

void InternalBacklightController::HandleGetBrightnessRequest(
    double* percent_out, bool* success_out) {
  DCHECK(percent_out);
  DCHECK(success_out);
  *percent_out = LevelToPercent(current_level_);
  *success_out = true;
}

void InternalBacklightController::EnsureUserBrightnessIsNonzero(
    BacklightBrightnessChange_Cause cause) {
  // Avoid turning the backlight back on if an external display is
  // connected since doing so may result in the desktop being resized. Also
  // don't turn it on if a policy has forced the brightness to zero.
  if (force_nonzero_brightness_for_user_activity_ &&
      display_mode_ == DisplayMode::NORMAL &&
      GetExplicitBrightnessPercent() < kMinVisiblePercent &&
      !using_policy_brightness_ && !use_ambient_light_) {
    SetExplicitBrightnessPercent(kMinVisiblePercent, kMinVisiblePercent,
                                 Transition::FAST, cause);
  }
}

void InternalBacklightController::SetExplicitBrightnessPercent(
    double ac_percent,
    double battery_percent,
    Transition transition,
    BacklightBrightnessChange_Cause cause) {
  use_ambient_light_ = false;
  ac_explicit_brightness_percent_ =
      ac_percent <= kEpsilon ? 0.0 : ClampPercentToVisibleRange(ac_percent);
  battery_explicit_brightness_percent_ =
      battery_percent <= kEpsilon ? 0.0
                                  : ClampPercentToVisibleRange(battery_percent);
  UpdateState(cause, transition);
}

void InternalBacklightController::UpdateState(
    BacklightBrightnessChange_Cause cause, Transition adjust_transition) {
  // Give up on the ambient light sensor if it's not supplying readings.
  if (use_ambient_light_ && !got_ambient_light_brightness_percent_ &&
      clock_->GetCurrentTime() - init_time_ >= kAmbientLightSensorTimeout) {
    LOG(ERROR) << "Giving up on ambient light sensor after getting no reading "
               << "within " << kAmbientLightSensorTimeout.InSeconds()
               << " seconds";
    use_ambient_light_ = false;
  }

  // Hold off on changing the brightness at startup until all the required
  // state has been received.
  // TODO(chromeos-power): Don't bail out if we'll turn the display off, since
  // that's independent of all of this.
  if (!got_power_source_ ||
      (use_ambient_light_ && !got_ambient_light_brightness_percent_))
    return;

  // First, figure out the backlight brightness and display power state that we
  // should be using right now.
  double brightness_percent = 100.0;
  Transition brightness_transition = Transition::INSTANT;

  chromeos::DisplayPowerState display_power = chromeos::DISPLAY_POWER_ALL_ON;
  base::TimeDelta display_delay;
  bool set_display_power = true;

  if (shutting_down_ || forced_off_) {
    brightness_percent = 0.0;
    display_power = chromeos::DISPLAY_POWER_ALL_OFF;
  } else if (suspended_) {
    brightness_percent = 0.0;
    // Chrome puts displays into the correct power state before suspend.
    set_display_power = false;
  } else if (off_for_inactivity_) {
    brightness_percent = 0.0;
    brightness_transition = Transition::FAST;
    display_power = chromeos::DISPLAY_POWER_ALL_OFF;
    display_delay = TransitionToTimeDelta(brightness_transition);
  } else if (lid_state_ == LidState::CLOSED) {
    brightness_percent = 0.0;
    // Leave external displays on for docked mode.
    display_power = chromeos::DISPLAY_POWER_INTERNAL_OFF_EXTERNAL_ON;
  } else {
    brightness_percent =
        std::min(GetUndimmedBrightnessPercent(),
                 dimmed_for_inactivity_ ? dimmed_brightness_percent_ : 100.0);

    if (battery_saver_ &&
        brightness_percent > battery_saver_brightness_percent_ &&
        cause != BacklightBrightnessChange_Cause_USER_REQUEST) {
      brightness_percent = battery_saver_brightness_percent_;
    }

    const bool turning_on =
        display_power_state_ != chromeos::DISPLAY_POWER_ALL_ON ||
        current_level_ == 0;
    brightness_transition =
        turning_on ? Transition::INSTANT
                   : (already_set_initial_state_ ? adjust_transition
                                                 : Transition::SLOW);

    if (brightness_percent <= kEpsilon) {
      // Keep external display(s) on if the brightness was explicitly set to 0.
      display_power = chromeos::DISPLAY_POWER_INTERNAL_OFF_EXTERNAL_ON;
      display_delay = TransitionToTimeDelta(brightness_transition) +
                      turn_off_screen_timeout_;
    }
  }

  // Now apply the state that we decided on.
  if (set_display_power && display_power != display_power_state_) {
    // For instant transitions, this call blocks until Chrome confirms that it
    // has made the change.
    display_power_setter_->SetDisplayPower(display_power, display_delay);
    display_power_state_ = display_power;
  }

  // Apply the brightness after toggling the display power. If we do it the
  // other way around, then the brightness set here has a potential to get
  // interleaved with the display power toggle operation in some drivers
  // resulting in this request being dropped and the brightness being set to its
  // previous value instead. See chrome-os-partner:31186 and :35662 for more
  // details.
  const int64_t new_level = PercentToLevel(brightness_percent);
  if (new_level != current_level_ || backlight_->TransitionInProgress()) {
    // Force an instant transition if we're moving into or out of the
    // below-min-visible (i.e. off-but-nonzero) range.
    bool starting_below_min_visible_level = current_level_ < min_visible_level_;
    bool ending_below_min_visible_level = new_level < min_visible_level_;
    if (instant_transitions_below_min_level_ &&
        starting_below_min_visible_level != ending_below_min_visible_level)
      brightness_transition = Transition::INSTANT;

    base::TimeDelta interval = TransitionToTimeDelta(brightness_transition);
    LOG(INFO) << "Setting brightness to " << new_level << " ("
              << brightness_percent << "%) over " << interval.InMilliseconds()
              << " ms";
    if (!backlight_->SetBrightnessLevel(new_level, interval)) {
      LOG(WARNING) << "Could not set brightness";
    } else {
      current_level_ = new_level;
      EmitBrightnessChangedSignal(dbus_wrapper_, kScreenBrightnessChangedSignal,
                                  brightness_percent, cause);
      for (BacklightControllerObserver& observer : observers_)
        observer.OnBrightnessChange(brightness_percent, cause, this);
    }
  }

  already_set_initial_state_ = true;
}

}  // namespace power_manager::policy
