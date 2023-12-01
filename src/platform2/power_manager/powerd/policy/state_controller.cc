// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/powerd/policy/state_controller.h"

#include <stdint.h>

#include <algorithm>
#include <cmath>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/files/file_util.h>
#include <base/functional/bind.h>
#include <base/functional/callback.h>
#include <base/logging.h>
#include <base/notreached.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <chromeos/dbus/service_constants.h>
#include <chromeos/ec/ec_commands.h>
#include <update_engine/proto_bindings/update_engine.pb.h>

#include "base/time/time.h"
#include "power_manager/common/clock.h"
#include "power_manager/common/metrics_constants.h"
#include "power_manager/common/power_constants.h"
#include "power_manager/common/prefs.h"
#include "power_manager/common/tracing.h"
#include "power_manager/common/util.h"
#include "power_manager/powerd/system/cros_ec_device_event.h"
#include "power_manager/powerd/system/dbus_wrapper.h"
#include "power_manager/proto_bindings/idle.pb.h"

namespace power_manager::policy {

namespace {

// Time to wait for display mode change after resuming with lid still closed
// before triggering idle and lid closed action (crbug.com/786721).
constexpr base::TimeDelta KWaitForExternalDisplayTimeout = base::Seconds(25);

// Time to wait for the display mode and policy after Init() is called.
constexpr base::TimeDelta kInitialStateTimeout = base::Seconds(10);

// Time to wait for the crash-boot-collect to successfully complete.
constexpr base::TimeDelta kCrashBootCollectTimeout = base::Minutes(1);

// Time to wait for responses to D-Bus method calls to update_engine.
constexpr base::TimeDelta kUpdateEngineDBusTimeout = base::Seconds(3);

// Interval between logging the list of current wake locks.
constexpr base::TimeDelta kWakeLocksLoggingInterval = base::Minutes(5);

// File used by crash_reporter to signal successful collection of per-boot crash
// logs.
constexpr char kCrashBootCollectorDoneFile[] =
    "/run/crash_reporter/boot-collector-done";

// A screen dim will be deferred by hps if `hps_result_` is POSITIVE longer than
// kHpsPositiveForDimDefer * delays_.screen_dim
constexpr float kHpsPositiveForDimDefer = 0.5;

// How many times hps is allowed to defer the dimming continuously.
constexpr int kNTimesForHpsToDeferDimming = 2;

// Returns |time_ms|, a time in milliseconds, as a
// util::TimeDeltaToString()-style string.
std::string MsToString(int64_t time_ms) {
  return util::TimeDeltaToString(base::Milliseconds(time_ms));
}

// Returns the minimum positive value after comparing |a| and |b|.  If one
// is zero or negative, the other is returned.  If both are zero or
// negative, an empty base::TimeDelta is returned.
base::TimeDelta GetMinPositiveTimeDelta(base::TimeDelta a, base::TimeDelta b) {
  if (a > base::TimeDelta()) {
    if (b > base::TimeDelta()) {
      return a < b ? a : b;
    } else {
      return a;
    }
  } else {
    return b;
  }
}

// Helper function for ScheduleActionTimeout() to compute how long to sleep
// before calling UpdateState() to perform the next-occurring action. Given
// |now| and an action that should be performed |action_delay| after
// |last_activity_time|, updates |timeout| to be the minimum of its current
// value and the time to wait before performing the action. Does nothing if
// |action_delay| is unset or if the action should've been performed already.
void UpdateActionTimeout(base::TimeTicks now,
                         base::TimeTicks last_activity_time,
                         base::TimeDelta action_delay,
                         base::TimeDelta* timeout) {
  if (action_delay <= base::TimeDelta())
    return;

  const base::TimeTicks action_time = last_activity_time + action_delay;
  if (action_time > now)
    *timeout = GetMinPositiveTimeDelta(*timeout, action_time - now);
}

// Helper function for UpdateState.  The general pattern here is:
// - If |inactivity_duration| has reached |delay| and
//   |action_already_performed| says that the controller hasn't yet
//   performed the corresponding action, then run |callback| and set
//   |action_already_performed| to ensure that the action doesn't get
//   performed again the next time this is called.
// - If |delay| hasn't been reached, then run |undo_callback| if non-null
//   to undo the action if needed and reset |action_already_performed| so
//   that the action can be performed later.
void HandleDelay(base::TimeDelta delay,
                 base::TimeDelta inactivity_duration,
                 base::OnceClosure callback,
                 base::OnceClosure undo_callback,
                 const std::string& description,
                 const std::string& undo_description,
                 bool* action_already_performed) {
  if (delay > base::TimeDelta() && inactivity_duration >= delay) {
    if (!*action_already_performed) {
      LOG(INFO) << description << " after "
                << util::TimeDeltaToString(inactivity_duration);
      std::move(callback).Run();
      *action_already_performed = true;
    }
  } else if (*action_already_performed) {
    if (!undo_callback.is_null()) {
      LOG(INFO) << undo_description;
      std::move(undo_callback).Run();
    }
    *action_already_performed = false;
  }
}

// Looks up |name|, an int64_t preference representing milliseconds, in
// |prefs|, and returns it as a base::TimeDelta.  Returns true on success.
bool GetMillisecondPref(PrefsInterface* prefs,
                        const std::string& name,
                        base::TimeDelta* out) {
  DCHECK(prefs);
  DCHECK(out);

  int64_t int_value = 0;
  if (!prefs->GetInt64(name, &int_value))
    return false;

  *out = base::Milliseconds(int_value);
  return true;
}

// Returns a string describing |delays| with each field prefixed by
// |prefix|. Helper method for GetPolicyDebugString().
std::string GetPolicyDelaysDebugString(
    const PowerManagementPolicy::Delays& delays, const std::string& prefix) {
  std::string str;
  if (delays.has_screen_dim_ms())
    str += prefix + "_dim=" + MsToString(delays.screen_dim_ms()) + " ";
  if (delays.has_quick_dim_ms())
    str += prefix + "_quick_dim=" + MsToString(delays.quick_dim_ms()) + " ";
  if (delays.has_screen_off_ms())
    str += prefix + "_screen_off=" + MsToString(delays.screen_off_ms()) + " ";
  if (delays.has_screen_lock_ms())
    str += prefix + "_lock=" + MsToString(delays.screen_lock_ms()) + " ";
  if (delays.has_quick_lock_ms())
    str += prefix + "_quick_lock=" + MsToString(delays.quick_lock_ms()) + " ";
  if (delays.has_idle_warning_ms())
    str += prefix + "_idle_warn=" + MsToString(delays.idle_warning_ms()) + " ";
  if (delays.has_idle_ms())
    str += prefix + "_idle=" + MsToString(delays.idle_ms()) + " ";
  return str;
}

// Returns a string describing the wake locks in |policy|, or an empty string if
// no wake locks are held.
std::string GetWakeLocksLogString(const PowerManagementPolicy& policy) {
  std::string msg;
  if (policy.screen_wake_lock())
    msg += " screen";
  if (policy.dim_wake_lock())
    msg += " dim";
  if (policy.system_wake_lock())
    msg += " system";

  if (msg.empty())
    return std::string();

  msg = "Active wake locks:" + msg;
  if (policy.has_reason())
    msg += " (" + policy.reason() + ")";
  return msg;
}

}  // namespace

StateController::TestApi::TestApi(StateController* controller)
    : controller_(controller) {}

StateController::TestApi::~TestApi() {
  controller_ = nullptr;
}

void StateController::TestApi::TriggerActionTimeout() {
  CHECK(controller_->action_timer_.IsRunning());
  controller_->action_timer_.Stop();
  controller_->HandleActionTimeout();
}

bool StateController::TestApi::TriggerInitialStateTimeout() {
  if (!controller_->initial_state_timer_.IsRunning())
    return false;

  controller_->initial_state_timer_.Stop();
  controller_->HandleInitialStateTimeout();
  return true;
}

bool StateController::TestApi::TriggerWaitForExternalDisplayTimeout() {
  if (!controller_->WaitingForExternalDisplay())
    return false;

  controller_->wait_for_external_display_timer_.Stop();
  controller_->HandleWaitForExternalDisplayTimeout();
  return true;
}

bool StateController::TestApi::TriggerHandleCrashBootCollectTimeout() {
  if (!controller_->WaitingForCrashBootCollect())
    return false;

  controller_->wait_for_crash_boot_collect_timer_.Stop();
  controller_->HandleCrashBootCollectTimeout();
  return true;
}

bool StateController::Delays::operator!=(
    const StateController::Delays& o) const {
  // Don't bother checking screen_dim_imminent; it's a synthetic delay that's
  // based solely on screen_dim.
  return idle != o.idle || idle_warning != o.idle_warning ||
         screen_off != o.screen_off || screen_dim != o.screen_dim ||
         screen_lock != o.screen_lock || quick_dim != o.quick_dim ||
         quick_lock != o.quick_lock;
}

class StateController::ActivityInfo {
 public:
  ActivityInfo() = default;
  ActivityInfo(const ActivityInfo&) = delete;
  ActivityInfo& operator=(const ActivityInfo&) = delete;

  ~ActivityInfo() = default;

  bool active() const { return active_; }

  // Returns |now| if the activity is currently active or the last time that it
  // was active otherwise (or an unset time if it was never active).
  //
  // This method provides a convenient shorthand for callers that are trying to
  // compute a most-recent-activity timestamp across several different
  // activities. This method's return value should not be compared against the
  // current time to determine if the activity is currently active; call
  // active() instead.
  base::TimeTicks GetLastActiveTime(base::TimeTicks now) const {
    return active_ ? now : last_active_time_;
  }

  // Updates the current state of the activity.
  void SetActive(bool active, base::TimeTicks now) {
    if (active == active_)
      return;

    active_ = active;
    last_active_time_ = active ? base::TimeTicks() : now;
  }

 private:
  // True if the activity is currently active.
  bool active_ = false;

  // If the activity is currently inactive, the time at which it was last
  // active. Unset if it is currently active or was never active.
  base::TimeTicks last_active_time_;
};

constexpr base::TimeDelta StateController::kScreenDimImminentInterval;
constexpr base::TimeDelta StateController::kDeferDimmingTimeLimit;

// static
std::string StateController::GetPolicyDebugString(
    const PowerManagementPolicy& policy) {
  std::string str = GetPolicyDelaysDebugString(policy.ac_delays(), "ac");
  str += GetPolicyDelaysDebugString(policy.battery_delays(), "battery");

  if (policy.has_ac_idle_action()) {
    str += "ac_idle=" +
           ActionToString(ProtoActionToAction(policy.ac_idle_action())) + " ";
  }
  if (policy.has_battery_idle_action()) {
    str += "battery_idle=" +
           ActionToString(ProtoActionToAction(policy.battery_idle_action())) +
           " ";
  }
  if (policy.has_lid_closed_action()) {
    str += "lid_closed=" +
           ActionToString(ProtoActionToAction(policy.lid_closed_action())) +
           " ";
  }
  if (policy.has_screen_wake_lock()) {
    str +=
        "screen_wake_lock=" + base::NumberToString(policy.screen_wake_lock()) +
        " ";
  }
  if (policy.has_dim_wake_lock())
    str +=
        "dim_wake_lock=" + base::NumberToString(policy.dim_wake_lock()) + " ";
  if (policy.has_system_wake_lock()) {
    str +=
        "system_wake_lock=" + base::NumberToString(policy.system_wake_lock()) +
        " ";
  }
  if (policy.has_use_audio_activity())
    str +=
        "use_audio=" + base::NumberToString(policy.use_audio_activity()) + " ";
  if (policy.has_use_video_activity())
    str +=
        "use_video=" + base::NumberToString(policy.use_video_activity()) + " ";
  if (policy.has_presentation_screen_dim_delay_factor()) {
    str += "presentation_factor=" +
           base::NumberToString(policy.presentation_screen_dim_delay_factor()) +
           " ";
  }
  if (policy.has_user_activity_screen_dim_delay_factor()) {
    str +=
        "user_activity_factor=" +
        base::NumberToString(policy.user_activity_screen_dim_delay_factor()) +
        " ";
  }
  if (policy.has_wait_for_initial_user_activity()) {
    str += "wait_for_initial_user_activity=" +
           base::NumberToString(policy.wait_for_initial_user_activity()) + " ";
  }
  if (policy.has_force_nonzero_brightness_for_user_activity()) {
    str += "force_nonzero_brightness_for_user_activity=" +
           base::NumberToString(
               policy.force_nonzero_brightness_for_user_activity()) +
           " ";
  }
  if (policy.has_send_feedback_if_undimmed()) {
    str += "send_feedback_if_undimmed=" +
           base::NumberToString(policy.send_feedback_if_undimmed()) + " ";
  }
  if (policy.has_reason())
    str += "(" + policy.reason() + ")";

  return str.empty() ? "[empty]" : str;
}

StateController::StateController()
    : clock_(std::make_unique<Clock>()),
      audio_activity_(std::make_unique<ActivityInfo>()),
      screen_wake_lock_(std::make_unique<ActivityInfo>()),
      dim_wake_lock_(std::make_unique<ActivityInfo>()),
      system_wake_lock_(std::make_unique<ActivityInfo>()),
      wake_lock_logger_(kWakeLocksLoggingInterval),
      weak_ptr_factory_(this) {}

StateController::~StateController() {
  if (prefs_)
    prefs_->RemoveObserver(this);
}

void StateController::Init(Delegate* delegate,
                           PrefsInterface* prefs,
                           system::DBusWrapperInterface* dbus_wrapper,
                           PowerSource power_source,
                           LidState lid_state) {
  delegate_ = delegate;
  prefs_ = prefs;
  prefs_->AddObserver(this);
  LoadPrefs();

  dbus_wrapper_ = dbus_wrapper;
  dbus_wrapper->ExportMethod(
      kGetInactivityDelaysMethod,
      base::BindRepeating(&StateController::HandleGetInactivityDelaysMethodCall,
                          weak_ptr_factory_.GetWeakPtr()));

  update_engine_dbus_proxy_ =
      dbus_wrapper_->GetObjectProxy(update_engine::kUpdateEngineServiceName,
                                    update_engine::kUpdateEngineServicePath);
  dbus_wrapper_->RegisterForServiceAvailability(
      update_engine_dbus_proxy_,
      base::BindOnce(&StateController::HandleUpdateEngineAvailable,
                     weak_ptr_factory_.GetWeakPtr()));
  dbus_wrapper_->RegisterForSignal(
      update_engine_dbus_proxy_, update_engine::kUpdateEngineInterface,
      update_engine::kStatusUpdateAdvanced,
      base::BindRepeating(
          &StateController::HandleUpdateEngineStatusUpdateSignal,
          weak_ptr_factory_.GetWeakPtr()));

  dim_advisor_.Init(dbus_wrapper_, this);

  last_user_activity_time_ = clock_->GetCurrentTime();
  power_source_ = power_source;
  lid_state_ = lid_state;

  initial_state_timer_.Start(FROM_HERE, kInitialStateTimeout, this,
                             &StateController::HandleInitialStateTimeout);

  crash_boot_collector_watcher_.Watch(
      base::FilePath(kCrashBootCollectorDoneFile),
      base::FilePathWatcher::Type::kNonRecursive,
      base::BindRepeating(
          &StateController::MaybeStopWaitForCrashBootCollectTimer,
          weak_ptr_factory_.GetWeakPtr()));

  wait_for_crash_boot_collect_timer_.Start(
      FROM_HERE, kCrashBootCollectTimeout, this,
      &StateController::HandleCrashBootCollectTimeout);

  UpdateSettingsAndState();

  // Emit the current screen-idle state in case powerd restarted while the
  // screen was dimmed or turned off.
  EmitScreenIdleStateChanged(screen_dimmed_, screen_turned_off_);

  initialized_ = true;
}

void StateController::HandlePowerSourceChange(PowerSource source) {
  TRACE_EVENT("power", "StateController::HandlePowerSourceChange", "source",
              source);
  CHECK(initialized_);
  if (source == power_source_)
    return;

  power_source_ = source;
  UpdateLastUserActivityTime();
  UpdateSettingsAndState();
}

void StateController::HandleLidStateChange(LidState state) {
  TRACE_EVENT("power", "StateController::HandleLidStateChange", "state", state);
  CHECK(initialized_);
  if (state == lid_state_)
    return;

  lid_state_ = state;

  if (lid_state_ == LidState::OPEN) {
    StopWaitForExternalDisplayTimer();
    UpdateLastUserActivityTime();
  }
  UpdateSettingsAndState();
}

void StateController::HandleTabletModeChange(TabletMode mode) {
  TRACE_EVENT("power", "StateController::HandleTabletModeChange", "mode", mode);
  DCHECK(initialized_);

  // We don't care about the mode, but we treat events as user activity.
  UpdateLastUserActivityTime();
  UpdateState();
}

void StateController::HandleSessionStateChange(SessionState state) {
  TRACE_EVENT("power", "StateController::HandleSessionStateChange", "state",
              state);
  CHECK(initialized_);
  if (state == session_state_)
    return;

  session_state_ = state;
  saw_user_activity_soon_after_screen_dim_or_off_ = false;
  saw_user_activity_during_current_session_ = false;
  UpdateLastUserActivityTime();
  UpdateSettingsAndState();
}

void StateController::HandleDisplayModeChange(DisplayMode mode) {
  TRACE_EVENT("power", "StateController::HandleDisplayModeChange", "mode",
              mode);
  CHECK(initialized_);
  if (mode == display_mode_ && got_initial_display_mode_)
    return;

  display_mode_ = mode;

  if (!got_initial_display_mode_) {
    got_initial_display_mode_ = true;
    MaybeStopInitialStateTimer();
  } else if (IsScreenTurnedOffRecently(
                 kIgnoreDisplayModeAfterScreenOffInterval)) {
    VLOG(1) << "Ignoring display mode change after recently turning the "
               "screens off";
    return;
  } else {
    UpdateLastUserActivityTime();
  }

  StopWaitForExternalDisplayTimer();

  if (defer_external_display_timeout_s_ && lid_state_ == LidState::CLOSED)
    wait_for_external_display_timer_.Start(
        FROM_HERE, base::Seconds(defer_external_display_timeout_s_), this,
        &StateController::HandleWaitForExternalDisplayTimeout);

  UpdateSettingsAndState();
}

void StateController::HandleResume(LidState state) {
  TRACE_EVENT("power", "StateController::HandleResume", "state", state);
  CHECK(initialized_);

  lid_state_ = state;
  // If resumed with closed lid and not in docked mode, let us wait for docked
  // mode before resuspending again.
  if (lid_state_ == LidState::CLOSED && !in_docked_mode()) {
    LOG(INFO) << "Waiting for external display before performing idle or "
                 "lid closed action";
    wait_for_external_display_timer_.Start(
        FROM_HERE, KWaitForExternalDisplayTimeout, this,
        &StateController::HandleWaitForExternalDisplayTimeout);
    lid_closed_action_performed_ = false;
  } else if (lid_state_ == LidState::OPEN ||
             lid_state_ == LidState::NOT_PRESENT || in_docked_mode()) {
    // Treat resume as a user activity if the lid is not closed or if we are in
    // docked mode.
    UpdateLastUserActivityTime();
  }
  UpdateSettingsAndState();
}

void StateController::HandlePolicyChange(const PowerManagementPolicy& policy) {
  TRACE_EVENT("power", "StateController::HandlePolicyChange");
  CHECK(initialized_);
  policy_ = policy;
  if (!got_initial_policy_) {
    got_initial_policy_ = true;
    MaybeStopInitialStateTimer();
  }

  const base::TimeTicks now = clock_->GetCurrentTime();
  screen_wake_lock_->SetActive(policy.screen_wake_lock(), now);
  dim_wake_lock_->SetActive(policy.dim_wake_lock(), now);
  system_wake_lock_->SetActive(policy.system_wake_lock(), now);

  UpdateSettingsAndState();

  // Update the message that periodically lists active wake locks.
  wake_lock_logger_.OnStateChanged(GetWakeLocksLogString(policy));
}

void StateController::HandleUserActivity() {
  TRACE_EVENT("power", "StateController::HandleUserActivity");
  CHECK(initialized_);

  // Ignore user activity reported while the lid is closed unless we're in
  // docked mode.
  if (lid_state_ == LidState::CLOSED && !in_docked_mode()) {
    LOG(WARNING) << "Ignoring user activity received while lid is closed";
    return;
  }

  const bool old_saw_user_activity =
      saw_user_activity_soon_after_screen_dim_or_off_;
  const bool screen_turned_off_recently = IsScreenTurnedOffRecently(
      kUserActivityAfterScreenOffIncreaseDelaysInterval);
  if (!saw_user_activity_soon_after_screen_dim_or_off_ &&
      ((screen_dimmed_ && !screen_turned_off_) || screen_turned_off_recently)) {
    LOG(INFO) << "Scaling delays due to user activity while screen was dimmed "
              << "or soon after it was turned off";
    saw_user_activity_soon_after_screen_dim_or_off_ = true;
  }

  if (session_state_ == SessionState::STARTED)
    saw_user_activity_during_current_session_ = true;

  UpdateLastUserActivityTime();
  if (old_saw_user_activity != saw_user_activity_soon_after_screen_dim_or_off_)
    UpdateSettingsAndState();
  else
    UpdateState();
}

void StateController::HandleVideoActivity() {
  TRACE_EVENT("power", "StateController::HandleVideoActivity");
  CHECK(initialized_);
  if (screen_dimmed_ || screen_turned_off_) {
    LOG(INFO) << "Ignoring video since screen is dimmed or off";
    return;
  }
  last_video_activity_time_ = clock_->GetCurrentTime();
  UpdateState();
}

void StateController::HandleWakeNotification() {
  TRACE_EVENT("power", "StateController::HandleWakeNotification");
  CHECK(initialized_);

  // Ignore user activity reported while the lid is closed unless we're in
  // docked mode.
  if (lid_state_ == LidState::CLOSED && !in_docked_mode()) {
    LOG(INFO) << "Ignoring wake notification while lid is closed";
    return;
  }

  last_wake_notification_time_ = clock_->GetCurrentTime();
  UpdateState();
}

void StateController::HandleAudioStateChange(bool active) {
  TRACE_EVENT("power", "StateController::HandleAudioStateChange", "active",
              active);
  CHECK(initialized_);
  audio_activity_->SetActive(active, clock_->GetCurrentTime());
  UpdateState();
}

void StateController::HandleTpmStatus(int dictionary_attack_count) {
  TRACE_EVENT("power", "StateController::HandleTpmStatus",
              "dictionary_attack_count", dictionary_attack_count);
  if (tpm_dictionary_attack_count_ == dictionary_attack_count)
    return;

  tpm_dictionary_attack_count_ = dictionary_attack_count;
  UpdateSettingsAndState();
}

PowerManagementPolicy::Delays StateController::CreateInactivityDelaysProto()
    const {
  PowerManagementPolicy::Delays proto;
  if (!delays_.idle.is_zero())
    proto.set_idle_ms(delays_.idle.InMilliseconds());
  if (!delays_.idle_warning.is_zero())
    proto.set_idle_warning_ms(delays_.idle_warning.InMilliseconds());
  if (!delays_.screen_off.is_zero())
    proto.set_screen_off_ms(delays_.screen_off.InMilliseconds());
  if (!delays_.screen_dim.is_zero())
    proto.set_screen_dim_ms(delays_.screen_dim.InMilliseconds());
  if (!delays_.quick_dim.is_zero())
    proto.set_quick_dim_ms(delays_.quick_dim.InMilliseconds());
  if (!delays_.screen_lock.is_zero())
    proto.set_screen_lock_ms(delays_.screen_lock.InMilliseconds());
  if (!delays_.quick_lock.is_zero())
    proto.set_quick_lock_ms(delays_.quick_lock.InMilliseconds());
  return proto;
}

void StateController::OnPrefChanged(const std::string& pref_name) {
  CHECK(initialized_);
  if (pref_name == kDisableIdleSuspendPref ||
      pref_name == kIgnoreExternalPolicyPref) {
    LOG(INFO) << "Reloading prefs for " << pref_name << " change";
    LoadPrefs();
    UpdateSettingsAndState();
  }
}

bool StateController::ShouldRequestDimDeferSuggestion(base::TimeTicks now) {
  return !screen_dimmed_ && delays_.screen_dim_imminent > base::TimeDelta() &&
         // Only consider defer dimming when it is close to actual dimming.
         (now - GetLastActivityTimeForScreenDim(now) >=
          delays_.screen_dim_imminent) &&
         // No dimming defer after kDeferDimmingTimeLimit - delays_.screen_dim;
         // this is to make sure dimming always happens within
         // kDeferDimmingTimeLimit.
         (now - GetLastActivityTimeForScreenDimWithoutDefer(now) <=
          kDeferDimmingTimeLimit - delays_.screen_dim);
}

void StateController::HandleDeferFromSmartDim() {
  TRACE_EVENT("power", "StateController::HandleDeferFromSmartDim");
  if (screen_dimmed_) {
    VLOG(1) << "Screen is already dimmed";
    return;
  }
  last_defer_screen_dim_time_ = clock_->GetCurrentTime();
  UpdateState();
}

// static
std::string StateController::ActionToString(Action action) {
  switch (action) {
    case Action::SUSPEND:
      return "suspend";
    case Action::STOP_SESSION:
      return "logout";
    case Action::SHUT_DOWN:
      return "shutdown";
    case Action::DO_NOTHING:
      return "no-op";
  }
  NOTREACHED() << "Unhandled action " << static_cast<int>(action);
  return base::StringPrintf("unknown (%d)", static_cast<int>(action));
}

// static
StateController::Action StateController::ProtoActionToAction(
    PowerManagementPolicy_Action proto_action) {
  switch (proto_action) {
    case PowerManagementPolicy_Action_SUSPEND:
      return Action::SUSPEND;
    case PowerManagementPolicy_Action_STOP_SESSION:
      return Action::STOP_SESSION;
    case PowerManagementPolicy_Action_SHUT_DOWN:
      return Action::SHUT_DOWN;
    case PowerManagementPolicy_Action_DO_NOTHING:
      return Action::DO_NOTHING;
    default:
      NOTREACHED() << "Unhandled action " << static_cast<int>(proto_action);
      return Action::DO_NOTHING;
  }
}

// static
void StateController::ScaleDelays(Delays* delays,
                                  double screen_dim_scale_factor) {
  DCHECK(delays);
  if (screen_dim_scale_factor <= 1.0 || delays->screen_dim <= base::TimeDelta())
    return;

  const base::TimeDelta orig_screen_dim = delays->screen_dim;
  delays->screen_dim = base::Microseconds(delays->screen_dim.InMicrosecondsF() *
                                          screen_dim_scale_factor);

  const base::TimeDelta diff = delays->screen_dim - orig_screen_dim;
  if (delays->screen_off > base::TimeDelta())
    delays->screen_off += diff;
  if (delays->screen_lock > base::TimeDelta())
    delays->screen_lock += diff;
  if (delays->idle_warning > base::TimeDelta())
    delays->idle_warning += diff;
  if (delays->idle > base::TimeDelta())
    delays->idle += diff;
}

// static
void StateController::SanitizeDelays(Delays* delays) {
  DCHECK(delays);

  // Don't try to turn the screen off after performing the idle action.
  if (delays->screen_off > base::TimeDelta())
    delays->screen_off = std::min(delays->screen_off, delays->idle);
  else
    delays->screen_off = base::TimeDelta();

  // Similarly, don't try to dim the screen after turning it off.
  if (delays->screen_dim > base::TimeDelta()) {
    delays->screen_dim =
        std::min(delays->screen_dim,
                 GetMinPositiveTimeDelta(delays->idle, delays->screen_off));
  } else {
    delays->screen_dim = base::TimeDelta();
  }

  // A quick_dim after screen_dim will never happen.
  if (delays->quick_dim >= delays->screen_dim) {
    delays->quick_dim = base::TimeDelta();
  }

  // A quick_lock after screen_lock will never happen.
  if (delays->screen_lock > base::TimeDelta() &&
      delays->quick_lock >= delays->screen_lock) {
    delays->quick_lock = base::TimeDelta();
  }

  // Cap the idle-warning timeout to the idle-action timeout.
  if (delays->idle_warning > base::TimeDelta())
    delays->idle_warning = std::min(delays->idle_warning, delays->idle);
  else
    delays->idle_warning = base::TimeDelta();

  // If the lock delay matches or exceeds the idle delay, unset it --
  // Chrome's lock-before-suspend setting should be enabled instead.
  if (delays->screen_lock >= delays->idle ||
      delays->screen_lock < base::TimeDelta()) {
    delays->screen_lock = base::TimeDelta();
  }
}

// static
void StateController::MergeDelaysFromPolicy(
    const PowerManagementPolicy::Delays& policy_delays, Delays* delays_out) {
  DCHECK(delays_out);

  if (policy_delays.has_idle_ms() && policy_delays.idle_ms() >= 0) {
    delays_out->idle = base::Milliseconds(policy_delays.idle_ms());
  }
  if (policy_delays.has_idle_warning_ms() &&
      policy_delays.idle_warning_ms() >= 0) {
    delays_out->idle_warning =
        base::Milliseconds(policy_delays.idle_warning_ms());
  }
  if (policy_delays.has_screen_dim_ms() && policy_delays.screen_dim_ms() >= 0) {
    delays_out->screen_dim = base::Milliseconds(policy_delays.screen_dim_ms());
  }
  if (policy_delays.has_quick_dim_ms() && policy_delays.quick_dim_ms() >= 0) {
    delays_out->quick_dim = base::Milliseconds(policy_delays.quick_dim_ms());
  }
  if (policy_delays.has_screen_off_ms() && policy_delays.screen_off_ms() >= 0) {
    delays_out->screen_off = base::Milliseconds(policy_delays.screen_off_ms());
  }
  if (policy_delays.has_screen_lock_ms() &&
      policy_delays.screen_lock_ms() >= 0) {
    delays_out->screen_lock =
        base::Milliseconds(policy_delays.screen_lock_ms());
  }
  if (policy_delays.has_quick_lock_ms() && policy_delays.quick_lock_ms() >= 0) {
    delays_out->quick_lock = base::Milliseconds(policy_delays.quick_lock_ms());
  }
}

bool StateController::IsScreenTurnedOffRecently(
    base::TimeDelta recently_off_threshold) {
  return delays_.screen_off > base::TimeDelta() && screen_turned_off_ &&
         (clock_->GetCurrentTime() - screen_turned_off_time_) <=
             recently_off_threshold;
}

bool StateController::WaitingForInitialState() const {
  return initial_state_timer_.IsRunning();
}

bool StateController::WaitingForExternalDisplay() const {
  return wait_for_external_display_timer_.IsRunning();
}

bool StateController::WaitingForCrashBootCollect() const {
  return wait_for_crash_boot_collect_timer_.IsRunning();
}

bool StateController::WaitingForInitialUserActivity() const {
  return wait_for_initial_user_activity_ &&
         session_state_ == SessionState::STARTED &&
         !saw_user_activity_during_current_session_;
}

void StateController::MaybeStopInitialStateTimer() {
  if (got_initial_display_mode_ && got_initial_policy_)
    initial_state_timer_.Stop();
}

void StateController::StopWaitForExternalDisplayTimer() {
  wait_for_external_display_timer_.Stop();
}

void StateController::MaybeStopWaitForCrashBootCollectTimer(
    const base::FilePath& path, bool error) {
  if (base::PathExists(base::FilePath(kCrashBootCollectorDoneFile)) &&
      wait_for_crash_boot_collect_timer_.IsRunning()) {
    wait_for_crash_boot_collect_timer_.Stop();
    if (lid_state_ == LidState::CLOSED)
      UpdateState();
  }
}

bool StateController::IsIdleBlocked() const {
  return (use_audio_activity_ && audio_activity_->active()) ||
         screen_wake_lock_->active() || dim_wake_lock_->active() ||
         system_wake_lock_->active();
}

bool StateController::IsScreenDimBlocked() const {
  return screen_wake_lock_->active();
}

bool StateController::IsScreenOffBlocked() const {
  // If HDMI audio is active, the screen needs to be kept on.
  return IsScreenDimBlocked() || dim_wake_lock_->active() ||
         (delegate_->IsHdmiAudioActive() && audio_activity_->active());
}

bool StateController::IsScreenLockBlocked() const {
  return IsScreenDimBlocked() || dim_wake_lock_->active();
}

base::TimeTicks StateController::GetLastActivityTimeForIdle(
    base::TimeTicks now) const {
  base::TimeTicks last_time =
      WaitingForInitialUserActivity() ? now : last_user_activity_time_;
  if (use_audio_activity_)
    last_time = std::max(last_time, audio_activity_->GetLastActiveTime(now));
  if (use_video_activity_)
    last_time = std::max(last_time, last_video_activity_time_);
  last_time = std::max(last_time, last_defer_screen_dim_time_);
  last_time = std::max(last_time, last_wake_notification_time_);

  // All types of wake locks defer the idle action.
  last_time = std::max(last_time, screen_wake_lock_->GetLastActiveTime(now));
  last_time = std::max(last_time, dim_wake_lock_->GetLastActiveTime(now));
  last_time = std::max(last_time, system_wake_lock_->GetLastActiveTime(now));

  return last_time;
}

base::TimeTicks StateController::GetLastActivityTimeForScreenDimWithoutDefer(
    base::TimeTicks now) const {
  base::TimeTicks last_time =
      WaitingForInitialUserActivity() ? now : last_user_activity_time_;
  if (use_video_activity_)
    last_time = std::max(last_time, last_video_activity_time_);
  last_time = std::max(last_time, last_wake_notification_time_);

  // Only full-brightness wake locks keep the screen from dimming.
  last_time = std::max(last_time, screen_wake_lock_->GetLastActiveTime(now));

  return last_time;
}

base::TimeTicks StateController::GetLastActivityTimeForScreenDim(
    base::TimeTicks now) const {
  return std::max(GetLastActivityTimeForScreenDimWithoutDefer(now),
                  last_defer_screen_dim_time_);
}

base::TimeTicks StateController::GetLastActivityTimeForQuickDim(
    base::TimeTicks now) const {
  return std::max(last_hps_result_change_time_,
                  GetLastActivityTimeForScreenDim(now));
}

base::TimeTicks StateController::GetLastActivityTimeForScreenOff(
    base::TimeTicks now) const {
  base::TimeTicks last_time = GetLastActivityTimeForScreenDim(now);

  // On-but-dimmed wake locks keep the screen on.
  last_time = std::max(last_time, dim_wake_lock_->GetLastActiveTime(now));

  // If HDMI audio is active, the screen needs to be kept on.
  if (delegate_->IsHdmiAudioActive())
    last_time = std::max(last_time, audio_activity_->GetLastActiveTime(now));

  return last_time;
}

base::TimeTicks StateController::GetLastActivityTimeForScreenLock(
    base::TimeTicks now) const {
  // On-but-dimmed wake locks also keep the screen from locking.
  return std::max(GetLastActivityTimeForScreenDim(now),
                  dim_wake_lock_->GetLastActiveTime(now));
}

base::TimeTicks StateController::GetLastActivityTimeForQuickLock(
    base::TimeTicks now) const {
  // On-but-dimmed wake locks also keep the screen from locking.
  return std::max(GetLastActivityTimeForScreenLock(now),
                  last_hps_result_change_time_);
}

void StateController::UpdateLastUserActivityTime() {
  last_user_activity_time_ = clock_->GetCurrentTime();
  delegate_->ReportUserActivityMetrics();
}

void StateController::LoadPrefs() {
  prefs_->GetBool(kRequireUsbInputDeviceToSuspendPref,
                  &require_usb_input_device_to_suspend_);
  prefs_->GetBool(kAvoidSuspendWhenHeadphoneJackPluggedPref,
                  &avoid_suspend_when_headphone_jack_plugged_);
  prefs_->GetBool(kDisableIdleSuspendPref, &disable_idle_suspend_);
  prefs_->GetBool(kSendFeedbackIfUndimmedPref, &send_feedback_if_undimmed_);
  prefs_->GetBool(kFactoryModePref, &factory_mode_);
  prefs_->GetBool(kIgnoreExternalPolicyPref, &ignore_external_policy_);

  int64_t defer_external_display_timeout;
  prefs_->GetInt64(kDeferExternalDisplayTimeoutPref,
                   &defer_external_display_timeout);
  defer_external_display_timeout_s_ =
      static_cast<int>(defer_external_display_timeout);

  int64_t tpm_threshold = 0;
  prefs_->GetInt64(kTpmCounterSuspendThresholdPref, &tpm_threshold);
  tpm_dictionary_attack_suspend_threshold_ = static_cast<int>(tpm_threshold);

  CHECK(
      GetMillisecondPref(prefs_, kPluggedSuspendMsPref, &pref_ac_delays_.idle));
  CHECK(GetMillisecondPref(prefs_, kPluggedOffMsPref,
                           &pref_ac_delays_.screen_off));
  CHECK(GetMillisecondPref(prefs_, kPluggedDimMsPref,
                           &pref_ac_delays_.screen_dim));
  CHECK(GetMillisecondPref(prefs_, kPluggedQuickDimMsPref,
                           &pref_ac_delays_.quick_dim));
  CHECK(GetMillisecondPref(prefs_, kPluggedQuickLockMsPref,
                           &pref_ac_delays_.quick_lock));

  CHECK(GetMillisecondPref(prefs_, kUnpluggedSuspendMsPref,
                           &pref_battery_delays_.idle));
  CHECK(GetMillisecondPref(prefs_, kUnpluggedOffMsPref,
                           &pref_battery_delays_.screen_off));
  CHECK(GetMillisecondPref(prefs_, kUnpluggedDimMsPref,
                           &pref_battery_delays_.screen_dim));
  CHECK(GetMillisecondPref(prefs_, kUnpluggedQuickDimMsPref,
                           &pref_battery_delays_.quick_dim));
  CHECK(GetMillisecondPref(prefs_, kUnpluggedQuickLockMsPref,
                           &pref_battery_delays_.quick_lock));

  SanitizeDelays(&pref_ac_delays_);
  SanitizeDelays(&pref_battery_delays_);

  // Don't wait around for the external policy if the controller has been
  // instructed to ignore it.
  if (ignore_external_policy_) {
    got_initial_policy_ = true;
    MaybeStopInitialStateTimer();
  }
}

void StateController::UpdateSettingsAndState() {
  TRACE_EVENT("power", "UpdateSettingsAndState");
  const Action old_idle_action = idle_action_;
  const Action old_lid_closed_action = lid_closed_action_;
  const Delays old_delays = delays_;

  const bool on_ac = power_source_ == PowerSource::AC;
  const bool presenting = display_mode_ == DisplayMode::PRESENTATION;

  // Start out with the defaults loaded from the power manager's prefs.
  idle_action_ = Action::SUSPEND;
  lid_closed_action_ = Action::SUSPEND;
  delays_ = on_ac ? pref_ac_delays_ : pref_battery_delays_;
  use_audio_activity_ = true;
  use_video_activity_ = true;
  wait_for_initial_user_activity_ = false;
  double presentation_factor = 1.0;
  double user_activity_factor = 1.0;
  reason_for_ignoring_idle_action_.clear();

  // Now update them with values that were set in the policy.
  if (!ignore_external_policy_) {
    if (on_ac && policy_.has_ac_idle_action())
      idle_action_ = ProtoActionToAction(policy_.ac_idle_action());
    else if (!on_ac && policy_.has_battery_idle_action())
      idle_action_ = ProtoActionToAction(policy_.battery_idle_action());
    if (policy_.has_lid_closed_action())
      lid_closed_action_ = ProtoActionToAction(policy_.lid_closed_action());

    if (on_ac && policy_.has_ac_delays())
      MergeDelaysFromPolicy(policy_.ac_delays(), &delays_);
    else if (!on_ac && policy_.has_battery_delays())
      MergeDelaysFromPolicy(policy_.battery_delays(), &delays_);

    if (policy_.has_use_audio_activity())
      use_audio_activity_ = policy_.use_audio_activity();
    if (policy_.has_use_video_activity())
      use_video_activity_ = policy_.use_video_activity();
    if (policy_.has_presentation_screen_dim_delay_factor())
      presentation_factor = policy_.presentation_screen_dim_delay_factor();
    if (policy_.has_user_activity_screen_dim_delay_factor())
      user_activity_factor = policy_.user_activity_screen_dim_delay_factor();
    if (policy_.has_wait_for_initial_user_activity()) {
      wait_for_initial_user_activity_ =
          policy_.wait_for_initial_user_activity();
    }
    if (policy_.has_send_feedback_if_undimmed()) {
      send_feedback_if_undimmed_ = policy_.send_feedback_if_undimmed();
    }
  }

  if (presenting)
    ScaleDelays(&delays_, presentation_factor);
  else if (saw_user_activity_soon_after_screen_dim_or_off_)
    ScaleDelays(&delays_, user_activity_factor);

  if (idle_action_ == Action::SUSPEND || idle_action_ == Action::SHUT_DOWN) {
    // The disable-idle-suspend pref overrides |policy_|. Note that it also
    // prevents the system from shutting down on idle if no session has been
    // started.
    if (disable_idle_suspend_) {
      idle_action_ = Action::DO_NOTHING;
      reason_for_ignoring_idle_action_ =
          "disable_idle_suspend powerd pref is set (done automatically in dev)";
    }

    // Avoid suspending or shutting down due to inactivity while a system
    // update is being applied on AC power so users on slow connections can
    // get updates. Continue suspending on lid-close so users don't get
    // confused, though.
    if (updater_state_ == UpdaterState::UPDATING && on_ac) {
      idle_action_ = Action::DO_NOTHING;
      reason_for_ignoring_idle_action_ = "applying update on AC power";
    }

    // Avoid suspending or shutting down due to inactivity immediately after
    // resume if we are waiting for external display.
    if (WaitingForExternalDisplay()) {
      idle_action_ = Action::DO_NOTHING;
      reason_for_ignoring_idle_action_ =
          "waiting for display mode change on resuming with lid closed";
    }
  }

  // Ignore the lid being closed while presenting to support docked mode.
  if (presenting)
    lid_closed_action_ = Action::DO_NOTHING;

  // Override the idle and lid-closed actions to suspend instead of shutting
  // down if the TPM dictionary-attack counter is high.
  if (tpm_dictionary_attack_suspend_threshold_ > 0 &&
      tpm_dictionary_attack_count_ >=
          tpm_dictionary_attack_suspend_threshold_) {
    LOG(WARNING) << "TPM dictionary attack count is "
                 << tpm_dictionary_attack_count_ << " (threshold is "
                 << tpm_dictionary_attack_suspend_threshold_ << "); "
                 << "overriding actions to suspend instead of shutting down";
    if (idle_action_ == Action::SHUT_DOWN)
      idle_action_ = Action::SUSPEND;
    if (lid_closed_action_ == Action::SHUT_DOWN)
      lid_closed_action_ = Action::SUSPEND;
  }

  // Most functionality is disabled in factory mode.
  if (factory_mode_) {
    delays_.quick_dim = base::TimeDelta();
    delays_.screen_dim = base::TimeDelta();
    delays_.screen_off = base::TimeDelta();
    delays_.screen_lock = base::TimeDelta();
    delays_.quick_lock = base::TimeDelta();
    lid_closed_action_ = Action::DO_NOTHING;
    idle_action_ = Action::DO_NOTHING;
    reason_for_ignoring_idle_action_ = "factory mode is enabled";
  }

  SanitizeDelays(&delays_);

  delays_.screen_dim_imminent = std::max(
      delays_.screen_dim - kScreenDimImminentInterval, base::TimeDelta());

  // If the idle or lid-closed actions changed, make sure that we perform
  // the new actions in the event that the system is already idle or the
  // lid is already closed.
  if (idle_action_ != old_idle_action)
    idle_action_performed_ = false;
  if (lid_closed_action_ != old_lid_closed_action)
    lid_closed_action_performed_ = false;

  // If the lid is already closed and the action is suspend, we can proactively
  // notify the EC of an upcoming suspend.
  if (lid_state_ == LidState::CLOSED && !lid_closed_action_performed_ &&
      lid_closed_action_ == Action::SUSPEND) {
    system::EnableCrosEcDeviceEvent(EC_DEVICE_EVENT_WLC, false);
  }

  // Let UpdateState() know if it may need to re-send the warning with an
  // updated time-until-idle-action.
  resend_idle_warning_ = sent_idle_warning_ &&
                         delays_.idle_warning != base::TimeDelta() &&
                         delays_.idle != old_delays.idle;

  LogSettings();

  if (delays_ != old_delays) {
    dbus_wrapper_->EmitSignalWithProtocolBuffer(kInactivityDelaysChangedSignal,
                                                CreateInactivityDelaysProto());
  }

  UpdateState();
}

void StateController::LogSettings() {
  std::vector<std::string> wake_locks;
  wake_locks.reserve(3);
  if (screen_wake_lock_->active())
    wake_locks.emplace_back("screen");
  if (dim_wake_lock_->active())
    wake_locks.emplace_back("dim");
  if (system_wake_lock_->active())
    wake_locks.emplace_back("system");

  LOG(INFO) << "Updated settings:"
            << " dim=" << util::TimeDeltaToString(delays_.screen_dim)
            << " quick_dim=" << util::TimeDeltaToString(delays_.quick_dim)
            << " screen_off=" << util::TimeDeltaToString(delays_.screen_off)
            << " lock=" << util::TimeDeltaToString(delays_.screen_lock)
            << " quick_lock=" << util::TimeDeltaToString(delays_.quick_lock)
            << " idle_warn=" << util::TimeDeltaToString(delays_.idle_warning)
            << " idle=" << util::TimeDeltaToString(delays_.idle) << " ("
            << ActionToString(idle_action_) << ")"
            << " lid_closed=" << ActionToString(lid_closed_action_)
            << " use_audio=" << use_audio_activity_
            << " use_video=" << use_video_activity_
            << " wake_locks=" << base::JoinString(wake_locks, ",");

  if (wait_for_initial_user_activity_) {
    LOG(INFO) << "Deferring inactivity-triggered actions until user activity "
              << "is observed each time a session starts";
  }
}

void StateController::PerformAction(Action action, ActionReason reason) {
  TRACE_EVENT("power", "StateController::PerformAction", "action",
              ActionToString(action), "reason", reason);
  switch (action) {
    case Action::SUSPEND:
      delegate_->Suspend(reason);
      break;
    case Action::STOP_SESSION:
      delegate_->StopSession();
      break;
    case Action::SHUT_DOWN:
      delegate_->ShutDown();
      break;
    case Action::DO_NOTHING:
      break;
    default:
      NOTREACHED() << "Unhandled action " << static_cast<int>(action);
  }
}

StateController::Action StateController::GetIdleAction() const {
  if (!delegate_->IsOobeCompleted()) {
    LOG(INFO) << "Not performing idle action without OOBE completed";
    return Action::DO_NOTHING;
  }
  if (idle_action_ == Action::SUSPEND && require_usb_input_device_to_suspend_ &&
      !delegate_->IsUsbInputDeviceConnected()) {
    LOG(INFO) << "Not suspending for idle without USB input device";
    return Action::DO_NOTHING;
  }
  if (idle_action_ == Action::SUSPEND &&
      avoid_suspend_when_headphone_jack_plugged_ &&
      delegate_->IsHeadphoneJackPlugged()) {
    LOG(INFO) << "Not suspending for idle due to headphone jack";
    return Action::DO_NOTHING;
  }
  return idle_action_;
}

void StateController::UpdateState() {
  TRACE_EVENT("power", "UpdateState");
  base::TimeTicks now = clock_->GetCurrentTime();
  base::TimeDelta idle_duration = now - GetLastActivityTimeForIdle(now);
  base::TimeDelta duration_since_last_activity_for_screen_dim =
      now - GetLastActivityTimeForScreenDim(now);
  base::TimeDelta screen_off_duration =
      now - GetLastActivityTimeForScreenOff(now);
  base::TimeDelta screen_lock_duration =
      now - GetLastActivityTimeForScreenLock(now);

  // Only request a dimming defer suggestion at certain condition.
  if (ShouldRequestDimDeferSuggestion(now)) {
    // Hps is allowed to defer a dimming only if:
    // (1) Hps is enabled.
    // (2) hps_result_ is POSITIVE.
    // (3) hps_result_ is in POSITIVE state for some time.
    // (4) dimming is not deferred for more than kNTimesForHpsToDeferDimming
    // times
    auto hps_wait = base::Microseconds(kHpsPositiveForDimDefer *
                                       delays_.screen_dim.InMicrosecondsF());
    if (dim_advisor_.IsHpsSenseEnabled() &&
        hps_result_ == hps::HpsResult::POSITIVE &&
        now - last_hps_result_change_time_ >= hps_wait &&
        now - GetLastActivityTimeForScreenDimWithoutDefer(now) <=
            kNTimesForHpsToDeferDimming * delays_.screen_dim) {
      last_defer_screen_dim_time_ = clock_->GetCurrentTime();
      LOG(INFO) << "StateController: screen dim is deferred by HPS.";
      delegate_->ReportHpsEventDurationMetrics(
          metrics::kStandardDimDeferredByHpsSec,
          duration_since_last_activity_for_screen_dim);
    } else if (dim_advisor_.ReadyForSmartDimRequest(
                   now, delays_.screen_dim_imminent)) {
      // Ask for a SmartDimDecision which may also decide to defer the screen
      // dim.
      dim_advisor_.RequestSmartDimDecision(now);
    }
  }

  const bool screen_was_dimmed = screen_dimmed_;

  if (dim_advisor_.IsHpsSenseEnabled() && !delays_.quick_dim.is_zero()) {
    // Use new dim logic with Hps.
    HandleDimWithHps(now, duration_since_last_activity_for_screen_dim);
  } else {
    // Use old dim logic without Hps.
    HandleDelay(
        delays_.screen_dim, duration_since_last_activity_for_screen_dim,
        base::BindOnce(&Delegate::DimScreen, base::Unretained(delegate_)),
        base::BindOnce(&Delegate::UndimScreen, base::Unretained(delegate_)),
        "Dimming screen", "Undimming screen", &screen_dimmed_);
    if (screen_dimmed_ && !screen_was_dimmed) {
      last_dim_time_ = now;
      // quick_dim_ahead_ is reset on a standard dim.
      quick_dim_ahead_ = base::TimeDelta();
    } else if (!screen_dimmed_) {
      // If screen is not dimmed, set last_dim_time_ as base::TimeTicks().
      last_dim_time_ = base::TimeTicks();
    }
    if (screen_dimmed_ && !screen_was_dimmed && audio_activity_->active() &&
        delegate_->IsHdmiAudioActive()) {
      LOG(INFO)
          << "Audio is currently being sent to display; screen will not be "
          << "turned off for inactivity";
    }
  }

  const bool screen_was_turned_off = screen_turned_off_;
  HandleDelay(
      delays_.screen_off, screen_off_duration,
      base::BindOnce(&Delegate::TurnScreenOff, base::Unretained(delegate_)),
      base::BindOnce(&Delegate::TurnScreenOn, base::Unretained(delegate_)),
      "Turning screen off", "Turning screen on", &screen_turned_off_);
  if (screen_turned_off_ && !screen_was_turned_off)
    screen_turned_off_time_ = now;
  else if (!screen_turned_off_)
    screen_turned_off_time_ = base::TimeTicks();

  if (dim_advisor_.IsHpsSenseEnabled() && !delays_.quick_lock.is_zero()) {
    HandleScreenLockWithHps(now, screen_lock_duration);
  } else {
    const bool requested_screen_lock_previously = requested_screen_lock_;
    HandleDelay(
        delays_.screen_lock, screen_lock_duration,
        base::BindOnce(&Delegate::LockScreen, base::Unretained(delegate_)),
        base::OnceClosure(), "Locking screen", "", &requested_screen_lock_);
    if (requested_screen_lock_ && !requested_screen_lock_previously) {
      last_lock_requested_time_ = now;
    } else if (!requested_screen_lock_) {
      // Set last_lock_requested_time_ as base::TimeTicks() if not requested.
      last_lock_requested_time_ = base::TimeTicks();
    }
  }

  if (screen_dimmed_ != screen_was_dimmed ||
      screen_turned_off_ != screen_was_turned_off) {
    EmitScreenIdleStateChanged(screen_dimmed_, screen_turned_off_);
  }

  // The idle-imminent signal is only emitted if an idle action is set.
  if (delays_.idle_warning > base::TimeDelta() &&
      idle_duration >= delays_.idle_warning &&
      idle_action_ != Action::DO_NOTHING) {
    if (!sent_idle_warning_ || resend_idle_warning_) {
      const base::TimeDelta time_until_idle = delays_.idle - idle_duration;
      LOG(INFO) << "Emitting idle-imminent signal with "
                << util::TimeDeltaToString(time_until_idle) << " after "
                << util::TimeDeltaToString(idle_duration);
      IdleActionImminent proto;
      proto.set_time_until_idle_action(time_until_idle.InMicroseconds());
      dbus_wrapper_->EmitSignalWithProtocolBuffer(kIdleActionImminentSignal,
                                                  proto);
      sent_idle_warning_ = true;
    }
  } else if (sent_idle_warning_) {
    sent_idle_warning_ = false;
    // When resetting the idle-warning trigger, only emit the idle-deferred
    // signal if the idle action hasn't been performed yet or if it was a
    // no-op action.
    if (!idle_action_performed_ || idle_action_ == Action::DO_NOTHING) {
      LOG(INFO) << "Emitting idle-deferred signal";
      dbus_wrapper_->EmitBareSignal(kIdleActionDeferredSignal);
    }
  }
  resend_idle_warning_ = false;

  Action idle_action_to_perform = Action::DO_NOTHING;
  if (idle_duration >= delays_.idle) {
    if (!idle_action_performed_) {
      if (!reason_for_ignoring_idle_action_.empty()) {
        LOG(INFO) << "Not performing idle action because "
                  << reason_for_ignoring_idle_action_;
      }
      idle_action_to_perform = GetIdleAction();
      LOG(INFO) << "Ready to perform idle action ("
                << ActionToString(idle_action_to_perform) << ") after "
                << util::TimeDeltaToString(idle_duration);
      idle_action_performed_ = true;
    }
  } else {
    idle_action_performed_ = false;
  }

  Action lid_closed_action_to_perform = Action::DO_NOTHING;
  // Hold off on the lid-closed action if
  //  1. The initial display mode or policy hasn't been received. powerd starts
  //     before Chrome's gotten a chance to configure the displays and send the
  //     policy, and we don't want to shut down immediately if the user rebooted
  //     with the lid closed.
  //  2. Just resumed with lid still closed. Chrome takes a little bit of time
  //     to identify and configure external display and we don't want to suspend
  //     immediately if the device resumes with the lid still closed.
  //  3. Booted with closed lid and crash_reporter has not yet collected
  //     per-boot crash logs. Look at (crbug.com/988831) for more info.

  if (lid_state_ == LidState::CLOSED && !WaitingForInitialState() &&
      !WaitingForExternalDisplay() && !WaitingForCrashBootCollect()) {
    if (!lid_closed_action_performed_) {
      lid_closed_action_to_perform = lid_closed_action_;
      LOG(INFO) << "Ready to perform lid-closed action ("
                << ActionToString(lid_closed_action_to_perform) << ")";
      lid_closed_action_performed_ = true;
    }
  } else {
    lid_closed_action_performed_ = false;
  }

  if (idle_action_to_perform == Action::SHUT_DOWN ||
      lid_closed_action_to_perform == Action::SHUT_DOWN) {
    // If either of the actions is shutting down, don't perform the other.
    PerformAction(Action::SHUT_DOWN, idle_action_to_perform == Action::SHUT_DOWN
                                         ? ActionReason::IDLE
                                         : ActionReason::LID_CLOSED);
  } else if (idle_action_to_perform == lid_closed_action_to_perform) {
    // If both actions are the same, only perform it once.
    PerformAction(idle_action_to_perform, ActionReason::IDLE);
  } else {
    // Otherwise, perform both actions.  Note that one or both may be
    // DO_NOTHING.
    PerformAction(idle_action_to_perform, ActionReason::IDLE);
    PerformAction(lid_closed_action_to_perform, ActionReason::LID_CLOSED);
  }

  ScheduleActionTimeout(now);
}

void StateController::ScheduleActionTimeout(base::TimeTicks now) {
  TRACE_EVENT_BEGIN("power", "StateController::ScheduleActionTimeout");
  // Find the minimum of the delays that haven't yet occurred.
  base::TimeDelta timeout_delay;
  if (!IsScreenDimBlocked()) {
    base::TimeTicks last_activity_time_for_screen_dim =
        GetLastActivityTimeForScreenDim(now);

    // Schedule an action for calling MLDecisionService.
    if (dim_advisor_.IsSmartDimEnabled()) {
      UpdateActionTimeout(now, last_activity_time_for_screen_dim,
                          delays_.screen_dim_imminent, &timeout_delay);
    }
    // Schedule an action for quick dim.
    // We only schedule an action for quick dim if `hps_result_` is NEGATIVE.
    // If `hps_result_` is POSITIVE, there will be no quick dim, and when that
    // value becomes NEGATIVE, the UpdateState will be called and a quick dim
    // action will be scheduled.
    if (dim_advisor_.IsHpsSenseEnabled() && !delays_.quick_dim.is_zero() &&
        !screen_dimmed_ && hps_result_ == hps::HpsResult::NEGATIVE) {
      UpdateActionTimeout(now, GetLastActivityTimeForQuickDim(now),
                          delays_.quick_dim, &timeout_delay);
    }

    UpdateActionTimeout(now, last_activity_time_for_screen_dim,
                        delays_.screen_dim, &timeout_delay);
  }
  if (!IsScreenOffBlocked()) {
    UpdateActionTimeout(now, GetLastActivityTimeForScreenOff(now),
                        delays_.screen_off, &timeout_delay);
  }
  if (!IsScreenLockBlocked()) {
    UpdateActionTimeout(now, GetLastActivityTimeForScreenLock(now),
                        delays_.screen_lock, &timeout_delay);
    // Schedule an action for quick lock.
    // We only schedule an action for quick lock if `hps_result_` is NEGATIVE.
    if (dim_advisor_.IsHpsSenseEnabled() && !delays_.quick_lock.is_zero() &&
        !requested_screen_lock_ && hps_result_ == hps::HpsResult::NEGATIVE) {
      UpdateActionTimeout(now, GetLastActivityTimeForQuickLock(now),
                          delays_.quick_lock, &timeout_delay);
    }
  }
  if (!IsIdleBlocked()) {
    UpdateActionTimeout(now, GetLastActivityTimeForIdle(now),
                        delays_.idle_warning, &timeout_delay);
    UpdateActionTimeout(now, GetLastActivityTimeForIdle(now), delays_.idle,
                        &timeout_delay);
  }

  if (timeout_delay > base::TimeDelta()) {
    action_timer_.Start(FROM_HERE, timeout_delay, this,
                        &StateController::HandleActionTimeout);
    action_timer_time_for_testing_ = now + timeout_delay;
  } else {
    action_timer_.Stop();
    action_timer_time_for_testing_ = base::TimeTicks();
  }
  TRACE_EVENT_END("power", "timeout_delay_ms", timeout_delay.InMillisecondsF());
}

void StateController::HandleActionTimeout() {
  TRACE_EVENT("power", "StateController::HandleActionTimeout");
  action_timer_time_for_testing_ = base::TimeTicks();
  UpdateState();
}

void StateController::HandleInitialStateTimeout() {
  TRACE_EVENT("power", "StateController::HandleInitialStateTimeout");
  LOG(INFO) << "Didn't receive initial notification about display mode or "
            << "policy; using " << DisplayModeToString(display_mode_)
            << " display mode";
  UpdateState();
}

void StateController::HandleCrashBootCollectTimeout() {
  TRACE_EVENT("power", "StateController::HandleCrashBootCollectTimeout");
  LOG(INFO) << "CrashBootCollect did not complete sucessfully in "
            << util::TimeDeltaToString(kCrashBootCollectTimeout);
  if (lid_state_ == LidState::CLOSED)
    UpdateState();
}

void StateController::HandleWaitForExternalDisplayTimeout() {
  TRACE_EVENT("power", "StateController::HandleWaitForExternalDisplayTimeout");
  LOG(INFO) << "Didn't receive display mode change notification in "
            << util::TimeDeltaToString(KWaitForExternalDisplayTimeout)
            << " on resuming with lid closed";
  UpdateSettingsAndState();
}

void StateController::HandleGetInactivityDelaysMethodCall(
    dbus::MethodCall* method_call,
    dbus::ExportedObject::ResponseSender response_sender) {
  std::unique_ptr<dbus::Response> response(
      dbus::Response::FromMethodCall(method_call));
  dbus::MessageWriter writer(response.get());
  writer.AppendProtoAsArrayOfBytes(CreateInactivityDelaysProto());
  std::move(response_sender).Run(std::move(response));
}

void StateController::HandleUpdateEngineAvailable(bool available) {
  if (!available) {
    LOG(ERROR) << "Failed waiting for update engine to become available";
    return;
  }

  dbus::MethodCall method_call(update_engine::kUpdateEngineInterface,
                               update_engine::kGetStatusAdvanced);
  std::unique_ptr<dbus::Response> response = dbus_wrapper_->CallMethodSync(
      update_engine_dbus_proxy_, &method_call, kUpdateEngineDBusTimeout);
  if (!response)
    return;

  HandleUpdateEngineStatusMessage(response.get());
}

void StateController::HandleUpdateEngineStatusUpdateSignal(
    dbus::Signal* signal) {
  HandleUpdateEngineStatusMessage(signal);
}

void StateController::HandleUpdateEngineStatusMessage(dbus::Message* message) {
  DCHECK(message);
  dbus::MessageReader reader(message);
  update_engine::StatusResult status;
  if (!reader.PopArrayOfBytesAsProto(&status)) {
    LOG(ERROR) << "Unable to read update status args.";
    return;
  }

  update_engine::Operation operation = status.current_operation();
  LOG(INFO) << "Update operation is " << Operation_Name(operation);
  UpdaterState state = UpdaterState::IDLE;
  if (operation == update_engine::Operation::DOWNLOADING ||
      operation == update_engine::Operation::VERIFYING ||
      operation == update_engine::Operation::FINALIZING) {
    state = UpdaterState::UPDATING;
  } else if (operation == update_engine::Operation::UPDATED_NEED_REBOOT) {
    state = UpdaterState::UPDATED;
  }

  if (state == updater_state_)
    return;

  updater_state_ = state;
  UpdateSettingsAndState();
}

void StateController::EmitScreenIdleStateChanged(bool dimmed, bool off) {
  ScreenIdleState proto;
  proto.set_dimmed(dimmed);
  proto.set_off(off);
  dbus_wrapper_->EmitSignalWithProtocolBuffer(kScreenIdleStateChangedSignal,
                                              proto);
}

void StateController::HandleDimWithHps(
    base::TimeTicks now,
    base::TimeDelta duration_since_last_activity_for_screen_dim) {
  if (!screen_dimmed_) {
    // Try to dim.
    const bool should_quick_dim =
        duration_since_last_activity_for_screen_dim <
            delays_.screen_dim_imminent &&
        hps_result_ == hps::HpsResult::NEGATIVE &&
        now - GetLastActivityTimeForQuickDim(now) >= delays_.quick_dim;

    const bool should_standard_dim =
        duration_since_last_activity_for_screen_dim >= delays_.screen_dim;

    if (should_quick_dim || should_standard_dim) {
      LOG(INFO) << "Dimming screen after "
                << util::TimeDeltaToString(
                       duration_since_last_activity_for_screen_dim);
      delegate_->DimScreen();
      screen_dimmed_ = true;
      last_dim_time_ = now;

      if (should_quick_dim) {
        // Quick dim is not recorded here, but recorded when it got reverted or
        // successfully transitioned to a standard dim.

        // `quick_dim_ahead_` records how far from a standard dim when this
        // quick dim happens; so that later on, when this quick dim got reverted
        // eventually, we'll know whether the quick_dim stayed long enough to
        // transition to a standard dim.
        quick_dim_ahead_ =
            delays_.screen_dim - duration_since_last_activity_for_screen_dim;
        delegate_->ReportDimEventMetrics(metrics::DimEvent::QUICK_DIM);
      } else {
        // Record a standard dim event.
        delegate_->ReportDimEventMetrics(metrics::DimEvent::STANDARD_DIM);
        quick_dim_ahead_ = base::TimeDelta();
      }
    }
  } else {
    // Try to undim.

    // Screen should be undimmed if there is a user_activity after last_dim_time
    // NOTE: comparing to the original condition
    //   duration_since_last_activity_for_screen_dim < delays_.screen_dim
    // The new condition will skip an edge case that the screen is dimmed and
    // the delays_.screen_dim is set to a larger value without any user
    // activity. This will undim the screen in the original condition; but not
    // in this new condition. We don't think this edge case could happen or even
    // if it does, a reasonably better behaviour is to apply that new
    // delays_.screen_dim in the next dimming process.
    bool undim_for_user_activity =
        GetLastActivityTimeForScreenDim(now) >= last_dim_time_;

    const bool undim_for_hps = !undim_for_user_activity &&
                               duration_since_last_activity_for_screen_dim <
                                   delays_.screen_dim_imminent &&
                               hps_result_ == hps::HpsResult::POSITIVE;

    if (undim_for_hps || undim_for_user_activity) {
      const base::TimeDelta duration_since_last_dim = now - last_dim_time_;

      LOG(INFO) << "Undimming screen after "
                << util::TimeDeltaToString(duration_since_last_dim);

      delegate_->UndimScreen();
      screen_dimmed_ = false;
      last_dim_time_ = base::TimeTicks();

      // We know that quick_dim happened quick_dim_ahead_ before standard dim,
      // and duration_since_last_dim has passed since last dim.
      // duration_since_last_dim >= quick_dim_ahead_ means that even if we
      // didn't have quick dim before, we would have a standard dim by now.
      // We named this case as a transitioning to standard dim.
      const bool transitioned_to_standard_dim =
          duration_since_last_dim >= quick_dim_ahead_;

      if (send_feedback_if_undimmed_ && !transitioned_to_standard_dim) {
        dim_advisor_.UnDimFeedback(undim_for_user_activity);
      }

      if (undim_for_hps) {
        // Undimmed by hps.

        delegate_->ReportHpsEventDurationMetrics(
            metrics::kQuickDimDurationBeforeRevertedByHpsSec,
            duration_since_last_dim);
        delegate_->ReportDimEventMetrics(
            metrics::DimEvent::QUICK_DIM_REVERTED_BY_HPS);
      } else {
        // Undimmed by user.

        if (quick_dim_ahead_.is_zero()) {
          // A standard dim was undimmed.
          delegate_->ReportHpsEventDurationMetrics(
              metrics::kStandardDimDurationBeforeRevertedByUserSec,
              duration_since_last_dim);
        } else {
          // A quick dim was undimmed.
          delegate_->ReportHpsEventDurationMetrics(
              metrics::kQuickDimDurationBeforeRevertedByUserSec,
              duration_since_last_dim);
          if (transitioned_to_standard_dim) {
            delegate_->ReportDimEventMetrics(
                metrics::DimEvent::QUICK_DIM_TRANSITIONED_TO_STANDARD_DIM);
          } else {
            delegate_->ReportDimEventMetrics(
                metrics::DimEvent::QUICK_DIM_REVERTED_BY_USER);
          }
        }
      }
    }
  }
}

void StateController::HandleScreenLockWithHps(
    base::TimeTicks now,
    base::TimeDelta duration_since_last_activity_for_screen_lock) {
  if (!requested_screen_lock_) {
    // Try to lock.
    const bool should_quick_lock =
        hps_result_ == hps::HpsResult::NEGATIVE &&
        now - GetLastActivityTimeForQuickLock(now) >= delays_.quick_lock;

    const bool should_standard_lock =
        delays_.screen_lock > base::TimeDelta() &&
        duration_since_last_activity_for_screen_lock >= delays_.screen_lock;

    if (should_quick_lock || should_standard_lock) {
      LOG(INFO) << "Lock screen after "
                << util::TimeDeltaToString(
                       duration_since_last_activity_for_screen_lock);
      delegate_->LockScreen();
      requested_screen_lock_ = true;
      last_lock_requested_time_ = now;
      if (should_quick_lock) {
        delegate_->ReportLockEventMetrics(metrics::LockEvent::QUICK_LOCK);
      } else {
        delegate_->ReportLockEventMetrics(metrics::LockEvent::STANDARD_LOCK);
      }
    }
  } else if (GetLastActivityTimeForScreenLock(now) >=
             last_lock_requested_time_) {
    requested_screen_lock_ = false;
    last_lock_requested_time_ = base::TimeTicks();
  }
}

void StateController::HandleHpsResultChange(hps::HpsResult hps_result) {
  // Calls UpdateState to consume the new HpsResult.
  if (hps_result_ == hps_result) {
    return;
  }
  hps_result_ = hps_result;
  last_hps_result_change_time_ = clock_->GetCurrentTime();
  UpdateState();
}

}  // namespace power_manager::policy
