// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef POWER_MANAGER_POWERD_POLICY_STATE_CONTROLLER_H_
#define POWER_MANAGER_POWERD_POLICY_STATE_CONTROLLER_H_

#include <memory>
#include <string>

#include <base/files/file_path_watcher.h>
#include <base/memory/weak_ptr.h>
#include <base/time/time.h>
#include <base/timer/timer.h>
#include <dbus/exported_object.h>
#include <dbus/message.h>

#include "hps/proto_bindings/hps_service.pb.h"
#include "power_manager/common/activity_logger.h"
#include "power_manager/common/metrics_constants.h"
#include "power_manager/common/power_constants.h"
#include "power_manager/common/prefs_observer.h"
#include "power_manager/powerd/policy/dim_advisor.h"
#include "power_manager/proto_bindings/policy.pb.h"

namespace dbus {
class Message;
class MethodCall;
class ObjectProxy;
class Signal;
}  // namespace dbus

namespace power_manager {

class Clock;
class PrefsInterface;

namespace system {
class DBusWrapperInterface;
}  // namespace system

namespace policy {

// StateController is responsible for telling the power manager when to
// perform various actions.
class StateController : public PrefsObserver {
 public:
  // Reasons that actions are performed.
  enum class ActionReason {
    // The user was inactive for long enough that the idle timeout was reached.
    IDLE,
    // The system's lid was closed.
    LID_CLOSED,
  };

  // Interface for classes that perform the actions requested by
  // StateController (or otherwise help it interact with the real world).
  class Delegate {
   public:
    virtual ~Delegate() = default;

    // Returns true if a USB input devices is connected.
    virtual bool IsUsbInputDeviceConnected() = 0;

    // Returns true if the Chrome OS OOBE (out of box experience) has been
    // completed.
    virtual bool IsOobeCompleted() = 0;

    // Returns true if an HDMI audio output is active. This method does not need
    // to check whether audio is actually currently playing.
    virtual bool IsHdmiAudioActive() = 0;

    // Returns true if a cable is currently plugged in to the headphone jack.
    virtual bool IsHeadphoneJackPlugged() = 0;

    // Dims the screen in response to the system being idle.
    virtual void DimScreen() = 0;

    // Undoes DimScreen().
    virtual void UndimScreen() = 0;

    // Turns the screen off in response to the system being idle.
    virtual void TurnScreenOff() = 0;

    // Undoes TurnScreenOff().
    virtual void TurnScreenOn() = 0;

    // Requests that the screen be locked.
    virtual void LockScreen() = 0;

    // Suspends the system.
    virtual void Suspend(ActionReason reason) = 0;

    // Stops the current session, logging the currently-logged-in user out.
    virtual void StopSession() = 0;

    // Shuts the system down.
    virtual void ShutDown() = 0;

    // Reports metrics in response to user activity.
    virtual void ReportUserActivityMetrics() = 0;

    // Reports metrics when a dim/undim happens.
    virtual void ReportDimEventMetrics(metrics::DimEvent sample) = 0;

    // Reports metrics when a quick/standard lock happens.
    virtual void ReportLockEventMetrics(metrics::LockEvent sample) = 0;

    // Reports duration metrics when a dim/undim happens.
    virtual void ReportHpsEventDurationMetrics(const std::string& event_name,
                                               base::TimeDelta duration) = 0;
  };

  class TestApi {
   public:
    explicit TestApi(StateController* controller);
    TestApi(const TestApi&) = delete;
    TestApi& operator=(const TestApi&) = delete;

    ~TestApi();

    Clock* clock() { return controller_->clock_.get(); }
    base::TimeTicks action_timer_time() const {
      return controller_->action_timer_time_for_testing_;
    }

    // Runs StateController::HandleActionTimeout(). May only be called if the
    // timer is running.
    void TriggerActionTimeout();

    // Runs StateController::HandleInitialStateTimeout(). Returns false if the
    // timer wasn't running.
    [[nodiscard]] bool TriggerInitialStateTimeout();

    // Runs StateController::HandleWaitForExternalDisplayTimeout(). Returns
    // false if the timer wasn't running.
    [[nodiscard]] bool TriggerWaitForExternalDisplayTimeout();

    // Runs StateController::HandleCrashBootCollectTimeout(). Returns
    // false if the timer wasn't running.
    bool TriggerHandleCrashBootCollectTimeout();

   private:
    StateController* controller_;  // weak
  };

  // Delays are lengthened if user activity is observed while the screen is
  // dimmed or within this interval of the screen being turned off.
  static constexpr base::TimeDelta
      kUserActivityAfterScreenOffIncreaseDelaysInterval = base::Seconds(60);

  // Ignore display mode changes within this interval after the screen is turned
  // off. These changes are assumed to be hotplug jitter/spam from poorly
  // implemented display hardware.
  static constexpr base::TimeDelta kIgnoreDisplayModeAfterScreenOffInterval =
      base::Seconds(30);

  // Time before the screen is dimmed when a ScreenDimImminent D-Bus signal
  // should be emitted.
  static constexpr base::TimeDelta kScreenDimImminentInterval =
      base::Seconds(5);

  // Besides put a limit on how many times we defer the dimming with hps, we
  // also want to add this time limit so that no defer will happen 15 minutes
  // after the user activity.
  static constexpr base::TimeDelta kDeferDimmingTimeLimit = base::Minutes(15);

  // Returns a string describing |policy|.
  static std::string GetPolicyDebugString(const PowerManagementPolicy& policy);

  StateController();
  StateController(const StateController&) = delete;
  StateController& operator=(const StateController&) = delete;

  ~StateController() override;

  base::TimeTicks last_user_activity_time() const {
    return last_user_activity_time_;
  }

  // Is the system currently in "docked mode", where it remains awake while
  // the lid is closed because an external display is connected?
  bool in_docked_mode() {
    return display_mode_ == DisplayMode::PRESENTATION &&
           lid_state_ == LidState::CLOSED;
  }

  // Ownership of |delegate|, |dbus_wrapper|, and |prefs| remains with the
  // caller.
  void Init(Delegate* delegate,
            PrefsInterface* prefs,
            system::DBusWrapperInterface* dbus_wrapper,
            PowerSource power_source,
            LidState lid_state);

  // Handles various changes to external state.
  void HandlePowerSourceChange(PowerSource source);
  void HandleLidStateChange(LidState state);
  void HandleTabletModeChange(TabletMode mode);
  void HandleSessionStateChange(SessionState state);
  void HandleDisplayModeChange(DisplayMode mode);
  // Handles Resume. |State| is the latest lid state after resume.
  void HandleResume(LidState state);
  void HandlePolicyChange(const PowerManagementPolicy& policy);

  // Handles notification of different types of activity.
  void HandleUserActivity();
  void HandleVideoActivity();
  void HandleWakeNotification();

  // Handles audio activity starting or stopping.
  void HandleAudioStateChange(bool active);

  // Handles updates to the TPM status.
  void HandleTpmStatus(int dictionary_attack_count);

  // Called when dim_advisor_.HandleSmartDimResponse returns
  // "Should defer". Virtual for mocking.
  virtual void HandleDeferFromSmartDim();

  // Called when a new hps_result is sent from Hps DBus.
  // Virtual for mocking.
  virtual void HandleHpsResultChange(hps::HpsResult hps_result);

  // PrefsInterface::Observer implementation:
  void OnPrefChanged(const std::string& pref_name) override;

  // Whether to request a dim defer suggestion from either MLDecisionService or
  // HPS.
  bool ShouldRequestDimDeferSuggestion(base::TimeTicks now);

 private:
  // Holds a collection of delays. Unset delays take the zero value.
  struct Delays {
    base::TimeDelta idle;
    base::TimeDelta idle_warning;
    base::TimeDelta screen_off;
    base::TimeDelta screen_dim;
    base::TimeDelta screen_dim_imminent;
    base::TimeDelta screen_lock;
    base::TimeDelta quick_dim;
    base::TimeDelta quick_lock;
    bool operator!=(const Delays& o) const;
  };

  // Tracks the state of an activity that starts and stops.
  class ActivityInfo;

  // These correspond to the identically-named values in the
  // PowerManagementPolicy_Action enum.
  enum class Action {
    SUSPEND,
    STOP_SESSION,
    SHUT_DOWN,
    DO_NOTHING,
  };

  static std::string ActionToString(Action action);

  // Converts an Action enum value from a PowerManagementPolicy protocol buffer
  // to the corresponding StateController::Action value.
  static Action ProtoActionToAction(PowerManagementPolicy_Action proto_action);

  // Current status of update_engine, the system updater.
  enum class UpdaterState {
    // No update is currently being applied.
    IDLE,
    // An update is being downloaded, verified, or applied.
    UPDATING,
    // An update has been successfully applied and will be used after a reboot.
    UPDATED,
  };

  // Scales the |screen_dim| delay within |delays| by
  // |screen_dim_scale_factor| and lengthens the other delays to maintain
  // their original distances from the screen-dim delay. Does nothing if
  // |screen_dim_scale_factor| is less than or equal to one or if the
  // dimming delay is unset.
  static void ScaleDelays(Delays* delays, double screen_dim_scale_factor);

  // Adjusts values in |delays| to ensure they make sense.
  static void SanitizeDelays(Delays* delays);

  // Merges set fields from |policy_delays| into |delays_out|, which should
  // already be initialized with default settings.
  static void MergeDelaysFromPolicy(
      const PowerManagementPolicy::Delays& policy_delays, Delays* delays_out);

  // Calculates whether the screen has turned off in the last
  // |recently_off_threshold|
  bool IsScreenTurnedOffRecently(base::TimeDelta recently_off_threshold);

  // Is StateController currently waiting for the display mode and policy to be
  // received for the first time after Init() was called?
  bool WaitingForInitialState() const;

  // Is Statecontroller waiting for external display on resuming with lid
  // still closed. Used to defer idle and suspend action until the timer
  // expires.
  bool WaitingForExternalDisplay() const;

  // Is StateController waiting for crash-reporter per boot crash collection.
  // Used to defer lid closed action until the timer expires.
  bool WaitingForCrashBootCollect() const;

  // Should inactivity-triggered actions be deferred due to StateController
  // waiting for user activity to be seen during the current session?
  bool WaitingForInitialUserActivity() const;

  // Stops |initial_state_timer_| if |got_initial_display_mode_| and
  // |got_initial_policy_| are both true.
  void MaybeStopInitialStateTimer();

  // Stops |wait_for_external_display_timer_|.
  void StopWaitForExternalDisplayTimer();

  // Stops |wait_for_crash_boot_collect_timer_| if
  // |kCrashBootCollectorDoneFile| exists.
  void MaybeStopWaitForCrashBootCollectTimer(const base::FilePath& path,
                                             bool error);

  // Returns true if the idle, screen-dim, screen-lock, or screen-off actions
  // are currently blocked and can't occur until something changes via a call to
  // UpdateState().
  bool IsIdleBlocked() const;
  bool IsScreenDimBlocked() const;
  bool IsScreenOffBlocked() const;
  bool IsScreenLockBlocked() const;

  // Returns the last time at which activity occurred that should defer
  // |idle_action_|, taking |on_ac_|, |use_audio_activity_|,
  // |use_video_activity_|, and |*_wake_lock_| into account.
  base::TimeTicks GetLastActivityTimeForIdle(base::TimeTicks now) const;

  // Returns the last time at which activity occurred that should defer a screen
  // timeout.
  base::TimeTicks GetLastActivityTimeForScreenDim(base::TimeTicks now) const;
  base::TimeTicks GetLastActivityTimeForScreenDimWithoutDefer(
      base::TimeTicks now) const;
  base::TimeTicks GetLastActivityTimeForQuickDim(base::TimeTicks now) const;
  base::TimeTicks GetLastActivityTimeForScreenOff(base::TimeTicks now) const;
  base::TimeTicks GetLastActivityTimeForScreenLock(base::TimeTicks now) const;
  base::TimeTicks GetLastActivityTimeForQuickLock(base::TimeTicks now) const;

  // Updates |last_user_activity_time_| to contain the current time and
  // calls |delegate_|'s ReportUserActivityMetrics() method.
  void UpdateLastUserActivityTime();

  // Initializes |require_usb_input_device_to_suspend_|, |pref_*|, and other
  // pref-derived members from |prefs_|.
  // TODO(chromeos-power): Add a |reload| argument. Most prefs should only be
  // read once at startup; ignore runtime changes to anything not checked in
  // OnPrefChanged().
  void LoadPrefs();

  // Updates in-use settings and calls UpdateState().  Copies values from
  // |pref_*| and then applies externally-provided settings from |policy_|.
  void UpdateSettingsAndState();

  // Logs the current settings (as updated by UpdateSettingsAndState()) to aid
  // in debugging.
  void LogSettings();

  // Instructs |delegate_| to perform |action| for |reason|.
  void PerformAction(Action action, ActionReason reason);

  // Helper function to UpdateState(). Returns idle action to be performed based
  // on user preferences and several other external factors.
  Action GetIdleAction() const;

  // Ensures that the system is in the correct state, given the times at which
  // activity was last seen, the lid state, the currently-set delays, etc.
  // Invokes ScheduleActionTimeout() when done. If something that affects the
  // current settings has changed, UpdateSettingsAndState() should be called
  // instead.
  void UpdateState();

  // Stops |action_timer_| and resets it to fire when action is next needed,
  // given a current time of |now|.
  void ScheduleActionTimeout(base::TimeTicks now);

  // Invoked by |action_timer_| when it's time to perform an action.
  void HandleActionTimeout();

  // Invoked by |initial_state_timer_| if the current display mode and policy
  // weren't received in a reasonable amount of time after Init() was called.
  void HandleInitialStateTimeout();

  // Invoked by |wait_for_crash_boot_collect_timer_| if
  // |kCrashBootCollectorDoneFile| is not created after
  // |kCrashBootCollectTimeout| after resuming.
  void HandleCrashBootCollectTimeout();

  // Invoked by |wait_for_external_display_timer_| if display mode change is not
  // received in |KResuspendOnClosedLidTimeout| after resuming with lid still
  // closed.
  void HandleWaitForExternalDisplayTimeout();

  // Constructs a protocol message containing the currently-active inactivity
  // delays.
  PowerManagementPolicy::Delays CreateInactivityDelaysProto() const;

  // Handles various D-Bus method calls.
  void HandleGetInactivityDelaysMethodCall(
      dbus::MethodCall* method_call,
      dbus::ExportedObject::ResponseSender response_sender);

  // Handles the update_engine D-Bus service becoming initially available.
  void HandleUpdateEngineAvailable(bool available);

  // Handles StatusUpdateAdvanced D-Bus signals from update_engine.
  void HandleUpdateEngineStatusUpdateSignal(dbus::Signal* signal);

  // Handles status updates from update_engine. This is a helper used by both
  // HandleUpdateEngineStatusUpdateSignal() and HandleUpdateEngineAvailable(),
  // and |message| can be either a StatusUpdateAdvanced D-Bus signal or the
  // response to a GetStatusAdvanced D-Bus method call; both have the same
  // arguments.
  void HandleUpdateEngineStatusMessage(dbus::Message* message);

  // Announces that the screen's dimmed- or off-for-inactivity state has
  // changed.
  void EmitScreenIdleStateChanged(bool dimmed, bool off);

  // This is an expansion of `HandleDelay` that serves screen dim/undim only.
  // When the screen is on and conditions of quick dim or standard dim are
  // satisfied, dim the screen.
  // When the screen is dimmed and Hps sense is positive or user activity
  // happens, undim the screen.
  void HandleDimWithHps(base::TimeTicks now,
                        base::TimeDelta screen_dim_duration);

  // This is an expansion of `HandleDelay` that serves screen lock only.
  // When conditions of quick lock or standard lock are satisfied, lock the
  // screen.
  void HandleScreenLockWithHps(base::TimeTicks now,
                               base::TimeDelta screen_lock_duration);

  Delegate* delegate_ = nullptr;                          // not owned
  PrefsInterface* prefs_ = nullptr;                       // not owned
  system::DBusWrapperInterface* dbus_wrapper_ = nullptr;  // not owned

  // Owned by |dbus_wrapper_|.
  dbus::ObjectProxy* update_engine_dbus_proxy_ = nullptr;

  std::unique_ptr<Clock> clock_;

  // Has Init() been called?
  bool initialized_ = false;

  // Have initial values for |display_mode_| and |policy_| been received? The
  // lid-closed action is deferred while waiting for the initial state.
  bool got_initial_display_mode_ = false;
  bool got_initial_policy_ = false;

  // Runs HandleActionTimeout().
  base::OneShotTimer action_timer_;

  // Runs HandleInitialStateTimeout().
  base::OneShotTimer initial_state_timer_;

  // Runs HandleWaitForExternalDisplayTimeout().
  base::OneShotTimer wait_for_external_display_timer_;

  // Runs HandleCrashBootCollectTimeout().
  base::OneShotTimer wait_for_crash_boot_collect_timer_;

  // Time at which |action_timer_| has been scheduled to fire.
  base::TimeTicks action_timer_time_for_testing_;

  // Current power source.
  PowerSource power_source_ = PowerSource::AC;

  // Current state of the lid.
  LidState lid_state_ = LidState::NOT_PRESENT;

  // Current user session state.
  SessionState session_state_ = SessionState::STOPPED;

  // Current system update state.
  UpdaterState updater_state_ = UpdaterState::IDLE;

  // Whether the system is presenting or not.
  DisplayMode display_mode_ = DisplayMode::NORMAL;

  // These track whether various actions have already been performed by
  // UpdateState().
  bool screen_dimmed_ = false;
  bool screen_turned_off_ = false;
  bool requested_screen_lock_ = false;
  bool sent_idle_warning_ = false;
  bool idle_action_performed_ = false;
  bool lid_closed_action_performed_ = false;

  // Set to true by UpdateSettingsAndState() if UpdateState() should send
  // another warning if the delay has elapsed, even if |sent_idle_warning_| is
  // true. Warnings contain the remaining time until the idle action will be
  // performed, so they are re-sent when this interval is likely to have
  // changed.
  bool resend_idle_warning_ = false;

  // Time at which the screen was turned off, or null if
  // |screen_turned_off_| is false.  Used for updating
  // |saw_user_activity_soon_after_screen_dim_or_off_|.
  base::TimeTicks screen_turned_off_time_;

  // Time of the last screen dim if screen is dimmed; it is set to be
  // base::TimeTicks() if screen is not currently dimmed.
  base::TimeTicks last_dim_time_;

  // Time of the last screen lock request; it is set to be base::TimeTicks()
  // when `requested_screen_lock_` is false.
  base::TimeTicks last_lock_requested_time_;

  // True if user activity was observed after the screen was dimmed or soon
  // after it was turned off (which can result in delays being lengthened
  // to not annoy the user the next time).  Reset when the session state
  // changes.
  bool saw_user_activity_soon_after_screen_dim_or_off_ = false;

  // True if user activity has been observed during the current session.
  bool saw_user_activity_during_current_session_ = false;

  // Should the system only idle-suspend if a USB input device is
  // connected?  This is controlled by the
  // |kRequireUsbInputDeviceToSuspendPref| pref and set on hardware that
  // doesn't wake in response to Bluetooth input devices.
  bool require_usb_input_device_to_suspend_ = false;

  // Should the system avoid suspending when something is plugged in to the
  // headphone jack? This is controlled by the
  // |kAvoidSuspendWhenHeadphoneJackPluggedPref| pref and set for hardware that
  // generates noise on the headphone jack when suspended.
  bool avoid_suspend_when_headphone_jack_plugged_ = false;

  // Should the system be prevented from suspending in response to
  // inactivity?  This is controlled by the |kDisableIdleSuspendPref| pref
  // and overrides |policy_|.
  bool disable_idle_suspend_ = false;

  // Whether to send feedback to `dim_advisor_` to possibly disable it if a
  // quick dim is undone by hps or by a user activity. This is controlled by the
  // |kSendFeedbackIfUndimmedPref| pref and gets overridden by |policy_|.
  bool send_feedback_if_undimmed_ = false;

  // Is the device using a factory image? This is controlled by the
  // |kFactoryModePref| pref and overrides |policy_|.
  bool factory_mode_ = false;

  // Should |policy_| be ignored?  Used by tests and developers.
  bool ignore_external_policy_ = false;

  // TPM dictionary-attack counter value.
  int tpm_dictionary_attack_count_ = 0;

  // |tpm_dictionary_attack_count_| value at or above which the system will
  // suspend instead of shutting down in some cases (see
  // http://crbug.com/462428), or 0 if disabled.
  int tpm_dictionary_attack_suspend_threshold_ = 0;

  // Amount of time (in seconds) to wait for external displays when a display
  // mode change occurs and the lid is closed.
  int defer_external_display_timeout_s_ = 0;

  // Time of the last report of user activity, video activity or wake
  // notification.
  base::TimeTicks last_user_activity_time_;
  base::TimeTicks last_video_activity_time_;
  base::TimeTicks last_wake_notification_time_;

  // Time of the last deferring screen dim.
  base::TimeTicks last_defer_screen_dim_time_;
  // Timestamp of the last time hps result changed.
  base::TimeTicks last_hps_result_change_time_;
  // HpsResult recorded. Use of this API is restricted by policy. Consult
  // go/cros-pdd#bookmark=id.7emuxnhxv638 and Chrome OS Privacy before
  // using.
  hps::HpsResult hps_result_ = hps::HpsResult::UNKNOWN;
  // This records how much earlier a quick dim is compared to a standard dim.
  // Used for estimating the effectiveness of a quick dim.
  base::TimeDelta quick_dim_ahead_;

  // Information about audio activity and full-brightness, screen-on-but-dimmed,
  // and system-level wake locks.
  std::unique_ptr<ActivityInfo> audio_activity_;
  std::unique_ptr<ActivityInfo> screen_wake_lock_;
  std::unique_ptr<ActivityInfo> dim_wake_lock_;
  std::unique_ptr<ActivityInfo> system_wake_lock_;

  // Most recent externally-supplied policy.
  PowerManagementPolicy policy_;

  // Current settings (|pref_*| with |policy_| layered on top).
  Action idle_action_ = Action::DO_NOTHING;
  Action lid_closed_action_ = Action::DO_NOTHING;
  Delays delays_;
  bool use_audio_activity_ = true;
  bool use_video_activity_ = true;
  bool wait_for_initial_user_activity_ = false;

  // Default settings loaded from prefs.
  Delays pref_ac_delays_;
  Delays pref_battery_delays_;

  // Human-readable explanation for why the idle action was ignored. This is set
  // by UpdateSettingsAndState() and logged by UpdateState() when the action
  // would actually be performed.
  std::string reason_for_ignoring_idle_action_;

  // Periodically logs active wake locks to aid in debugging.
  // HandlePolicyChange() logs changes to the wake lock state, but it can be
  // hard find and interpret these messages when the last policy change happened
  // long ago.
  OngoingStateActivityLogger wake_lock_logger_;

  // Watcher to monitor the presence of |kCrashBootCollectorDoneFile|.
  // Presence of this file indicates successful collection of per-boot crash
  // collection.
  base::FilePathWatcher crash_boot_collector_watcher_;

  // Class that decides whether to defer the imminent screen dimming via dbus
  // method call to kMlDecisionServiceInterface.
  DimAdvisor dim_advisor_;

  base::WeakPtrFactory<StateController> weak_ptr_factory_;
};

}  // namespace policy
}  // namespace power_manager

#endif  // POWER_MANAGER_POWERD_POLICY_STATE_CONTROLLER_H_
