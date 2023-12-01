// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef POWER_MANAGER_POWERD_POLICY_SUSPENDER_H_
#define POWER_MANAGER_POWERD_POLICY_SUSPENDER_H_

#include <stdint.h>

#include <memory>
#include <optional>
#include <queue>
#include <string>
#include <utility>
#include <vector>

#include <base/compiler_specific.h>
#include <base/memory/weak_ptr.h>
#include <base/time/time.h>
#include <base/timer/timer.h>
#include <dbus/exported_object.h>
#include <dbus/message.h>

#include "power_manager/common/power_constants.h"
#include "power_manager/powerd/policy/adaptive_charging_controller.h"
#include "power_manager/powerd/policy/suspend_delay_observer.h"
#include "power_manager/powerd/system/display/display_watcher_observer.h"
#include "power_manager/powerd/system/suspend_configurator.h"
#include "power_manager/proto_bindings/suspend.pb.h"

namespace power_manager {

class Clock;
class PrefsInterface;

namespace system {
class DarkResumeInterface;
class DBusWrapperInterface;
class DisplayWatcherInterface;
class InputWatcher;
class WakeupSourceIdentifierInterface;
}  // namespace system

namespace policy {

class ShutdownFromSuspendInterface;
class SuspendDelayController;

// Suspender is responsible for suspending the system.
//
// First, some terminology:
//
// - A "suspend request" refers to a request (either generated within powerd or
//   originating from another process) for powerd to suspend the system. The
//   request is complete after the system resumes successfully or the request is
//   canceled (e.g. by user activity).
//
// - A "suspend attempt" refers to a single attempt by powerd to suspend the
//   system by writing to /sys/power/state.
//
// A suspend request may result in multiple attempts: An attempt may fail and be
// retried after a brief delay, or the system may do a "dark resume" (i.e. wake
// without turning the display on), check the battery level, and then resuspend
// immediately.
//
// The typical flow in the simple case is as follows:
//
// - RequestSuspend() is called when suspending is desired.
// - StartRequest() does pre-suspend preparation and emits a SuspendImminent
//   signal to announce the new suspend request to processes that have
//   previously registered suspend delays via RegisterSuspendDelay().
// - OnReadyForSuspend() is called to announce that all processes have announced
//   readiness via HandleSuspendReadiness().
// - Suspend() runs the powerd_suspend script to perform a suspend attempt.
// - After powerd_suspend returns successfully, FinishRequest() undoes the
//   pre-suspend preparation and emits a SuspendDone signal.
// - If powerd_suspend reported failure, a timer is started to retry the suspend
//   attempt.
//
// At any point before Suspend() has been called, user activity can cancel the
// current suspend attempt.
class Suspender : public SuspendDelayObserver,
                  public system::DisplayWatcherObserver {
 public:
  // Information about dark resumes used for histograms.
  // First value is wake reason; second is wake duration.
  using DarkResumeInfo = std::pair<std::string, base::TimeDelta>;

  // Interface for classes responsible for performing actions on behalf of
  // Suspender.  The general sequence when suspending is:
  //
  // - Suspender::StartRequest() calls PrepareToSuspend() and then notifies
  //   other processes that the system is about to suspend.
  // - Suspender::Suspend() calls DoSuspend() to actually suspend the system.
  //   This may occur multiple times if the attempt fails and is retried or if
  //   the system wakes for dark resume and then resuspends.
  // - After the suspend request is complete, Suspender::FinishRequest()
  //   calls UndoPrepareToSuspend().
  class Delegate {
   public:
    // Outcomes for a suspend attempt.
    enum class SuspendResult {
      // The system successfully suspended and resumed.
      SUCCESS = 0,
      // The kernel reported a (possibly transient) error while suspending.
      FAILURE,
      // The suspend attempt was canceled as a result of a wakeup event.
      CANCELED,
    };

    virtual ~Delegate() = default;

    // Returns a initial value for suspend-related IDs that's likely (but not
    // guaranteed) to yield successive IDs that are unique across all of the
    // powerd runs during the current boot session.
    virtual int GetInitialSuspendId() = 0;

    // Returns an initial value for the dark suspend IDs that's likely (but not
    // guaranteed) to yield successive IDs that are unique across all of the
    // powerd runs during the current boot session.  Additionally, successive
    // IDs generated from this value should not collide with successive IDs
    // generated from the value returned by GetInitialSuspendId().
    virtual int GetInitialDarkSuspendId() = 0;

    // Is the lid currently closed?  Returns false if the query fails or if
    // the system doesn't have a lid.
    virtual bool IsLidClosedForSuspend() = 0;

    // Reads the current wakeup count from sysfs and stores it in
    // |wakeup_count|. Returns true on success.
    virtual bool ReadSuspendWakeupCount(uint64_t* wakeup_count) = 0;

    // Sets state that persists across powerd restarts but not across system
    // reboots to track whether a suspend requests's commencement was announced
    // (the SuspendImminent signal was emitted) but its completion wasn't (the
    // SuspendDone signal wasn't emitted).
    virtual void SetSuspendAnnounced(bool announced) = 0;

    // Gets the state previously set via SetSuspendAnnounced().
    virtual bool GetSuspendAnnounced() = 0;

    // Performs any work that needs to happen before other processes are
    // informed that the system is about to suspend, including turning off the
    // backlight. Called by StartRequest().
    virtual void PrepareToSuspend() = 0;

    // Suspend audio: it needs to happen after other processes have announced
    // suspend readiness. It can't be done earlier since VMs using virtio-snd
    // requires active CRAS to properly suspend themselves. Called by Suspend().
    virtual void SuspendAudio() = 0;

    // Undoes SuspendAudio
    virtual void ResumeAudio() = 0;

    // Synchronously runs the powerd_suspend script to suspend the system for
    // |duration|. If |wakeup_count_valid| is true, passes |wakeup_count| to the
    // script so it can avoid suspending if additional wakeup events occur.
    // Called by Suspend().
    virtual SuspendResult DoSuspend(uint64_t wakeup_count,
                                    bool wakeup_count_valid,
                                    base::TimeDelta duration,
                                    bool to_hibernate) = 0;

    // Undoes the preparations performed by PrepareToSuspend(). Called by
    // FinishRequest().
    virtual void UndoPrepareToSuspend(bool success,
                                      int num_suspend_attempts,
                                      bool hibernated) = 0;

    // Generates and reports metrics for wakeups in dark resume.
    virtual void GenerateDarkResumeMetrics(
        const std::vector<DarkResumeInfo>& dark_resume_wake_durations,
        base::TimeDelta suspend_duration_) = 0;

    // Shuts the system down in response to repeated failed suspend attempts.
    virtual void ShutDownForFailedSuspend(bool hibernate) = 0;

    // Shuts the system down in response to the ShutdownFromSuspend determining
    // the system should shut down.
    virtual void ShutDownFromSuspend() = 0;

    // Apply system quirks before attempting to suspend. Quirks should focus on
    // workarounds for devices that don't behave correctly because of how they
    // handle wakeup_events.
    virtual void ApplyQuirksBeforeSuspend() = 0;

    // Unapply system quirks after suspend.
    virtual void UnapplyQuirksAfterSuspend() = 0;
  };

  // Helper class providing functionality needed by tests.
  class TestApi {
   public:
    explicit TestApi(Suspender* suspender);
    TestApi(const TestApi&) = delete;
    TestApi& operator=(const TestApi&) = delete;

    int suspend_id() const { return suspender_->suspend_request_id_; }
    int dark_suspend_id() const { return suspender_->dark_suspend_id_; }

    Clock* clock() const { return suspender_->clock_.get(); }
    SuspendDelayController* suspend_delay_controller() const {
      return suspender_->suspend_delay_controller_.get();
    }
    SuspendDelayController* dark_suspend_delay_controller() const {
      return suspender_->dark_suspend_delay_controller_.get();
    }

    // Runs Suspender::HandleEvent(EVENT_READY_TO_RESUSPEND) if
    // |resuspend_timer_| is running. Returns false otherwise.
    bool TriggerResuspendTimeout();

    void set_last_dark_resume_wake_reason(const std::string& wake_reason) {
      suspender_->last_dark_resume_wake_reason_ = wake_reason;
    }

    std::string GetDefaultWakeReason() const;

   private:
    Suspender* suspender_;  // weak
  };

  Suspender();
  Suspender(const Suspender&) = delete;
  Suspender& operator=(const Suspender&) = delete;

  ~Suspender() override;

  void Init(Delegate* delegate,
            system::DBusWrapperInterface* dbus_wrapper,
            system::DarkResumeInterface* dark_resume,
            system::DisplayWatcherInterface* display_watcher,
            system::WakeupSourceIdentifierInterface* wakeup_source_identifier,
            policy::ShutdownFromSuspendInterface* shutdown_from_suspend,
            AdaptiveChargingControllerInterface* adaptive_charging_controller,
            PrefsInterface* prefs,
            system::SuspendConfiguratorInterface* suspend_configurator);

  // Starts the suspend process. Note that suspending happens
  // asynchronously. The system will automatically resume after |duration| if it
  // is non-zero.
  void RequestSuspend(SuspendImminent::Reason reason,
                      base::TimeDelta duration,
                      SuspendFlavor flavor);

  // Like RequestSuspend(), but aborts the suspend attempt immediately if
  // the current wakeup count reported by the kernel exceeds
  // |wakeup_count|. Autotests can pass an external wakeup count to ensure
  // that machines in the test cluster don't sleep indefinitely (see
  // http://crbug.com/218175).
  // TODO(chromeos-power): Delete this and add a std::optional<uint64_t> arg to
  // RequestSuspend.
  void RequestSuspendWithExternalWakeupCount(SuspendImminent::Reason reason,
                                             uint64_t wakeup_count,
                                             base::TimeDelta duration,
                                             SuspendFlavor flavor);

  // Aborts an imminent resume from hibernation.
  void AbortResumeFromHibernate();

  // Handles events that may abort in-progress suspend attempts.
  void HandleLidOpened();
  void HandleUserActivity();
  void HandleWakeNotification();
  void HandleShutdown();
  void HandleDisplayModeChange(DisplayMode mode);

  // Handles the D-Bus name |name| becoming owned by |new_owner| instead of
  // |old_owner|.
  void HandleDBusNameOwnerChanged(const std::string& name,
                                  const std::string& old_owner,
                                  const std::string& new_owner);

  // SuspendDelayObserver override:
  void OnReadyForSuspend(SuspendDelayController* controller,
                         int suspend_id) override;

  // DisplayWatcherObserver implementation
  void OnDisplaysChanged(
      const std::vector<system::DisplayInfo>& displays) override;

 private:
  // States that Suspender can be in while the event loop is running.
  enum class State {
    // Nothing suspend-related is going on. The device isn't in dark resume in
    // this state i.e. |dark_resume_->InDarkResume| has to be false.
    IDLE = 0,
    // powerd has announced a new suspend request to other processes and is
    // waiting for clients that have registered suspend delays to report
    // readiness.
    WAITING_FOR_NORMAL_SUSPEND_DELAYS,
    // powerd is waiting to resuspend after waking into a dark resume.
    WAITING_FOR_DARK_SUSPEND_DELAYS,
    // powerd is waiting to resuspend after a failed suspend attempt from normal
    // or dark resume i.e.|dark_resume_->InDarkResume()| can be true in this
    // state.
    WAITING_TO_RETRY_SUSPEND,
    // The system is shutting down. Suspend requests are ignored.
    SHUTTING_DOWN,
    // The system is braced for an imminent hibernate resume, which if
    // successful transfers execution to an entirely new world.
    RESUMING_FROM_HIBERNATE,
  };

  enum class Event {
    // A suspend request was received.
    SUSPEND_REQUESTED = 0,
    // Clients that have registered suspend delays have all reported readiness
    // (or timed out).
    SUSPEND_DELAYS_READY,
    // User activity was reported.
    USER_ACTIVITY,
    // The system is ready to resuspend (after either a failed suspend attempt
    // or a dark resume).
    READY_TO_RESUSPEND,
    // The system is shutting down.
    SHUTDOWN_STARTED,
    // A notification was created or updated.
    WAKE_NOTIFICATION,
    // Display mode change was reported.
    DISPLAY_MODE_CHANGE,
    // New display observed by powerd.
    NEW_DISPLAY,
    // A request aborting resume from hibernation was received.
    ABORT_RESUME_FROM_HIBERNATE,
  };

  // Converts |event| to a string.
  static std::string EventToString(Event event);

  // Called by Init() to export suspend-related D-Bus methods on
  // |dbus_wrapper_|.
  void ExportDBusMethods();

  // D-Bus method handlers.
  void RegisterSuspendDelay(
      SuspendDelayController* controller,
      dbus::MethodCall* method_call,
      dbus::ExportedObject::ResponseSender response_sender);
  void UnregisterSuspendDelay(
      SuspendDelayController* controller,
      dbus::MethodCall* method_call,
      dbus::ExportedObject::ResponseSender response_sender);
  void HandleSuspendReadiness(
      SuspendDelayController* controller,
      dbus::MethodCall* method_call,
      dbus::ExportedObject::ResponseSender response_sender);
  void RecordDarkResumeWakeReason(
      dbus::MethodCall* method_call,
      dbus::ExportedObject::ResponseSender response_sender);

  // Performs actions and updates |state_| in response to |event|.
  void HandleEvent(Event event);

  // Helper method called by HandleEvent when in State::SUSPEND_DELAYS_NORMAL.
  void HandleEventInWaitingForNormalSuspendDelays(Event event);

  // Helper method called by HandleEvent when in
  // State::WAITING_FOR_DARK_SUSPEND_DELAYS or State::WAITING_TO_RETRY_SUSPEND.
  void HandleEventInDarkResumeOrRetrySuspend(Event event);

  // Called by HandleEventInWaitingForNormalSuspendDelays or
  // HandleEventInDarkResumeOrRetrySuspend to handle Event::USER_ACTIVITY or
  // Event::WAKE_NOTIFICATION. Returns new value for |state_|.
  State HandleWakeEventInSuspend(Event event);

  // Helper method called by HandleEvent when in
  // State::RESUMING_FROM_HIBERNATE.
  void HandleEventInResumingFromHibernate(Event event);

  // Starts a new suspend request, notifying clients that have registered delays
  // that the system is about to suspend.
  void StartRequest();

  // Completes the current suspend request, undoing any work performed by
  // StartRequest().
  void FinishRequest(bool success,
                     SuspendDone::WakeupType wakeup_type,
                     bool hibernated);

  // Actually performs a suspend attempt and waits for the system to resume,
  // returning a new value for |state_|.
  State Suspend();

  // Helper methods called by Suspend() to handle various suspend results.
  State HandleNormalResume(Delegate::SuspendResult result, bool from_hibernate);
  State HandleDarkResume(Delegate::SuspendResult result);

  // Helper method called by HandleNormalResume() or HandleDarkResume() in
  // response to a failed or canceled suspend or hibernation attempt.
  State HandleUnsuccessfulSuspend(Delegate::SuspendResult result,
                                  bool hibernate);

  // Starts |resuspend_timer_| to send EVENT_READY_TO_RESUSPEND after |delay|.
  void ScheduleResuspend(const base::TimeDelta& delay);

  // Emits D-Bus signal announcing the end of a suspend request.
  void EmitSuspendDoneSignal(int suspend_request_id,
                             const base::TimeDelta& suspend_duration,
                             SuspendDone::WakeupType wakeup_type,
                             bool hibernated);

  // Emits a D-Bus signal announcing that the system will soon resuspend from
  // dark resume. |dark_resume_id_| is used as the request ID.
  void EmitDarkSuspendImminentSignal();

  // Emits a D-Bus signal indicating that suspend callbacks have been processed
  // and the system is fully ready to resume from hibernation.
  void EmitHibernateResumeReadySignal(int suspend_request_id);

  Delegate* delegate_ = nullptr;                          // weak
  system::DBusWrapperInterface* dbus_wrapper_ = nullptr;  // weak
  system::DarkResumeInterface* dark_resume_ = nullptr;    // weak
  system::WakeupSourceIdentifierInterface* wakeup_source_identifier_ =
      nullptr;  // weak
  policy::ShutdownFromSuspendInterface* shutdown_from_suspend_ =
      nullptr;  // weak
  AdaptiveChargingControllerInterface* adaptive_charging_controller_ =
      nullptr;  // weak

  PrefsInterface* prefs_ = nullptr;  // weak
  std::unique_ptr<Clock> clock_;
  std::unique_ptr<SuspendDelayController> suspend_delay_controller_;
  std::unique_ptr<SuspendDelayController> dark_suspend_delay_controller_;

  // Current state of the object, updated just before returning control to the
  // event loop.
  State state_ = State::IDLE;

  // True if HandleEvent() is currently handling an event.
  bool handling_event_ = false;

  // True if HandleEvent() is currently processing |queued_events_|.
  bool processing_queued_events_ = false;

  // Unhandled events that were received while |handling_event_| was true.
  std::queue<Event> queued_events_;

  // Unique ID associated with the current suspend request.
  int suspend_request_id_ = 0;

  // Unique ID associated with the current dark suspend request.
  int dark_suspend_id_ = 0;

  // The reason that was supplied for the current suspend request.
  SuspendImminent::Reason suspend_request_reason_ =
      SuspendImminent_Reason_OTHER;

  // An optional wakeup count supplied via
  // RequestSuspendWithExternalWakeupCount().
  bool suspend_request_supplied_wakeup_count_ = false;
  uint64_t suspend_request_wakeup_count_ = 0;
  base::TimeDelta suspend_duration_;

  // Number of wakeup events received at the start of the current suspend
  // attempt. Passed to the kernel to cancel an attempt if user activity is
  // received while powerd's event loop isn't running.
  uint64_t wakeup_count_ = 0;
  bool wakeup_count_valid_ = false;

  // The type of suspend requested.
  SuspendFlavor suspend_request_flavor_ = SuspendFlavor::SUSPEND_DEFAULT;

  // Boot time at which the suspend request started.
  base::TimeTicks suspend_request_start_time_;

  // Time to wait before retrying a failed suspend attempt.
  base::TimeDelta retry_delay_;

  // Maximum number of times to retry after a failed suspend attempt before
  // giving up and shutting down the system.
  int64_t max_retries_ = 0;

  // Number of suspend attempts made in the current series. Up to |max_retries_|
  // additional attempts are made after a failure, but this counter is reset
  // after waking into dark resume.
  int current_num_attempts_ = 0;

  // Number of suspend attempts made in the first series after the
  // RequestSuspend() call. |current_num_attempts_| is copied here when doing a
  // dark resume.
  int initial_num_attempts_ = 0;

  // The boot time at which the system entered dark resume. Set by
  // HandleDarkResume() when it sees a successful dark resume.
  base::TimeTicks dark_resume_start_time_;

  // Information about each wake that occurred during dark resume. This vector
  // is cleared by StartRequest() and reported by FinishRequest().
  //
  // HandleDarkResume() pushes a new entry when it sees a successful dark
  // resume, but the entry's wake reason and duration is updated by Suspend()
  // when it commences the next dark suspend cycle.
  std::vector<DarkResumeInfo> dark_resume_wake_durations_;

  // Current set of displays in sorted (compared using operator<) order that
  // suspender is aware of. Note that OnDisplaysChanged() assumes that this
  // vector remains unchanged.
  std::vector<system::DisplayInfo> displays_;

  // The wake reason for the last dark resume.
  std::string last_dark_resume_wake_reason_;

  // Runs HandleEvent(EVENT_READY_TO_RESUSPEND).
  base::OneShotTimer resuspend_timer_;

  // Whether the system is presenting or not.
  DisplayMode display_mode_ = DisplayMode::NORMAL;

  // Whether or not the system supports hibernate.
  bool hibernate_available_;

  // Keep this last.
  base::WeakPtrFactory<Suspender> weak_ptr_factory_;
};

}  // namespace policy
}  // namespace power_manager

#endif  // POWER_MANAGER_POWERD_POLICY_SUSPENDER_H_
