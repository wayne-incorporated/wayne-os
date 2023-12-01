// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/powerd/policy/state_controller.h"

#include <stdint.h>

#include <utility>
#include <vector>

#include <base/format_macros.h>
#include <base/logging.h>
#include <base/run_loop.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <base/time/time.h>
#include <chromeos/dbus/service_constants.h>
#include <dbus/message.h>
#include <gtest/gtest.h>
#include <update_engine/proto_bindings/update_engine.pb.h>

#include "hps/proto_bindings/hps_service.pb.h"
#include "power_manager/common/action_recorder.h"
#include "power_manager/common/clock.h"
#include "power_manager/common/fake_prefs.h"
#include "power_manager/common/metrics_constants.h"
#include "power_manager/common/power_constants.h"
#include "power_manager/powerd/system/dbus_wrapper_stub.h"
#include "power_manager/powerd/testing/test_environment.h"
#include "power_manager/proto_bindings/idle.pb.h"
#include "power_manager/proto_bindings/policy.pb.h"

namespace power_manager::policy {

namespace {

using HpsResult = hps::HpsResult;

// Strings returned by TestDelegate::GetActions() to describe various
// actions that were requested.
const char kScreenDim[] = "dim";
const char kScreenOff[] = "off";
const char kScreenLock[] = "lock";
const char kScreenUndim[] = "undim";
const char kScreenOn[] = "on";
const char kSuspendIdle[] = "suspend_idle";
const char kSuspendLidClosed[] = "suspend_lid";
const char kStopSession[] = "logout";
const char kShutDown[] = "shut_down";
const char kReportUserActivityMetrics[] = "metrics";

// String returned by TestDelegate::GetActions() if no actions were
// requested.
const char kNoActions[] = "";

// Return a string representation of DimEvent.
std::string GetDimEventString(metrics::DimEvent sample) {
  return base::StringPrintf("DimEvent-%d", sample);
}

// Return a string representation of LockEvent.
std::string GetLockEventString(metrics::LockEvent sample) {
  return base::StringPrintf("LockEvent-%d", sample);
}

// Return a string representation of event name and duration.
std::string GetHpsEventDurationString(const std::string& event_name,
                                      base::TimeDelta duration) {
  return base::StringPrintf("%s:%d", event_name.c_str(),
                            static_cast<int>(duration.InSeconds()));
}

// StateController::Delegate implementation that records requested actions.
class TestDelegate : public StateController::Delegate, public ActionRecorder {
 public:
  TestDelegate() = default;
  TestDelegate(const TestDelegate&) = delete;
  TestDelegate& operator=(const TestDelegate&) = delete;

  ~TestDelegate() override = default;

  void set_record_metrics_actions(bool record) {
    record_metrics_actions_ = record;
  }
  void set_record_hps_event_metrics(bool record) {
    record_hps_event_metrics_ = record;
  }
  void set_usb_input_device_connected(bool connected) {
    usb_input_device_connected_ = connected;
  }
  void set_oobe_completed(bool completed) { oobe_completed_ = completed; }
  void set_hdmi_audio_active(bool active) { hdmi_audio_active_ = active; }
  void set_headphone_jack_plugged(bool plugged) {
    headphone_jack_plugged_ = plugged;
  }

  // StateController::Delegate overrides:
  bool IsUsbInputDeviceConnected() override {
    return usb_input_device_connected_;
  }

  bool IsOobeCompleted() override { return oobe_completed_; }
  bool IsHdmiAudioActive() override { return hdmi_audio_active_; }
  bool IsHeadphoneJackPlugged() override { return headphone_jack_plugged_; }
  void DimScreen() override { AppendAction(kScreenDim); }
  void UndimScreen() override { AppendAction(kScreenUndim); }
  void TurnScreenOff() override { AppendAction(kScreenOff); }
  void TurnScreenOn() override { AppendAction(kScreenOn); }
  void LockScreen() override { AppendAction(kScreenLock); }
  void Suspend(StateController::ActionReason reason) override {
    switch (reason) {
      case StateController::ActionReason::IDLE:
        AppendAction(kSuspendIdle);
        break;
      case StateController::ActionReason::LID_CLOSED:
        AppendAction(kSuspendLidClosed);
        break;
    }
  }
  void StopSession() override { AppendAction(kStopSession); }
  void ShutDown() override { AppendAction(kShutDown); }

  void ReportUserActivityMetrics() override {
    if (record_metrics_actions_)
      AppendAction(kReportUserActivityMetrics);
  }
  void ReportDimEventMetrics(metrics::DimEvent sample) override {
    if (record_hps_event_metrics_) {
      AppendAction(GetDimEventString(sample));
    }
  }
  void ReportLockEventMetrics(metrics::LockEvent sample) override {
    if (record_hps_event_metrics_) {
      AppendAction(GetLockEventString(sample));
    }
  }
  void ReportHpsEventDurationMetrics(const std::string& event_name,
                                     base::TimeDelta duration) override {
    if (record_hps_event_metrics_) {
      AppendAction(GetHpsEventDurationString(event_name, duration));
    }
  }

 private:
  // Should calls to ReportUserActivityMetrics be recorded in |actions_|? These
  // are noisy, so by default, they aren't recorded.
  bool record_metrics_actions_ = false;

  // Should calls to ReportDimEventMetrics and
  // ReportHpsEventDurationMetrics be recorded in |actions_|? These are noisy,
  // so by default, they aren't recorded.
  bool record_hps_event_metrics_ = false;

  // Should IsUsbInputDeviceConnected() return true?
  bool usb_input_device_connected_ = false;

  // Should IsOobeCompleted() return true?
  bool oobe_completed_ = true;

  // Should IsHdmiAudioActive() return true?
  bool hdmi_audio_active_ = false;

  // Should IsHeadphoneJackPlugged() return true?
  bool headphone_jack_plugged_ = false;
};

// Fills an update_engine message used either for a GetStatusAdvanced response
// or a StatusUpdateAdvanced signal.
void FillUpdateMessage(dbus::Message* message,
                       const update_engine::Operation& operation) {
  update_engine::StatusResult status;
  status.set_last_checked_time(1 /* arbitrary */);
  status.set_progress(0.0 /* arbitrary */);
  status.set_current_operation(operation);

  dbus::MessageWriter writer(message);
  writer.AppendProtoAsArrayOfBytes(status);
}

// Returns a string representation of an IdleActionImminent D-Bus signal. See
// StateControllerTest::GetDBusSignals().
std::string GetIdleActionImminentString(base::TimeDelta time_until_idle) {
  return base::StringPrintf("%s(%" PRId64 ")", kIdleActionImminentSignal,
                            time_until_idle.InMilliseconds());
}

// Returns a string representation of an InactivityDelaysChanged D-Bus signal.
// See StateControllerTest::GetDBusSignals().
std::string GetInactivityDelaysChangedString(base::TimeDelta idle,
                                             base::TimeDelta idle_warning,
                                             base::TimeDelta screen_off,
                                             base::TimeDelta screen_dim,
                                             base::TimeDelta screen_lock) {
  return base::StringPrintf(
      "%s(%" PRId64 ",%" PRId64 ",%" PRId64 ",%" PRId64 ",%" PRId64 ")",
      kInactivityDelaysChangedSignal, idle.InMilliseconds(),
      idle_warning.InMilliseconds(), screen_off.InMilliseconds(),
      screen_dim.InMilliseconds(), screen_lock.InMilliseconds());
}

// Returns a string representation of a ScreenIdleStateChanged D-Bus signal. See
// StateControllerTest::GetDBusSignals().
std::string GetScreenIdleStateChangedString(bool dimmed, bool off) {
  return base::StringPrintf("%s(%s,%s)", kScreenIdleStateChangedSignal,
                            std::to_string(dimmed).c_str(),
                            std::to_string(off).c_str());
}

}  // namespace

class StateControllerTest : public TestEnvironment {
 public:
  StateControllerTest()
      : test_api_(&controller_),
        update_engine_proxy_(dbus_wrapper_.GetObjectProxy(
            update_engine::kUpdateEngineServiceName,
            update_engine::kUpdateEngineServicePath)),
        ml_decision_proxy_(
            dbus_wrapper_.GetObjectProxy(chromeos::kMlDecisionServiceName,
                                         chromeos::kMlDecisionServicePath)),
        hps_dbus_proxy_(dbus_wrapper_.GetObjectProxy(hps::kHpsServiceName,
                                                     hps::kHpsServicePath)) {
    dbus_wrapper_.SetMethodCallback(base::BindRepeating(
        &StateControllerTest::HandleDBusMethodCall, base::Unretained(this)));
  }
  StateControllerTest(const StateControllerTest&) = delete;
  StateControllerTest& operator=(const StateControllerTest&) = delete;

 protected:
  void SetMillisecondPref(const std::string& name, base::TimeDelta value) {
    prefs_.SetInt64(name, value.InMilliseconds());
  }

  // Sets values in |prefs_| based on |default_*| members and initializes
  // |controller_|.
  void Init() {
    SetMillisecondPref(kPluggedSuspendMsPref, default_ac_suspend_delay_);
    SetMillisecondPref(kPluggedOffMsPref, default_ac_screen_off_delay_);
    SetMillisecondPref(kPluggedDimMsPref, default_ac_screen_dim_delay_);
    SetMillisecondPref(kPluggedQuickDimMsPref, default_ac_quick_dim_delay_);
    SetMillisecondPref(kPluggedQuickLockMsPref, default_ac_quick_lock_delay_);
    SetMillisecondPref(kUnpluggedSuspendMsPref, default_battery_suspend_delay_);
    SetMillisecondPref(kUnpluggedOffMsPref, default_battery_screen_off_delay_);
    SetMillisecondPref(kUnpluggedDimMsPref, default_battery_screen_dim_delay_);
    SetMillisecondPref(kUnpluggedQuickDimMsPref,
                       default_battery_quick_dim_delay_);
    SetMillisecondPref(kUnpluggedQuickLockMsPref,
                       default_battery_quick_lock_delay_);
    prefs_.SetInt64(kDisableIdleSuspendPref, default_disable_idle_suspend_);
    prefs_.SetInt64(kFactoryModePref, default_factory_mode_);
    prefs_.SetInt64(kRequireUsbInputDeviceToSuspendPref,
                    default_require_usb_input_device_to_suspend_);
    prefs_.SetInt64(kAvoidSuspendWhenHeadphoneJackPluggedPref,
                    default_avoid_suspend_when_headphone_jack_plugged_);
    prefs_.SetInt64(kIgnoreExternalPolicyPref, default_ignore_external_policy_);
    prefs_.SetInt64(kDeferExternalDisplayTimeoutPref,
                    default_defer_external_display_timeout_);

    test_api_.clock()->set_current_time_for_testing(now_);
    controller_.Init(&delegate_, &prefs_, &dbus_wrapper_, initial_power_source_,
                     initial_lid_state_);

    if (send_initial_display_mode_)
      controller_.HandleDisplayModeChange(initial_display_mode_);
    if (send_initial_policy_)
      controller_.HandlePolicyChange(initial_policy_);
    if (trigger_wait_for_crash_boot_collect_timeout_)
      test_api_.TriggerHandleCrashBootCollectTimeout();
  }

  // Advances |now_| by |interval_|.
  void AdvanceTime(base::TimeDelta interval) {
    now_ += interval;
    test_api_.clock()->set_current_time_for_testing(now_);
  }

  // Checks that |controller_|'s action timeout is scheduled for |now_| and then
  // runs it.  Returns false if the timeout isn't scheduled or is scheduled for
  // a different time.
  [[nodiscard]] bool TriggerTimeout() {
    base::TimeTicks timeout_time = test_api_.action_timer_time();
    if (timeout_time == base::TimeTicks()) {
      LOG(ERROR) << "Ignoring request to trigger unscheduled timeout at "
                 << (now_ - base::TimeTicks()).InMicroseconds();
      return false;
    }
    if (timeout_time != now_) {
      LOG(ERROR) << "Ignoring request to trigger timeout scheduled for "
                 << (timeout_time - base::TimeTicks()).InMicroseconds()
                 << " at " << (now_ - base::TimeTicks()).InMicroseconds();
      return false;
    }
    test_api_.TriggerActionTimeout();
    return true;
  }

  // Advances |now_| by |interval| and calls TriggerTimeout().
  [[nodiscard]] bool AdvanceTimeAndTriggerTimeout(base::TimeDelta interval) {
    AdvanceTime(interval);
    return TriggerTimeout();
  }

  // Advances |now_| by |next_delay| minus the last delay passed to this
  // method and calls TriggerTimeout().  This is useful when invoking
  // successive delays: for example, given delays at 2, 4, and 5 minutes,
  // instead of calling AdvanceTimeAndTriggerTimeout() with 2, (4 - 2), and
  // then (5 - 4), StepTimeAndTriggerTimeout() can be called with 2, 4, and
  // 5.  Call ResetLastStepDelay() before a new sequence of delays to reset
  // the "last delay".
  void StepTime(base::TimeDelta next_delay) {
    AdvanceTime(next_delay - last_step_delay_);
    last_step_delay_ = next_delay;
  }

  [[nodiscard]] bool StepTimeAndTriggerTimeout(base::TimeDelta next_delay) {
    StepTime(next_delay);
    return TriggerTimeout();
  }

  // Resets the "last delay" used by StepTimeAndTriggerTimeout().
  void ResetLastStepDelay() { last_step_delay_ = base::TimeDelta(); }

  // Steps through time to trigger the default AC screen dim, off, and
  // suspend timeouts.
  [[nodiscard]] bool TriggerDefaultAcTimeouts() {
    ResetLastStepDelay();
    return StepTimeAndTriggerTimeout(default_ac_screen_dim_delay_) &&
           StepTimeAndTriggerTimeout(default_ac_screen_off_delay_) &&
           StepTimeAndTriggerTimeout(default_ac_suspend_delay_);
  }

  // Emits a StatusUpdateAdvanced D-Bus signal on behalf of update_engine.
  void EmitStatusUpdateSignal(const update_engine::Operation& operation) {
    dbus::Signal signal(update_engine::kUpdateEngineInterface,
                        update_engine::kStatusUpdateAdvanced);
    FillUpdateMessage(&signal, operation);
    dbus_wrapper_.EmitRegisteredSignal(update_engine_proxy_, &signal);
  }

  void EmitHpsSignal(const hps::HpsResult result) {
    hps::HpsResultProto result_proto;
    result_proto.set_value(result);

    dbus::Signal signal(hps::kHpsServiceInterface, hps::kHpsSenseChanged);
    dbus::MessageWriter writer(&signal);
    writer.AppendProtoAsArrayOfBytes(result_proto);
    dbus_wrapper_.EmitRegisteredSignal(hps_dbus_proxy_, &signal);
  }

  // Generates responses for D-Bus method calls to other processes sent via
  // |dbus_wrapper_|.
  std::unique_ptr<dbus::Response> HandleDBusMethodCall(dbus::ObjectProxy* proxy,
                                                       dbus::MethodCall* call) {
    dbus_method_calls_.push_back(call->GetMember());
    if (proxy == update_engine_proxy_ &&
        call->GetInterface() == update_engine::kUpdateEngineInterface &&
        call->GetMember() == update_engine::kGetStatusAdvanced) {
      std::unique_ptr<dbus::Response> response =
          dbus::Response::FromMethodCall(call);
      FillUpdateMessage(response.get(), update_engine_operation_);
      return response;
    }

    if (proxy == ml_decision_proxy_ &&
        call->GetInterface() == chromeos::kMlDecisionServiceInterface &&
        call->GetMember() ==
            chromeos::kMlDecisionServiceShouldDeferScreenDimMethod) {
      if (simulate_smart_dim_timeout_)
        return nullptr;

      std::unique_ptr<dbus::Response> response =
          dbus::Response::FromMethodCall(call);
      dbus::MessageWriter writer(response.get());
      writer.AppendBool(defer_screen_dimming_);

      return response;
    }

    ADD_FAILURE() << "Got unexpected D-Bus method call to "
                  << call->GetInterface() << "." << call->GetMember()
                  << " on proxy " << proxy;
    return nullptr;
  }

  // SignalType is passed to GetDBusSignals() to describe which types of signals
  // to return.
  enum class SignalType {
    // Return all emitted signals.
    ALL,
    // Return only ScreenDimImminent, IdleActionImminent, and IdleActionDeferred
    // signals.
    ACTIONS,
  };

  // Returns a comma-separated string describing D-Bus signals emitted by
  // |dbus_wrapper_| and matched by |signal_type|. Also clears all recorded
  // signals (regardless of whether they're matched or not).
  std::string GetDBusSignals(SignalType signal_type) {
    std::vector<std::string> signals;
    for (size_t i = 0; i < dbus_wrapper_.num_sent_signals(); ++i) {
      const std::string name = dbus_wrapper_.GetSentSignalName(i);
      if (signal_type == SignalType::ACTIONS &&
          (name != kIdleActionImminentSignal &&
           name != kIdleActionDeferredSignal))
        continue;

      if (name == kIdleActionImminentSignal) {
        IdleActionImminent proto;
        EXPECT_TRUE(dbus_wrapper_.GetSentSignal(i, name, &proto, nullptr));
        signals.push_back(GetIdleActionImminentString(
            base::Microseconds(proto.time_until_idle_action())));
      } else if (name == kInactivityDelaysChangedSignal) {
        PowerManagementPolicy::Delays proto;
        EXPECT_TRUE(dbus_wrapper_.GetSentSignal(i, name, &proto, nullptr));
        signals.push_back(GetInactivityDelaysChangedString(
            base::Milliseconds(proto.idle_ms()),
            base::Milliseconds(proto.idle_warning_ms()),
            base::Milliseconds(proto.screen_off_ms()),
            base::Milliseconds(proto.screen_dim_ms()),
            base::Milliseconds(proto.screen_lock_ms())));
      } else if (name == kScreenIdleStateChangedSignal) {
        ScreenIdleState proto;
        EXPECT_TRUE(dbus_wrapper_.GetSentSignal(i, name, &proto, nullptr));
        signals.push_back(
            GetScreenIdleStateChangedString(proto.dimmed(), proto.off()));
      } else {
        signals.push_back(name);
      }
    }
    dbus_wrapper_.ClearSentSignals();
    return base::JoinString(signals, ",");
  }

  // Return a comma-separated string listing the names of D-Bus method calls
  // sent by |dbus_wrapper_|. Also clears all recorded method calls.
  std::string GetDBusMethodCalls() {
    std::string method_calls_str = base::JoinString(dbus_method_calls_, ",");
    dbus_method_calls_.clear();
    return method_calls_str;
  }

  FakePrefs prefs_;
  TestDelegate delegate_;
  system::DBusWrapperStub dbus_wrapper_;
  StateController controller_;
  StateController::TestApi test_api_;
  dbus::ObjectProxy* update_engine_proxy_;  // owned by |dbus_wrapper_|
  dbus::ObjectProxy* ml_decision_proxy_;    // owned by |dbus_wrapper_|
  dbus::ObjectProxy* hps_dbus_proxy_;       // owned by |dbus_wrapper_|

  base::TimeTicks now_ = base::TimeTicks() + base::Microseconds(1000);

  // Last delay that was passed to StepTimeAndTriggerTimeout().
  base::TimeDelta last_step_delay_;

  // Preference values.  Tests may change these before calling Init().
  base::TimeDelta default_ac_suspend_delay_ = base::Seconds(120);
  base::TimeDelta default_ac_screen_off_delay_ = base::Seconds(100);
  base::TimeDelta default_ac_screen_dim_delay_ = base::Seconds(90);
  base::TimeDelta default_ac_quick_dim_delay_ = base::Seconds(70);
  base::TimeDelta default_ac_quick_lock_delay_ = base::Seconds(80);
  base::TimeDelta default_battery_suspend_delay_ = base::Seconds(60);
  base::TimeDelta default_battery_screen_off_delay_ = base::Seconds(40);
  base::TimeDelta default_battery_screen_dim_delay_ = base::Seconds(30);
  base::TimeDelta default_battery_quick_dim_delay_ = base::Seconds(20);
  base::TimeDelta default_battery_quick_lock_delay_ = base::Seconds(25);
  int64_t default_disable_idle_suspend_ = 0;
  int64_t default_factory_mode_ = 0;
  int64_t default_require_usb_input_device_to_suspend_ = 0;
  int64_t default_avoid_suspend_when_headphone_jack_plugged_ = 0;
  int64_t default_ignore_external_policy_ = 0;
  int64_t default_defer_external_display_timeout_ = 0;

  // Values passed by Init() to StateController::Init().
  PowerSource initial_power_source_ = PowerSource::AC;
  LidState initial_lid_state_ = LidState::OPEN;

  // Initial display mode to send in Init().
  DisplayMode initial_display_mode_ = DisplayMode::NORMAL;
  bool send_initial_display_mode_ = true;

  // Trigger wait_for_crash_boot_collect_timeout in Init().
  bool trigger_wait_for_crash_boot_collect_timeout_ = true;

  // Initial policy to send in Init().
  PowerManagementPolicy initial_policy_;
  bool send_initial_policy_ = true;

  // Operation for update_engine to return in response to GetStatusAdvanced
  // calls.
  update_engine::Operation update_engine_operation_ =
      update_engine::Operation::IDLE;

  // Names of D-Bus method calls.
  std::vector<std::string> dbus_method_calls_;

  // Response that powerd will receive from RequestSmartDimDecision.
  bool defer_screen_dimming_ = true;
  // If true, RequestSmartDimDecision will receive a nullptr as response, just
  // like when timeout.
  bool simulate_smart_dim_timeout_ = false;
};

// Tests the basic operation of the different delays.
TEST_F(StateControllerTest, BasicDelays) {
  Init();

  // Initial messages describing the inactivity delays and reporting that the
  // screen is undimmed and turned on should be sent at startup.
  EXPECT_EQ(
      JoinActions(
          GetInactivityDelaysChangedString(
              default_ac_suspend_delay_, base::TimeDelta() /* idle_warning */,
              default_ac_screen_off_delay_, default_ac_screen_dim_delay_,
              base::TimeDelta() /* lock */)
              .c_str(),
          GetScreenIdleStateChangedString(false, false).c_str(), nullptr),
      GetDBusSignals(SignalType::ALL));

  // The screen should be dimmed after the configured interval and then undimmed
  // in response to user activity.
  ASSERT_TRUE(AdvanceTimeAndTriggerTimeout(default_ac_screen_dim_delay_));
  EXPECT_EQ(JoinActions(kScreenDim, nullptr), delegate_.GetActions());
  EXPECT_EQ(GetScreenIdleStateChangedString(true, false).c_str(),
            GetDBusSignals(SignalType::ALL));

  controller_.HandleUserActivity();
  EXPECT_EQ(kScreenUndim, delegate_.GetActions());
  EXPECT_EQ(GetScreenIdleStateChangedString(false, false).c_str(),
            GetDBusSignals(SignalType::ALL));

  // The screen should be dimmed after the configured interval and then undimmed
  // in response to wake notification.
  ASSERT_TRUE(AdvanceTimeAndTriggerTimeout(default_ac_screen_dim_delay_));
  EXPECT_EQ(JoinActions(kScreenDim, nullptr), delegate_.GetActions());
  EXPECT_EQ(GetScreenIdleStateChangedString(true, false).c_str(),
            GetDBusSignals(SignalType::ALL));

  controller_.HandleWakeNotification();
  EXPECT_EQ(kScreenUndim, delegate_.GetActions());
  EXPECT_EQ(GetScreenIdleStateChangedString(false, false).c_str(),
            GetDBusSignals(SignalType::ALL));

  // The system should eventually suspend if the user is inactive.
  ASSERT_TRUE(StepTimeAndTriggerTimeout(default_ac_screen_dim_delay_));
  EXPECT_EQ(kScreenDim, delegate_.GetActions());
  EXPECT_EQ(GetScreenIdleStateChangedString(true, false).c_str(),
            GetDBusSignals(SignalType::ALL));

  ASSERT_TRUE(StepTimeAndTriggerTimeout(default_ac_screen_off_delay_));
  EXPECT_EQ(kScreenOff, delegate_.GetActions());
  EXPECT_EQ(GetScreenIdleStateChangedString(true, true).c_str(),
            GetDBusSignals(SignalType::ALL));

  ASSERT_TRUE(StepTimeAndTriggerTimeout(default_ac_suspend_delay_));
  EXPECT_EQ(kSuspendIdle, delegate_.GetActions());

  // No further timeouts should be scheduled at this point.
  EXPECT_TRUE(test_api_.action_timer_time().is_null());

  // When the system resumes, the screen should be undimmed and turned back
  // on.
  controller_.HandleResume(LidState::NOT_PRESENT);
  EXPECT_EQ(JoinActions(kScreenUndim, kScreenOn, nullptr),
            delegate_.GetActions());
  EXPECT_EQ(GetScreenIdleStateChangedString(false, false).c_str(),
            GetDBusSignals(SignalType::ALL));

  // The screen should be dimmed again after the screen-dim delay.
  ASSERT_TRUE(AdvanceTimeAndTriggerTimeout(default_ac_screen_dim_delay_));
  EXPECT_EQ(kScreenDim, delegate_.GetActions());
  EXPECT_EQ(GetScreenIdleStateChangedString(true, false).c_str(),
            GetDBusSignals(SignalType::ALL));
}

// Tests that the screen isn't dimmed while video is detected.
TEST_F(StateControllerTest, VideoDefersDimming) {
  Init();

  // The screen shouldn't be dimmed while a video is playing.
  const base::TimeDelta kHalfDimDelay = default_ac_screen_dim_delay_ / 2;
  controller_.HandleVideoActivity();
  AdvanceTime(kHalfDimDelay);
  controller_.HandleVideoActivity();
  AdvanceTime(kHalfDimDelay);
  controller_.HandleVideoActivity();
  AdvanceTime(kHalfDimDelay);
  controller_.HandleVideoActivity();
  EXPECT_EQ(kNoActions, delegate_.GetActions());

  // After the video stops, the dimming delay should happen as expected.
  ResetLastStepDelay();
  ASSERT_TRUE(StepTimeAndTriggerTimeout(default_ac_screen_dim_delay_));
  EXPECT_EQ(kScreenDim, delegate_.GetActions());

  // Video activity should be ignored while the screen is dimmed or off.
  controller_.HandleVideoActivity();
  EXPECT_EQ(kNoActions, delegate_.GetActions());
  ASSERT_TRUE(StepTimeAndTriggerTimeout(default_ac_screen_off_delay_));
  EXPECT_EQ(kScreenOff, delegate_.GetActions());
  controller_.HandleVideoActivity();
  EXPECT_EQ(kNoActions, delegate_.GetActions());

  // After the user starts another video, the dimming delay should fire
  // again after the video stops.
  controller_.HandleUserActivity();
  EXPECT_EQ(JoinActions(kScreenUndim, kScreenOn, nullptr),
            delegate_.GetActions());
  controller_.HandleVideoActivity();
  EXPECT_EQ(kNoActions, delegate_.GetActions());
  ASSERT_TRUE(AdvanceTimeAndTriggerTimeout(default_ac_screen_dim_delay_));
  EXPECT_EQ(kScreenDim, delegate_.GetActions());
}

// Tests that the screen dims, is turned off, and is locked while audio is
// playing.
TEST_F(StateControllerTest, AudioBlocksSuspend) {
  Init();

  const base::TimeDelta kDimDelay = base::Seconds(300);
  const base::TimeDelta kOffDelay = base::Seconds(310);
  const base::TimeDelta kLockDelay = base::Seconds(320);
  const base::TimeDelta kIdleDelay = base::Seconds(330);

  PowerManagementPolicy policy;
  policy.mutable_ac_delays()->set_screen_dim_ms(kDimDelay.InMilliseconds());
  policy.mutable_ac_delays()->set_screen_off_ms(kOffDelay.InMilliseconds());
  policy.mutable_ac_delays()->set_screen_lock_ms(kLockDelay.InMilliseconds());
  policy.mutable_ac_delays()->set_idle_ms(kIdleDelay.InMilliseconds());
  controller_.HandlePolicyChange(policy);

  // Report audio activity and check that the controller goes through the
  // usual dim->off->lock progression.
  controller_.HandleAudioStateChange(true);
  ASSERT_TRUE(StepTimeAndTriggerTimeout(kDimDelay));
  EXPECT_EQ(kScreenDim, delegate_.GetActions());
  ASSERT_TRUE(StepTimeAndTriggerTimeout(kOffDelay));
  EXPECT_EQ(kScreenOff, delegate_.GetActions());
  ASSERT_TRUE(StepTimeAndTriggerTimeout(kLockDelay));
  EXPECT_EQ(kScreenLock, delegate_.GetActions());

  // The idle action is blocked until audio activity stops, so no further
  // timeouts should be scheduled.
  EXPECT_TRUE(test_api_.action_timer_time().is_null());

  // After the audio stops, the controller should wait for the full suspend
  // delay before suspending.
  controller_.HandleAudioStateChange(false);
  EXPECT_EQ(kNoActions, delegate_.GetActions());
  ASSERT_TRUE(AdvanceTimeAndTriggerTimeout(kIdleDelay));
  EXPECT_EQ(kSuspendIdle, delegate_.GetActions());
}

// Tests that the system is suspended when the lid is closed.
TEST_F(StateControllerTest, LidCloseSuspendsByDefault) {
  Init();
  controller_.HandleLidStateChange(LidState::CLOSED);
  EXPECT_EQ(kSuspendLidClosed, delegate_.GetActions());

  // After the lid is opened, the next delay should be screen-dimming (i.e.
  // all timers should be reset).
  controller_.HandleResume(LidState::OPEN);
  EXPECT_EQ(kNoActions, delegate_.GetActions());
  controller_.HandleLidStateChange(LidState::OPEN);
  EXPECT_EQ(kNoActions, delegate_.GetActions());
  ASSERT_TRUE(AdvanceTimeAndTriggerTimeout(default_ac_screen_dim_delay_));
  EXPECT_EQ(kScreenDim, delegate_.GetActions());
}

// Tests that timeouts are reset when the user logs in or out.
TEST_F(StateControllerTest, SessionStateChangeResetsTimeouts) {
  Init();
  controller_.HandleSessionStateChange(SessionState::STARTED);
  ASSERT_TRUE(StepTimeAndTriggerTimeout(default_ac_screen_dim_delay_));
  ASSERT_TRUE(StepTimeAndTriggerTimeout(default_ac_screen_off_delay_));
  EXPECT_EQ(JoinActions(kScreenDim, kScreenOff, nullptr),
            delegate_.GetActions());

  // The screen should be undimmed and turned on when a user logs out.
  controller_.HandleSessionStateChange(SessionState::STOPPED);
  EXPECT_EQ(JoinActions(kScreenUndim, kScreenOn, nullptr),
            delegate_.GetActions());

  // The screen should be dimmed again after the usual delay.
  ASSERT_TRUE(AdvanceTimeAndTriggerTimeout(default_ac_screen_dim_delay_));
  EXPECT_EQ(kScreenDim, delegate_.GetActions());
}

// Tests that delays are scaled while presenting and that they return to
// their original values when not presenting.
TEST_F(StateControllerTest, ScaleDelaysWhilePresenting) {
  Init();

  const double kScreenDimFactor = 3.0;
  const base::TimeDelta kDimDelay = base::Seconds(300);
  const base::TimeDelta kOffDelay = base::Seconds(310);
  const base::TimeDelta kLockDelay = base::Seconds(320);
  const base::TimeDelta kWarnDelay = base::Seconds(330);
  const base::TimeDelta kIdleDelay = base::Seconds(340);

  const base::TimeDelta kScaledDimDelay =
      base::Microseconds(kDimDelay.InMicrosecondsF() * kScreenDimFactor);
  const base::TimeDelta kDelayDiff = kScaledDimDelay - kDimDelay;
  const base::TimeDelta kScaledOffDelay = kOffDelay + kDelayDiff;
  const base::TimeDelta kScaledLockDelay = kLockDelay + kDelayDiff;
  const base::TimeDelta kScaledWarnDelay = kWarnDelay + kDelayDiff;
  const base::TimeDelta kScaledIdleDelay = kIdleDelay + kDelayDiff;

  PowerManagementPolicy policy;
  policy.mutable_ac_delays()->set_screen_dim_ms(kDimDelay.InMilliseconds());
  policy.mutable_ac_delays()->set_screen_off_ms(kOffDelay.InMilliseconds());
  policy.mutable_ac_delays()->set_screen_lock_ms(kLockDelay.InMilliseconds());
  policy.mutable_ac_delays()->set_idle_warning_ms(kWarnDelay.InMilliseconds());
  policy.mutable_ac_delays()->set_idle_ms(kIdleDelay.InMilliseconds());
  policy.set_ac_idle_action(PowerManagementPolicy_Action_STOP_SESSION);
  policy.set_presentation_screen_dim_delay_factor(kScreenDimFactor);
  controller_.HandlePolicyChange(policy);

  controller_.HandleDisplayModeChange(DisplayMode::PRESENTATION);
  EXPECT_EQ(kNoActions, delegate_.GetActions());
  ResetLastStepDelay();
  ASSERT_TRUE(StepTimeAndTriggerTimeout(kScaledDimDelay));
  EXPECT_EQ(kScreenDim, delegate_.GetActions());
  ASSERT_TRUE(StepTimeAndTriggerTimeout(kScaledOffDelay));
  EXPECT_EQ(kScreenOff, delegate_.GetActions());
  ASSERT_TRUE(StepTimeAndTriggerTimeout(kScaledLockDelay));
  EXPECT_EQ(kScreenLock, delegate_.GetActions());
  ASSERT_TRUE(StepTimeAndTriggerTimeout(kScaledWarnDelay));
  EXPECT_EQ(GetIdleActionImminentString(kScaledIdleDelay - kScaledWarnDelay),
            GetDBusSignals(SignalType::ACTIONS));
  ASSERT_TRUE(StepTimeAndTriggerTimeout(kScaledIdleDelay));
  EXPECT_EQ(kStopSession, delegate_.GetActions());
  AdvanceTime(StateController::kIgnoreDisplayModeAfterScreenOffInterval +
              base::Seconds(1));

  controller_.HandleDisplayModeChange(DisplayMode::NORMAL);
  EXPECT_EQ(JoinActions(kScreenUndim, kScreenOn, nullptr),
            delegate_.GetActions());
  ResetLastStepDelay();
  ASSERT_TRUE(StepTimeAndTriggerTimeout(kDimDelay));
  EXPECT_EQ(kScreenDim, delegate_.GetActions());
  ASSERT_TRUE(StepTimeAndTriggerTimeout(kOffDelay));
  EXPECT_EQ(kScreenOff, delegate_.GetActions());
  ASSERT_TRUE(StepTimeAndTriggerTimeout(kLockDelay));
  EXPECT_EQ(kScreenLock, delegate_.GetActions());
  ASSERT_TRUE(StepTimeAndTriggerTimeout(kWarnDelay));
  EXPECT_EQ(GetIdleActionImminentString(kIdleDelay - kWarnDelay),
            GetDBusSignals(SignalType::ACTIONS));
  ASSERT_TRUE(StepTimeAndTriggerTimeout(kIdleDelay));
  EXPECT_EQ(kStopSession, delegate_.GetActions());
}

// Tests that the appropriate delays are used when switching between battery
// and AC power.
TEST_F(StateControllerTest, PowerSourceChange) {
  // Start out on battery power.
  initial_power_source_ = PowerSource::BATTERY;
  default_battery_screen_dim_delay_ = base::Seconds(60);
  default_battery_screen_off_delay_ = base::Seconds(90);
  default_battery_suspend_delay_ = base::Seconds(100);
  default_ac_screen_dim_delay_ = base::Seconds(120);
  default_ac_screen_off_delay_ = base::Seconds(150);
  default_ac_suspend_delay_ = base::Seconds(160);
  Init();

  ASSERT_TRUE(StepTimeAndTriggerTimeout(default_battery_screen_dim_delay_));
  EXPECT_EQ(kScreenDim, delegate_.GetActions());
  ASSERT_TRUE(StepTimeAndTriggerTimeout(default_battery_screen_off_delay_));
  EXPECT_EQ(kScreenOff, delegate_.GetActions());
  ASSERT_TRUE(StepTimeAndTriggerTimeout(default_battery_suspend_delay_));
  EXPECT_EQ(kSuspendIdle, delegate_.GetActions());

  // Switch to AC power and check that the AC delays are used instead.
  controller_.HandleResume(LidState::NOT_PRESENT);
  EXPECT_EQ(JoinActions(kScreenUndim, kScreenOn, nullptr),
            delegate_.GetActions());
  controller_.HandlePowerSourceChange(PowerSource::AC);
  ResetLastStepDelay();
  ASSERT_TRUE(StepTimeAndTriggerTimeout(default_ac_screen_dim_delay_));
  EXPECT_EQ(kScreenDim, delegate_.GetActions());
  ASSERT_TRUE(StepTimeAndTriggerTimeout(default_ac_screen_off_delay_));
  EXPECT_EQ(kScreenOff, delegate_.GetActions());
  ASSERT_TRUE(StepTimeAndTriggerTimeout(default_ac_suspend_delay_));
  EXPECT_EQ(kSuspendIdle, delegate_.GetActions());

  // Resume and wait for the screen to be dimmed.
  controller_.HandleResume(LidState::NOT_PRESENT);
  EXPECT_EQ(JoinActions(kScreenUndim, kScreenOn, nullptr),
            delegate_.GetActions());
  ASSERT_TRUE(AdvanceTimeAndTriggerTimeout(default_ac_screen_dim_delay_));
  EXPECT_EQ(kScreenDim, delegate_.GetActions());

  // Switch back to battery.  The controller should treat the power source
  // change as a user action and undim the screen (rather than e.g.
  // suspending immediately since |default_battery_suspend_delay_| has been
  // exceeded) and then proceed through the battery delays.
  controller_.HandlePowerSourceChange(PowerSource::BATTERY);
  EXPECT_EQ(kScreenUndim, delegate_.GetActions());
  ResetLastStepDelay();
  ASSERT_TRUE(StepTimeAndTriggerTimeout(default_battery_screen_dim_delay_));
  EXPECT_EQ(kScreenDim, delegate_.GetActions());
  ASSERT_TRUE(StepTimeAndTriggerTimeout(default_battery_screen_off_delay_));
  EXPECT_EQ(kScreenOff, delegate_.GetActions());
  ASSERT_TRUE(StepTimeAndTriggerTimeout(default_battery_suspend_delay_));
  EXPECT_EQ(kSuspendIdle, delegate_.GetActions());
}

// Tests that externally-supplied policy supercedes powerd's default prefs.
TEST_F(StateControllerTest, PolicySupercedesPrefs) {
  Init();

  // Set an external policy that disables most delays and instructs the
  // power manager to shut the system down after 10 minutes of inactivity
  // if on AC power or stop the session if on battery power.
  const base::TimeDelta kIdleDelay = base::Seconds(600);
  PowerManagementPolicy policy;
  policy.mutable_ac_delays()->set_idle_ms(kIdleDelay.InMilliseconds());
  policy.mutable_ac_delays()->set_screen_off_ms(0);
  policy.mutable_ac_delays()->set_screen_dim_ms(0);
  policy.mutable_ac_delays()->set_screen_lock_ms(0);
  *policy.mutable_battery_delays() = policy.ac_delays();
  policy.set_ac_idle_action(PowerManagementPolicy_Action_SHUT_DOWN);
  policy.set_battery_idle_action(PowerManagementPolicy_Action_STOP_SESSION);
  policy.set_lid_closed_action(PowerManagementPolicy_Action_DO_NOTHING);
  policy.set_use_audio_activity(false);
  policy.set_use_video_activity(false);
  controller_.HandlePolicyChange(policy);

  ASSERT_TRUE(AdvanceTimeAndTriggerTimeout(kIdleDelay));
  EXPECT_EQ(kShutDown, delegate_.GetActions());

  controller_.HandleUserActivity();
  EXPECT_EQ(kNoActions, delegate_.GetActions());

  // Wait for half of the idle delay and then report user activity, which
  // should reset the logout timeout.  Audio and video activity should not
  // reset the timeout, however.
  AdvanceTime(kIdleDelay / 2);
  controller_.HandleUserActivity();
  AdvanceTime(kIdleDelay / 2);
  controller_.HandleAudioStateChange(true);
  controller_.HandleVideoActivity();
  ASSERT_TRUE(AdvanceTimeAndTriggerTimeout(kIdleDelay / 2));
  EXPECT_EQ(kShutDown, delegate_.GetActions());

  // The policy's request to do nothing when the lid is closed should be
  // honored.
  controller_.HandleDisplayModeChange(DisplayMode::NORMAL);
  controller_.HandleLidStateChange(LidState::CLOSED);
  EXPECT_EQ(kNoActions, delegate_.GetActions());

  // Wait 120 seconds and then send an updated policy that dims the screen
  // after 60 seconds.  The screen should dim immediately.
  AdvanceTime(base::Seconds(120));
  policy.mutable_ac_delays()->set_screen_dim_ms(60000);
  controller_.HandlePolicyChange(policy);
  EXPECT_EQ(kScreenDim, delegate_.GetActions());

  // Switch to battery power, which still has an unset screen-dimming
  // delay.  The screen should undim immediately.
  controller_.HandlePowerSourceChange(PowerSource::BATTERY);
  EXPECT_EQ(kScreenUndim, delegate_.GetActions());

  // Wait for the idle timeout to be reached and check that the battery
  // idle action is performed.
  ASSERT_TRUE(AdvanceTimeAndTriggerTimeout(base::Seconds(600)));
  EXPECT_EQ(kStopSession, delegate_.GetActions());

  // Update the policy again to shut down if the lid is closed.  Since the
  // lid is already closed, the system should shut down immediately.
  policy.set_lid_closed_action(PowerManagementPolicy_Action_SHUT_DOWN);
  controller_.HandlePolicyChange(policy);
  EXPECT_EQ(kShutDown, delegate_.GetActions());

  // After setting the "ignore external policy" pref, the defaults should
  // be used.
  prefs_.SetInt64(kIgnoreExternalPolicyPref, 1);
  prefs_.NotifyObservers(kIgnoreExternalPolicyPref);
  controller_.HandlePowerSourceChange(PowerSource::AC);
  controller_.HandleAudioStateChange(false);
  ASSERT_TRUE(TriggerDefaultAcTimeouts());
}

// Test that unset fields in a policy are ignored.
TEST_F(StateControllerTest, PartiallyFilledPolicy) {
  Init();

  // Set a policy that has a very short dimming delay but leaves all other
  // fields unset.
  const base::TimeDelta kDimDelay = base::Seconds(1);
  PowerManagementPolicy policy;
  policy.mutable_ac_delays()->set_screen_dim_ms(kDimDelay.InMilliseconds());
  controller_.HandlePolicyChange(policy);

  // The policy's dimming delay should be used, but the rest of the delays
  // should come from prefs.
  ASSERT_TRUE(StepTimeAndTriggerTimeout(kDimDelay));
  EXPECT_EQ(kScreenDim, delegate_.GetActions());
  ASSERT_TRUE(StepTimeAndTriggerTimeout(default_ac_screen_off_delay_));
  EXPECT_EQ(kScreenOff, delegate_.GetActions());
  ASSERT_TRUE(StepTimeAndTriggerTimeout(default_ac_suspend_delay_));
  EXPECT_EQ(kSuspendIdle, delegate_.GetActions());
  controller_.HandleResume(LidState::NOT_PRESENT);
  EXPECT_EQ(JoinActions(kScreenUndim, kScreenOn, nullptr),
            delegate_.GetActions());

  // Setting an empty policy should revert to the values from the prefs.
  policy.Clear();
  controller_.HandlePolicyChange(policy);
  ASSERT_TRUE(TriggerDefaultAcTimeouts());
  EXPECT_EQ(JoinActions(kScreenDim, kScreenOff, kSuspendIdle, nullptr),
            delegate_.GetActions());
}

// Tests that policies that enable audio detection while disabling video
// detection result in the screen getting locked at the expected time but
// defer suspend.
TEST_F(StateControllerTest, PolicyDisablingVideo) {
  Init();

  const base::TimeDelta kDimDelay = base::Seconds(300);
  const base::TimeDelta kOffDelay = base::Seconds(310);
  const base::TimeDelta kLockDelay = base::Seconds(320);
  const base::TimeDelta kIdleDelay = base::Seconds(330);

  PowerManagementPolicy policy;
  policy.mutable_ac_delays()->set_screen_dim_ms(kDimDelay.InMilliseconds());
  policy.mutable_ac_delays()->set_screen_off_ms(kOffDelay.InMilliseconds());
  policy.mutable_ac_delays()->set_screen_lock_ms(kLockDelay.InMilliseconds());
  policy.mutable_ac_delays()->set_idle_ms(kIdleDelay.InMilliseconds());
  policy.set_ac_idle_action(PowerManagementPolicy_Action_SUSPEND);
  policy.set_use_audio_activity(true);
  policy.set_use_video_activity(false);
  controller_.HandlePolicyChange(policy);

  // Proceed through the screen-dim, screen-off, and screen-lock delays,
  // reporting video and audio activity along the way.  The screen should
  // be locked (since |use_video_activity| is false).
  controller_.HandleVideoActivity();
  controller_.HandleAudioStateChange(true);
  EXPECT_EQ(kNoActions, delegate_.GetActions());
  ASSERT_TRUE(StepTimeAndTriggerTimeout(kDimDelay));
  EXPECT_EQ(kScreenDim, delegate_.GetActions());
  controller_.HandleVideoActivity();
  EXPECT_EQ(kNoActions, delegate_.GetActions());
  ASSERT_TRUE(StepTimeAndTriggerTimeout(kOffDelay));
  EXPECT_EQ(kScreenOff, delegate_.GetActions());
  controller_.HandleVideoActivity();
  EXPECT_EQ(kNoActions, delegate_.GetActions());
  ASSERT_TRUE(StepTimeAndTriggerTimeout(kLockDelay));
  EXPECT_EQ(kScreenLock, delegate_.GetActions());

  // The system shouldn't suspend until a full |kIdleDelay| after the audio
  // activity stops, since |use_audio_activity| is false.
  controller_.HandleVideoActivity();
  controller_.HandleAudioStateChange(false);
  EXPECT_EQ(kNoActions, delegate_.GetActions());
  ASSERT_TRUE(AdvanceTimeAndTriggerTimeout(kIdleDelay));
  EXPECT_EQ(kSuspendIdle, delegate_.GetActions());
}

// Tests that the controller does something reasonable if the lid is closed
// just as the idle delay is reached but before the timeout has fired.
TEST_F(StateControllerTest, SimultaneousIdleAndLidActions) {
  Init();

  // Step through the normal delays.  Just when the suspend delay is about
  // to run, close the lid.  We should only make one suspend attempt.
  ASSERT_TRUE(StepTimeAndTriggerTimeout(default_ac_screen_dim_delay_));
  ASSERT_TRUE(StepTimeAndTriggerTimeout(default_ac_screen_off_delay_));
  EXPECT_EQ(JoinActions(kScreenDim, kScreenOff, nullptr),
            delegate_.GetActions());
  AdvanceTime(default_ac_suspend_delay_ - default_ac_screen_off_delay_);
  controller_.HandleLidStateChange(LidState::CLOSED);
  EXPECT_EQ(kSuspendIdle, delegate_.GetActions());
}

// Tests that the screen stays on while audio is playing if an HDMI output is
// active.
TEST_F(StateControllerTest, KeepScreenOnForHdmiAudio) {
  Init();

  delegate_.set_hdmi_audio_active(true);
  ASSERT_TRUE(StepTimeAndTriggerTimeout(default_ac_screen_dim_delay_));
  EXPECT_EQ(kScreenDim, delegate_.GetActions());

  // The screen should be dimmed but stay on while HDMI is active and audio is
  // playing.
  controller_.HandleAudioStateChange(true);
  AdvanceTime(default_ac_screen_off_delay_);
  EXPECT_EQ(kNoActions, delegate_.GetActions());

  // After audio stops, the screen should turn off after the usual delay.
  controller_.HandleAudioStateChange(false);
  ASSERT_TRUE(AdvanceTimeAndTriggerTimeout(default_ac_screen_off_delay_));
  EXPECT_EQ(kScreenOff, delegate_.GetActions());

  // Audio activity should turn the screen back on.
  controller_.HandleAudioStateChange(true);
  EXPECT_EQ(kScreenOn, delegate_.GetActions());
}

// Tests that the |kRequireUsbInputDeviceToSuspendPref| pref is honored.
TEST_F(StateControllerTest, RequireUsbInputDeviceToSuspend) {
  default_require_usb_input_device_to_suspend_ = 1;
  delegate_.set_usb_input_device_connected(false);
  Init();

  // Advance through the usual delays.  The suspend timeout should
  // trigger as before, but no action should be performed.
  ASSERT_TRUE(TriggerDefaultAcTimeouts());
  EXPECT_EQ(JoinActions(kScreenDim, kScreenOff, nullptr),
            delegate_.GetActions());

  // After a USB input device is connected, the system should suspend as
  // before.
  delegate_.set_usb_input_device_connected(true);
  controller_.HandleUserActivity();
  EXPECT_EQ(JoinActions(kScreenUndim, kScreenOn, nullptr),
            delegate_.GetActions());
  ASSERT_TRUE(TriggerDefaultAcTimeouts());
  EXPECT_EQ(JoinActions(kScreenDim, kScreenOff, kSuspendIdle, nullptr),
            delegate_.GetActions());

  // Check the same scenario with a wake notification event.
  controller_.HandleWakeNotification();
  EXPECT_EQ(JoinActions(kScreenUndim, kScreenOn, nullptr),
            delegate_.GetActions());
  ASSERT_TRUE(TriggerDefaultAcTimeouts());
  EXPECT_EQ(JoinActions(kScreenDim, kScreenOff, kSuspendIdle, nullptr),
            delegate_.GetActions());
}

// Tests that suspend is deferred before OOBE is completed.
TEST_F(StateControllerTest, DontSuspendBeforeOobeCompleted) {
  delegate_.set_oobe_completed(false);
  Init();

  // The screen should dim and turn off as usual, but the system shouldn't
  // be suspended.
  ASSERT_TRUE(TriggerDefaultAcTimeouts());
  EXPECT_EQ(JoinActions(kScreenDim, kScreenOff, nullptr),
            delegate_.GetActions());

  // Report user activity and mark OOBE as done.  The system should suspend
  // this time.
  controller_.HandleUserActivity();
  EXPECT_EQ(JoinActions(kScreenUndim, kScreenOn, nullptr),
            delegate_.GetActions());
  delegate_.set_oobe_completed(true);
  ASSERT_TRUE(TriggerDefaultAcTimeouts());
  EXPECT_EQ(JoinActions(kScreenDim, kScreenOff, kSuspendIdle, nullptr),
            delegate_.GetActions());

  // Set OOBE to be incomplete again and send a wake notification. This should
  // turn on the display. Now set OOBE to be complete and trigger default
  // timeouts, this should result in system suspend.
  delegate_.set_oobe_completed(false);
  controller_.HandleWakeNotification();
  EXPECT_EQ(JoinActions(kScreenUndim, kScreenOn, nullptr),
            delegate_.GetActions());
  delegate_.set_oobe_completed(true);
  ASSERT_TRUE(TriggerDefaultAcTimeouts());
  EXPECT_EQ(JoinActions(kScreenDim, kScreenOff, kSuspendIdle, nullptr),
            delegate_.GetActions());
}

// Tests that the disable-idle-suspend pref is honored and overrides policies.
TEST_F(StateControllerTest, DisableIdleSuspend) {
  default_disable_idle_suspend_ = 1;
  Init();
  controller_.HandleSessionStateChange(SessionState::STARTED);

  // With the disable-idle-suspend pref set, the system shouldn't suspend
  // when it's idle.
  ASSERT_TRUE(TriggerDefaultAcTimeouts());
  EXPECT_EQ(JoinActions(kScreenDim, kScreenOff, nullptr),
            delegate_.GetActions());

  // Even after explicitly setting a policy to suspend on idle, the system
  // should still stay up.
  PowerManagementPolicy policy;
  policy.set_ac_idle_action(PowerManagementPolicy_Action_SUSPEND);
  controller_.HandlePolicyChange(policy);
  EXPECT_EQ(kNoActions, delegate_.GetActions());

  // Stop-session actions should still be honored.
  policy.set_ac_idle_action(PowerManagementPolicy_Action_STOP_SESSION);
  controller_.HandlePolicyChange(policy);
  EXPECT_EQ(kStopSession, delegate_.GetActions());

  // Shutdown actions should be ignored, though.
  policy.set_ac_idle_action(PowerManagementPolicy_Action_SHUT_DOWN);
  controller_.HandlePolicyChange(policy);
  controller_.HandleSessionStateChange(SessionState::STOPPED);
  EXPECT_EQ(JoinActions(kScreenUndim, kScreenOn, nullptr),
            delegate_.GetActions());
  ASSERT_TRUE(TriggerDefaultAcTimeouts());
  EXPECT_EQ(JoinActions(kScreenDim, kScreenOff, nullptr),
            delegate_.GetActions());

  // Sending a wake notification should turn the screen on. Triggering default
  // timeouts should not suspend the device due to idle suspend being disabled.
  controller_.HandleWakeNotification();
  EXPECT_EQ(JoinActions(kScreenUndim, kScreenOn, nullptr),
            delegate_.GetActions());
  ASSERT_TRUE(TriggerDefaultAcTimeouts());
  EXPECT_EQ(JoinActions(kScreenDim, kScreenOff, nullptr),
            delegate_.GetActions());

  // The controller should watch the pref for changes.  After setting it to
  // 0, the system should shut down due to inactivity.
  controller_.HandleUserActivity();
  EXPECT_EQ(JoinActions(kScreenUndim, kScreenOn, nullptr),
            delegate_.GetActions());
  prefs_.SetInt64(kDisableIdleSuspendPref, 0);
  prefs_.NotifyObservers(kDisableIdleSuspendPref);
  ASSERT_TRUE(TriggerDefaultAcTimeouts());
  EXPECT_EQ(JoinActions(kScreenDim, kScreenOff, kShutDown, nullptr),
            delegate_.GetActions());
}

// Tests that the factory-mode pref is honored and overrides policies.
TEST_F(StateControllerTest, FactoryMode) {
  default_factory_mode_ = 1;
  Init();
  controller_.HandleSessionStateChange(SessionState::STARTED);

  // Turn on the smartdim request.
  dbus_wrapper_.NotifyServiceAvailable(ml_decision_proxy_, true);

  // With the factory-mode pref set, the system shouldn't have any actions
  // scheduled, and powerd shouldn't request smartdim decision.
  ASSERT_TRUE(AdvanceTimeAndTriggerTimeout(default_ac_suspend_delay_));
  EXPECT_EQ(kNoActions, delegate_.GetActions());
  EXPECT_EQ("", GetDBusMethodCalls());
  EXPECT_FALSE(controller_.ShouldRequestDimDeferSuggestion(now_));

  // Closing the lid shouldn't do anything.
  controller_.HandleLidStateChange(LidState::CLOSED);
  EXPECT_EQ(kNoActions, delegate_.GetActions());

  // Policy-supplied settings should also be overridden.
  PowerManagementPolicy policy;
  policy.mutable_ac_delays()->set_screen_off_ms(
      default_ac_screen_off_delay_.InMilliseconds());
  policy.mutable_ac_delays()->set_screen_lock_ms(
      default_ac_screen_off_delay_.InMilliseconds());
  policy.mutable_ac_delays()->set_idle_ms(
      default_ac_suspend_delay_.InMilliseconds());
  policy.set_ac_idle_action(PowerManagementPolicy_Action_SUSPEND);
  policy.set_lid_closed_action(PowerManagementPolicy_Action_SUSPEND);
  controller_.HandlePolicyChange(policy);
  EXPECT_EQ(kNoActions, delegate_.GetActions());
}

// Test that tablet mode events are treated as user activity.
TEST_F(StateControllerTest, TreatTabletModeChangeAsUserActivity) {
  Init();
  ASSERT_TRUE(StepTimeAndTriggerTimeout(default_ac_screen_dim_delay_));
  ASSERT_TRUE(StepTimeAndTriggerTimeout(default_ac_screen_off_delay_));
  ASSERT_EQ(JoinActions(kScreenDim, kScreenOff, nullptr),
            delegate_.GetActions());
  controller_.HandleTabletModeChange(TabletMode::ON);
  EXPECT_EQ(JoinActions(kScreenUndim, kScreenOn, nullptr),
            delegate_.GetActions());

  ResetLastStepDelay();
  ASSERT_TRUE(StepTimeAndTriggerTimeout(default_ac_screen_dim_delay_));
  ASSERT_EQ(kScreenDim, delegate_.GetActions());
  controller_.HandleTabletModeChange(TabletMode::OFF);
  EXPECT_EQ(kScreenUndim, delegate_.GetActions());
}

// Tests that the controller does something reasonable when given delays
// that don't make sense.
TEST_F(StateControllerTest, InvalidDelays) {
  // The dim delay should be less than the off delay, which should be less
  // than the idle delay.  All of those constraints are violated here, so
  // all of the other delays should be capped to the idle delay.
  default_ac_screen_dim_delay_ = base::Seconds(120);
  default_ac_screen_off_delay_ = base::Seconds(110);
  default_ac_suspend_delay_ = base::Seconds(100);
  Init();
  ASSERT_TRUE(AdvanceTimeAndTriggerTimeout(default_ac_suspend_delay_));
  EXPECT_EQ(JoinActions(kScreenDim, kScreenOff, kSuspendIdle, nullptr),
            delegate_.GetActions());

  // Policy delays should also be cleaned up.
  const base::TimeDelta kDimDelay = base::Seconds(70);
  const base::TimeDelta kOffDelay = base::Seconds(50);
  const base::TimeDelta kLockDelay = base::Seconds(80);
  const base::TimeDelta kIdleDelay = base::Seconds(60);

  PowerManagementPolicy policy;
  policy.mutable_ac_delays()->set_screen_dim_ms(kDimDelay.InMilliseconds());
  policy.mutable_ac_delays()->set_screen_off_ms(kOffDelay.InMilliseconds());
  policy.mutable_ac_delays()->set_screen_lock_ms(kLockDelay.InMilliseconds());
  policy.mutable_ac_delays()->set_idle_ms(kIdleDelay.InMilliseconds());
  controller_.HandlePolicyChange(policy);

  // The screen-dim delay should be capped to the screen-off delay, while
  // the screen-lock delay should be ignored since it extends beyond the
  // suspend delay.
  controller_.HandleResume(LidState::NOT_PRESENT);
  EXPECT_EQ(JoinActions(kScreenUndim, kScreenOn, nullptr),
            delegate_.GetActions());
  ResetLastStepDelay();
  ASSERT_TRUE(StepTimeAndTriggerTimeout(kOffDelay));
  EXPECT_EQ(JoinActions(kScreenDim, kScreenOff, nullptr),
            delegate_.GetActions());
  ASSERT_TRUE(StepTimeAndTriggerTimeout(kIdleDelay));
  EXPECT_EQ(kSuspendIdle, delegate_.GetActions());
}

// Tests that the controller cues the delegate to report metrics when user
// activity is observed.
TEST_F(StateControllerTest, ReportMetrics) {
  delegate_.set_record_metrics_actions(true);
  Init();

  // Various events considered to represent user activity (direct activity,
  // power source changes, presentation mode, etc.) should all trigger
  // metrics.
  controller_.HandleUserActivity();
  EXPECT_EQ(kReportUserActivityMetrics, delegate_.GetActions());
  ASSERT_TRUE(AdvanceTimeAndTriggerTimeout(default_ac_screen_dim_delay_));
  EXPECT_EQ(kScreenDim, delegate_.GetActions());
  controller_.HandlePowerSourceChange(PowerSource::BATTERY);
  EXPECT_EQ(JoinActions(kReportUserActivityMetrics, kScreenUndim, nullptr),
            delegate_.GetActions());
  AdvanceTime(default_ac_screen_dim_delay_ / 2);
  controller_.HandleDisplayModeChange(DisplayMode::PRESENTATION);
  EXPECT_EQ(kReportUserActivityMetrics, delegate_.GetActions());
}

// Tests that we avoid suspending while headphones are connected when so
// requested.
TEST_F(StateControllerTest, AvoidSuspendForHeadphoneJack) {
  default_avoid_suspend_when_headphone_jack_plugged_ = 1;
  Init();

  // With headphones connected, we shouldn't suspend.
  delegate_.set_headphone_jack_plugged(true);
  ASSERT_TRUE(TriggerDefaultAcTimeouts());
  EXPECT_EQ(JoinActions(kScreenDim, kScreenOff, nullptr),
            delegate_.GetActions());

  // A wake notification should turn the screen on but a timeout still shouldn't
  // suspend the device.
  controller_.HandleWakeNotification();
  EXPECT_EQ(JoinActions(kScreenUndim, kScreenOn, nullptr),
            delegate_.GetActions());
  ASSERT_TRUE(TriggerDefaultAcTimeouts());
  EXPECT_EQ(JoinActions(kScreenDim, kScreenOff, nullptr),
            delegate_.GetActions());

  // Without headphones, we should.
  delegate_.set_headphone_jack_plugged(false);
  controller_.HandleUserActivity();
  EXPECT_EQ(JoinActions(kScreenUndim, kScreenOn, nullptr),
            delegate_.GetActions());
  ASSERT_TRUE(TriggerDefaultAcTimeouts());
  EXPECT_EQ(JoinActions(kScreenDim, kScreenOff, kSuspendIdle, nullptr),
            delegate_.GetActions());

  // Non-suspend actions should still be performed while headphones are
  // connected.
  controller_.HandleResume(LidState::NOT_PRESENT);
  delegate_.set_headphone_jack_plugged(true);
  EXPECT_EQ(JoinActions(kScreenUndim, kScreenOn, nullptr),
            delegate_.GetActions());
  PowerManagementPolicy policy;
  policy.set_ac_idle_action(PowerManagementPolicy_Action_SHUT_DOWN);
  controller_.HandlePolicyChange(policy);
  EXPECT_EQ(kNoActions, delegate_.GetActions());
  ASSERT_TRUE(TriggerDefaultAcTimeouts());
  EXPECT_EQ(JoinActions(kScreenDim, kScreenOff, kShutDown, nullptr),
            delegate_.GetActions());
}

// Tests that the controller handles being woken from idle-suspend by a
// lid-close event (http://crosbug.com/38011).
TEST_F(StateControllerTest, LidCloseAfterIdleSuspend) {
  Init();
  PowerManagementPolicy policy;
  ASSERT_TRUE(TriggerDefaultAcTimeouts());
  EXPECT_EQ(JoinActions(kScreenDim, kScreenOff, kSuspendIdle, nullptr),
            delegate_.GetActions());

  policy.set_ac_idle_action(PowerManagementPolicy_Action_DO_NOTHING);
  controller_.HandlePolicyChange(policy);
  // Close the lid, which may wake the system.  The controller should
  // re-suspend immediately after it receives the lid-closed event, without
  // turning the screen back on.
  controller_.HandleResume(LidState::CLOSED);
  EXPECT_TRUE(test_api_.TriggerWaitForExternalDisplayTimeout());
  EXPECT_EQ(kSuspendLidClosed, delegate_.GetActions());
}

// Tests that the controller resuspends after |KResuspendOnClosedLidTimeout| on
// resuming with closed lid from suspend-from-lid-closed. Happens when the lid
// is opened and closed so quickly that no events are generated
// (http://crosbug.com/p/17499).
TEST_F(StateControllerTest, ResuspendAfterLidOpenAndClose) {
  Init();
  controller_.HandleLidStateChange(LidState::CLOSED);
  EXPECT_EQ(kSuspendLidClosed, delegate_.GetActions());

  // The lid-closed action should be repeated after
  // |KResuspendOnClosedLidTimeout| if the lid is still closed when the system
  // resumes and powerd did not receive any display mode change notification in
  // the mean time.
  controller_.HandleResume(LidState::CLOSED);
  EXPECT_TRUE(test_api_.TriggerWaitForExternalDisplayTimeout());

  EXPECT_EQ(kSuspendLidClosed, delegate_.GetActions());
}

// Tests that delays function as expected on a system that lacks a lid and
// that resume is treated as user activity.
TEST_F(StateControllerTest, LidNotPresent) {
  initial_lid_state_ = LidState::NOT_PRESENT;
  Init();
  ASSERT_TRUE(TriggerDefaultAcTimeouts());
  EXPECT_EQ(JoinActions(kScreenDim, kScreenOff, kSuspendIdle, nullptr),
            delegate_.GetActions());
  controller_.HandleResume(LidState::NOT_PRESENT);
  EXPECT_EQ(JoinActions(kScreenUndim, kScreenOn, nullptr),
            delegate_.GetActions());
}

// Tests that the system doesn't suspend while an update is being applied.
TEST_F(StateControllerTest, AvoidSuspendDuringSystemUpdate) {
  Init();

  // When update_engine comes up, make it report that an update is being
  // applied.  The screen should dim and be turned off, but the system should
  // stay awake.
  update_engine_operation_ = update_engine::Operation::DOWNLOADING;
  dbus_wrapper_.NotifyServiceAvailable(update_engine_proxy_, true);
  ASSERT_TRUE(TriggerDefaultAcTimeouts());
  EXPECT_EQ(JoinActions(kScreenDim, kScreenOff, nullptr),
            delegate_.GetActions());

  // When the update has been applied, the system should suspend immediately.
  EmitStatusUpdateSignal(update_engine::Operation::UPDATED_NEED_REBOOT);
  EXPECT_EQ(kSuspendIdle, delegate_.GetActions());

  // Resume the system and announce another update.
  controller_.HandleResume(LidState::OPEN);
  controller_.HandleUserActivity();
  EXPECT_EQ(JoinActions(kScreenUndim, kScreenOn, nullptr),
            delegate_.GetActions());
  EmitStatusUpdateSignal(update_engine::Operation::FINALIZING);

  // Closing the lid should still suspend.
  controller_.HandleLidStateChange(LidState::CLOSED);
  EXPECT_EQ(kSuspendLidClosed, delegate_.GetActions());

  // Step through all of the timeouts again.
  controller_.HandleResume(LidState::CLOSED);
  controller_.HandleLidStateChange(LidState::OPEN);
  controller_.HandleUserActivity();
  ASSERT_TRUE(TriggerDefaultAcTimeouts());
  EXPECT_EQ(JoinActions(kScreenDim, kScreenOff, nullptr),
            delegate_.GetActions());

  // The system should also suspend immediately after transitioning from
  // the "updating" state back to "idle" (i.e. the update was unsuccessful).
  EmitStatusUpdateSignal(update_engine::Operation::IDLE);
  EXPECT_EQ(kSuspendIdle, delegate_.GetActions());
  controller_.HandleResume(LidState::OPEN);
  controller_.HandleUserActivity();
  EXPECT_EQ(JoinActions(kScreenUndim, kScreenOn, nullptr),
            delegate_.GetActions());

  // If the idle action is changed to log the user out instead of
  // suspending or shutting down, it should still be performed while an
  // update is in-progress.
  PowerManagementPolicy policy;
  policy.set_ac_idle_action(PowerManagementPolicy_Action_STOP_SESSION);
  controller_.HandlePolicyChange(policy);
  EmitStatusUpdateSignal(update_engine::Operation::DOWNLOADING);
  ASSERT_TRUE(TriggerDefaultAcTimeouts());
  EXPECT_EQ(JoinActions(kScreenDim, kScreenOff, kStopSession, nullptr),
            delegate_.GetActions());
}

// Tests that idle warnings are emitted as requested.
TEST_F(StateControllerTest, IdleWarnings) {
  Init();

  const base::TimeDelta kIdleWarningDelay = base::Seconds(50);
  const base::TimeDelta kIdleDelay = base::Seconds(60);
  const base::TimeDelta kHalfInterval = (kIdleDelay - kIdleWarningDelay) / 2;

  PowerManagementPolicy policy;
  policy.mutable_ac_delays()->set_screen_dim_ms(0);
  policy.mutable_ac_delays()->set_screen_off_ms(0);
  policy.mutable_ac_delays()->set_screen_lock_ms(0);
  policy.mutable_ac_delays()->set_idle_warning_ms(
      kIdleWarningDelay.InMilliseconds());
  policy.mutable_ac_delays()->set_idle_ms(kIdleDelay.InMilliseconds());
  policy.set_ac_idle_action(PowerManagementPolicy_Action_STOP_SESSION);
  controller_.HandlePolicyChange(policy);

  // The idle-action-imminent notification should be sent at the requested
  // time.
  ASSERT_TRUE(StepTimeAndTriggerTimeout(kIdleWarningDelay));
  EXPECT_EQ(GetIdleActionImminentString(kIdleDelay - kIdleWarningDelay),
            GetDBusSignals(SignalType::ACTIONS));
  ASSERT_TRUE(StepTimeAndTriggerTimeout(kIdleDelay));
  EXPECT_EQ(kStopSession, delegate_.GetActions());

  // The idle-action-deferred notification shouldn't be sent when exiting
  // the inactive state after the idle action has been performed.
  controller_.HandleUserActivity();
  EXPECT_EQ(kNoActions, delegate_.GetActions());

  // If the controller exits the inactive state before the idle action is
  // performed, an idle-action-deferred notification should be sent.
  ResetLastStepDelay();
  ASSERT_TRUE(StepTimeAndTriggerTimeout(kIdleWarningDelay));
  EXPECT_EQ(GetIdleActionImminentString(kIdleDelay - kIdleWarningDelay),
            GetDBusSignals(SignalType::ACTIONS));
  AdvanceTime(kHalfInterval);
  controller_.HandleUserActivity();
  EXPECT_EQ(kIdleActionDeferredSignal, GetDBusSignals(SignalType::ACTIONS));

  // Let the warning fire again.
  ResetLastStepDelay();
  ASSERT_TRUE(StepTimeAndTriggerTimeout(kIdleWarningDelay));
  EXPECT_EQ(GetIdleActionImminentString(kIdleDelay - kIdleWarningDelay),
            GetDBusSignals(SignalType::ACTIONS));

  // Increase the warning delay and check that the deferred notification is
  // sent.
  policy.mutable_ac_delays()->set_idle_warning_ms(
      (kIdleWarningDelay + kHalfInterval).InMilliseconds());
  EXPECT_EQ("", GetDBusSignals(SignalType::ACTIONS));
  controller_.HandlePolicyChange(policy);
  EXPECT_EQ(kIdleActionDeferredSignal, GetDBusSignals(SignalType::ACTIONS));

  // The warning should be sent again when its new delay is reached, and
  // the idle action should be performed at the usual time.
  ASSERT_TRUE(AdvanceTimeAndTriggerTimeout(kHalfInterval));
  EXPECT_EQ(GetIdleActionImminentString(kIdleDelay -
                                        (kIdleWarningDelay + kHalfInterval)),
            GetDBusSignals(SignalType::ACTIONS));
  ASSERT_TRUE(AdvanceTimeAndTriggerTimeout(kHalfInterval));
  EXPECT_EQ(kStopSession, delegate_.GetActions());

  // If the warning delay is cleared after the idle-imminent signal has been
  // sent, an idle-deferred signal should be sent.
  ResetLastStepDelay();
  policy.mutable_ac_delays()->set_idle_warning_ms(
      kIdleWarningDelay.InMilliseconds());
  controller_.HandlePolicyChange(policy);
  EXPECT_EQ(kNoActions, delegate_.GetActions());
  controller_.HandleUserActivity();
  ASSERT_TRUE(StepTimeAndTriggerTimeout(kIdleWarningDelay));
  EXPECT_EQ(GetIdleActionImminentString(kIdleDelay - kIdleWarningDelay),
            GetDBusSignals(SignalType::ACTIONS));
  policy.mutable_ac_delays()->set_idle_warning_ms(0);
  controller_.HandlePolicyChange(policy);
  EXPECT_EQ(kIdleActionDeferredSignal, GetDBusSignals(SignalType::ACTIONS));

  // The same signals should be sent again if the delay is added and removed
  // without the time advancing.
  policy.mutable_ac_delays()->set_idle_warning_ms(
      kIdleWarningDelay.InMilliseconds());
  controller_.HandlePolicyChange(policy);
  EXPECT_EQ(GetIdleActionImminentString(kIdleDelay - kIdleWarningDelay),
            GetDBusSignals(SignalType::ACTIONS));
  policy.mutable_ac_delays()->set_idle_warning_ms(0);
  controller_.HandlePolicyChange(policy);
  EXPECT_EQ(kIdleActionDeferredSignal, GetDBusSignals(SignalType::ACTIONS));

  // Setting the idle action to "do nothing" should send an idle-deferred
  // message if idle-imminent was already sent.
  controller_.HandleUserActivity();
  policy.mutable_ac_delays()->set_idle_warning_ms(
      kIdleWarningDelay.InMilliseconds());
  controller_.HandlePolicyChange(policy);
  EXPECT_EQ(kNoActions, delegate_.GetActions());
  ResetLastStepDelay();
  ASSERT_TRUE(StepTimeAndTriggerTimeout(kIdleWarningDelay));
  EXPECT_EQ(GetIdleActionImminentString(kIdleDelay - kIdleWarningDelay),
            GetDBusSignals(SignalType::ACTIONS));
  policy.set_ac_idle_action(PowerManagementPolicy_Action_DO_NOTHING);
  controller_.HandlePolicyChange(policy);
  EXPECT_EQ(kIdleActionDeferredSignal, GetDBusSignals(SignalType::ACTIONS));

  // Setting the idle action back to "stop session" should cause
  // idle-imminent to get sent again.
  policy.set_ac_idle_action(PowerManagementPolicy_Action_STOP_SESSION);
  controller_.HandlePolicyChange(policy);
  EXPECT_EQ(GetIdleActionImminentString(kIdleDelay - kIdleWarningDelay),
            GetDBusSignals(SignalType::ACTIONS));
  policy.set_ac_idle_action(PowerManagementPolicy_Action_DO_NOTHING);
  controller_.HandlePolicyChange(policy);
  EXPECT_EQ(kIdleActionDeferredSignal, GetDBusSignals(SignalType::ACTIONS));
  ASSERT_TRUE(StepTimeAndTriggerTimeout(kIdleDelay));
  EXPECT_EQ("", GetDBusSignals(SignalType::ACTIONS));
  EXPECT_EQ(kNoActions, delegate_.GetActions());

  // The idle-imminent message shouldn't get sent in the first place when
  // the action is unset.
  controller_.HandleUserActivity();
  EXPECT_EQ(kNoActions, delegate_.GetActions());
  ASSERT_TRUE(AdvanceTimeAndTriggerTimeout(kIdleWarningDelay));
  EXPECT_EQ(kNoActions, delegate_.GetActions());
  controller_.HandleUserActivity();
  EXPECT_EQ(kNoActions, delegate_.GetActions());

  // If an action is set after the idle delay has been reached,
  // idle-imminent should be sent immediately and the action should
  // be performed.
  controller_.HandleUserActivity();
  ResetLastStepDelay();
  ASSERT_TRUE(StepTimeAndTriggerTimeout(kIdleWarningDelay));
  EXPECT_EQ(kNoActions, delegate_.GetActions());
  ASSERT_TRUE(StepTimeAndTriggerTimeout(kIdleDelay));
  EXPECT_EQ(kNoActions, delegate_.GetActions());
  policy.set_ac_idle_action(PowerManagementPolicy_Action_STOP_SESSION);
  controller_.HandlePolicyChange(policy);
  EXPECT_EQ(GetIdleActionImminentString(base::TimeDelta()),
            GetDBusSignals(SignalType::ACTIONS));
  EXPECT_EQ(kStopSession, delegate_.GetActions());

  // Let idle-imminent get sent and then increase the idle delay. idle-imminent
  // should be sent again immediately with an updated time-until-idle-action.
  controller_.HandleUserActivity();
  EXPECT_EQ(kNoActions, delegate_.GetActions());
  ResetLastStepDelay();
  ASSERT_TRUE(StepTimeAndTriggerTimeout(kIdleWarningDelay));
  EXPECT_EQ(GetIdleActionImminentString(kIdleDelay - kIdleWarningDelay),
            GetDBusSignals(SignalType::ACTIONS));
  policy.mutable_ac_delays()->set_idle_ms(2 * kIdleDelay.InMilliseconds());
  controller_.HandlePolicyChange(policy);
  EXPECT_EQ(GetIdleActionImminentString(2 * kIdleDelay - kIdleWarningDelay),
            GetDBusSignals(SignalType::ACTIONS));
}

// Tests that wake locks reported via policy messages defer actions
// appropriately. Use HandleUserActivity to turn the screen on.
TEST_F(StateControllerTest, WakeLocksWithUserActivity) {
  Init();

  const base::TimeDelta kDimDelay = base::Seconds(60);
  const base::TimeDelta kOffDelay = base::Seconds(70);
  const base::TimeDelta kLockDelay = base::Seconds(80);
  const base::TimeDelta kIdleDelay = base::Seconds(90);

  PowerManagementPolicy policy;
  policy.mutable_ac_delays()->set_screen_dim_ms(kDimDelay.InMilliseconds());
  policy.mutable_ac_delays()->set_screen_off_ms(kOffDelay.InMilliseconds());
  policy.mutable_ac_delays()->set_screen_lock_ms(kLockDelay.InMilliseconds());
  policy.mutable_ac_delays()->set_idle_ms(kIdleDelay.InMilliseconds());
  policy.set_ac_idle_action(PowerManagementPolicy_Action_SUSPEND);
  policy.set_system_wake_lock(true);
  controller_.HandlePolicyChange(policy);

  // Step the time forward and check that the system doesn't suspend.
  ASSERT_TRUE(StepTimeAndTriggerTimeout(kDimDelay));
  EXPECT_EQ(kScreenDim, delegate_.GetActions());
  ASSERT_TRUE(StepTimeAndTriggerTimeout(kOffDelay));
  EXPECT_EQ(kScreenOff, delegate_.GetActions());
  ASSERT_TRUE(StepTimeAndTriggerTimeout(kLockDelay));
  EXPECT_EQ(kScreenLock, delegate_.GetActions());
  EXPECT_TRUE(test_api_.action_timer_time().is_null());

  // Sending an updated policy with a on-but-dimmed wake lock should turn the
  // screen on immediately but leave it dimmed.
  policy.set_dim_wake_lock(true);
  controller_.HandlePolicyChange(policy);
  EXPECT_EQ(kScreenOn, delegate_.GetActions());

  // A full-brightness wake lock should undim the screen.
  policy.set_screen_wake_lock(true);
  controller_.HandlePolicyChange(policy);
  EXPECT_EQ(kScreenUndim, delegate_.GetActions());
  controller_.HandleUserActivity();
  EXPECT_EQ("", delegate_.GetActions());

  // Set a dim wake lock. The screen should be dimmed but no further actions
  // should be taken.
  policy.set_screen_wake_lock(false);
  policy.set_dim_wake_lock(true);
  policy.set_system_wake_lock(false);
  controller_.HandlePolicyChange(policy);
  ASSERT_TRUE(AdvanceTimeAndTriggerTimeout(kDimDelay));
  EXPECT_EQ(kScreenDim, delegate_.GetActions());
  EXPECT_TRUE(test_api_.action_timer_time().is_null());
  controller_.HandleUserActivity();
  EXPECT_EQ(kScreenUndim, delegate_.GetActions());

  // Now try the same thing with a full-brightness wake lock. No actions
  // should be scheduled.
  policy.set_screen_wake_lock(true);
  policy.set_dim_wake_lock(false);
  policy.set_system_wake_lock(false);
  controller_.HandlePolicyChange(policy);
  EXPECT_TRUE(test_api_.action_timer_time().is_null());

  // Remove the wake lock and check that the normal actions are performed.
  policy.set_screen_wake_lock(false);
  controller_.HandlePolicyChange(policy);
  ResetLastStepDelay();
  ASSERT_TRUE(StepTimeAndTriggerTimeout(kDimDelay));
  EXPECT_EQ(kScreenDim, delegate_.GetActions());
  ASSERT_TRUE(StepTimeAndTriggerTimeout(kOffDelay));
  EXPECT_EQ(kScreenOff, delegate_.GetActions());
  ASSERT_TRUE(StepTimeAndTriggerTimeout(kLockDelay));
  EXPECT_EQ(kScreenLock, delegate_.GetActions());
  ASSERT_TRUE(StepTimeAndTriggerTimeout(kIdleDelay));
  EXPECT_EQ(kSuspendIdle, delegate_.GetActions());
}

// Tests that wake locks reported via policy messages defer actions
// appropriately. Use HandleWakeNotification to turn the screen on.
TEST_F(StateControllerTest, WakeLocksWithWakeNotification) {
  Init();

  // Set a system wake lock and check that the system turns off the display.
  // Sending a wake notification should undim and turn on the screen.
  PowerManagementPolicy policy;
  policy.set_system_wake_lock(true);
  controller_.HandlePolicyChange(policy);
  ASSERT_TRUE(StepTimeAndTriggerTimeout(default_ac_screen_dim_delay_));
  EXPECT_EQ(kScreenDim, delegate_.GetActions());
  ASSERT_TRUE(StepTimeAndTriggerTimeout(default_ac_screen_off_delay_));
  EXPECT_EQ(kScreenOff, delegate_.GetActions());
  EXPECT_TRUE(test_api_.action_timer_time().is_null());
  controller_.HandleWakeNotification();
  EXPECT_EQ(JoinActions(kScreenUndim, kScreenOn, nullptr),
            delegate_.GetActions());

  // Change the wake lock to be a dim wake lock. Check that the screen dims and
  // doesn't turn off. Sending a wake notification should undim the screen.
  policy.set_system_wake_lock(false);
  policy.set_dim_wake_lock(true);
  controller_.HandlePolicyChange(policy);
  ResetLastStepDelay();
  ASSERT_TRUE(StepTimeAndTriggerTimeout(default_ac_screen_dim_delay_));
  EXPECT_EQ(kScreenDim, delegate_.GetActions());
  EXPECT_TRUE(test_api_.action_timer_time().is_null());
  controller_.HandleWakeNotification();
  EXPECT_EQ(kScreenUndim, delegate_.GetActions());
}

// Tests that the system avoids suspending on lid-closed when an external
// display is connected.
TEST_F(StateControllerTest, DockedMode) {
  Init();

  // Connect an external display and close the lid. The system shouldn't
  // suspend.
  controller_.HandleDisplayModeChange(DisplayMode::PRESENTATION);
  EXPECT_EQ(kNoActions, delegate_.GetActions());
  controller_.HandleLidStateChange(LidState::CLOSED);
  EXPECT_EQ(kNoActions, delegate_.GetActions());

  // Open the lid and check that nothing happens.
  controller_.HandleLidStateChange(LidState::OPEN);
  EXPECT_EQ(kNoActions, delegate_.GetActions());

  // Close the lid again and check that the system suspends immediately
  // after the external display is unplugged.
  controller_.HandleLidStateChange(LidState::CLOSED);
  EXPECT_EQ(kNoActions, delegate_.GetActions());
  controller_.HandleDisplayModeChange(DisplayMode::NORMAL);
  EXPECT_EQ(kSuspendLidClosed, delegate_.GetActions());
}

// Tests that the system recognizes external display connect on resuming with
// lid still closed (crbug.com/786721).
TEST_F(StateControllerTest, ResumeOnExternalDisplayWithLidClosed) {
  Init();

  // Close the lid and let the system suspend.
  controller_.HandleLidStateChange(LidState::CLOSED);
  EXPECT_EQ(kSuspendLidClosed, delegate_.GetActions());
  // Trigger a resume. StateController is expected to wait for
  // |KResuspendOnClosedLidTimeout| before triggering idle or lid closed action
  // again.
  controller_.HandleResume(LidState::CLOSED);
  // Mimic chrome notifying powerd about display mode change.
  controller_.HandleDisplayModeChange(DisplayMode::PRESENTATION);
  // Timer that blocks idle or lid closed action should not be running anymore.
  EXPECT_FALSE(test_api_.TriggerWaitForExternalDisplayTimeout());
  EXPECT_EQ(kNoActions, delegate_.GetActions());
  // Open the lid and check that the internal panels turns back on.
  controller_.HandleLidStateChange(LidState::OPEN);
  EXPECT_EQ(kNoActions, delegate_.GetActions());
}

// Tests that PowerManagementPolicy's
// |user_activity_screen_dim_delay_factor| field is honored.
TEST_F(StateControllerTest, IncreaseDelaysAfterUserActivity) {
  Init();
  controller_.HandleSessionStateChange(SessionState::STARTED);

  // Send a policy where delays are doubled if user activity is observed
  // while the screen is dimmed or soon after it's turned off.
  const base::TimeDelta kDimDelay = base::Seconds(120);
  const base::TimeDelta kOffDelay = base::Seconds(200);
  const base::TimeDelta kLockDelay = base::Seconds(300);
  const base::TimeDelta kIdleWarningDelay = base::Seconds(320);
  const base::TimeDelta kIdleDelay = base::Seconds(330);
  const double kDelayFactor = 2.0;
  PowerManagementPolicy policy;
  policy.mutable_ac_delays()->set_screen_dim_ms(kDimDelay.InMilliseconds());
  policy.mutable_ac_delays()->set_screen_off_ms(kOffDelay.InMilliseconds());
  policy.mutable_ac_delays()->set_screen_lock_ms(kLockDelay.InMilliseconds());
  policy.mutable_ac_delays()->set_idle_warning_ms(
      kIdleWarningDelay.InMilliseconds());
  policy.mutable_ac_delays()->set_idle_ms(kIdleDelay.InMilliseconds());
  policy.set_ac_idle_action(PowerManagementPolicy_Action_SUSPEND);
  policy.set_user_activity_screen_dim_delay_factor(kDelayFactor);
  controller_.HandlePolicyChange(policy);

  // Wait for the screen to dim and then immediately report user activity.
  ASSERT_TRUE(AdvanceTimeAndTriggerTimeout(kDimDelay));
  EXPECT_EQ(kScreenDim, delegate_.GetActions());
  controller_.HandleUserActivity();
  EXPECT_EQ(kScreenUndim, delegate_.GetActions());

  // This should result in the dimming delay being doubled and its distance
  // to all of the other delays being held constant.
  const base::TimeDelta kScaledDimDelay =
      base::Microseconds(kDelayFactor * kDimDelay.InMicrosecondsF());
  ASSERT_TRUE(AdvanceTimeAndTriggerTimeout(kScaledDimDelay));
  EXPECT_EQ(kScreenDim, delegate_.GetActions());
  ASSERT_TRUE(AdvanceTimeAndTriggerTimeout(kOffDelay - kDimDelay));
  EXPECT_EQ(kScreenOff, delegate_.GetActions());
  ASSERT_TRUE(AdvanceTimeAndTriggerTimeout(kLockDelay - kOffDelay));
  EXPECT_EQ(kScreenLock, delegate_.GetActions());
  ASSERT_TRUE(AdvanceTimeAndTriggerTimeout(kIdleWarningDelay - kLockDelay));
  EXPECT_EQ(GetIdleActionImminentString(kIdleDelay - kIdleWarningDelay),
            GetDBusSignals(SignalType::ACTIONS));
  ASSERT_TRUE(AdvanceTimeAndTriggerTimeout(kIdleDelay - kIdleWarningDelay));
  EXPECT_EQ(kSuspendIdle, delegate_.GetActions());

  // Stop the session, which should unscale the delays.  This time, wait
  // for the screen to get turned off and check that the delays are again
  // lengthened after user activity.
  controller_.HandleUserActivity();
  EXPECT_EQ(JoinActions(kScreenUndim, kScreenOn, nullptr),
            delegate_.GetActions());
  controller_.HandleSessionStateChange(SessionState::STOPPED);
  ResetLastStepDelay();
  ASSERT_TRUE(StepTimeAndTriggerTimeout(kDimDelay));
  EXPECT_EQ(kScreenDim, delegate_.GetActions());
  ASSERT_TRUE(StepTimeAndTriggerTimeout(kOffDelay));
  EXPECT_EQ(kScreenOff, delegate_.GetActions());
  controller_.HandleUserActivity();
  EXPECT_EQ(JoinActions(kScreenUndim, kScreenOn, nullptr),
            delegate_.GetActions());
  ASSERT_TRUE(AdvanceTimeAndTriggerTimeout(kScaledDimDelay));
  EXPECT_EQ(kScreenDim, delegate_.GetActions());

  // Start another session (to again unscale the delays).  Let the screen
  // get dimmed and turned off, but wait longer than the threshold before
  // reporting user activity.  The delays should be unchanged.
  controller_.HandleUserActivity();
  EXPECT_EQ(JoinActions(kScreenUndim, nullptr), delegate_.GetActions());
  controller_.HandleSessionStateChange(SessionState::STARTED);
  ResetLastStepDelay();
  ASSERT_TRUE(StepTimeAndTriggerTimeout(kDimDelay));
  EXPECT_EQ(kScreenDim, delegate_.GetActions());
  ASSERT_TRUE(StepTimeAndTriggerTimeout(kOffDelay));
  EXPECT_EQ(kScreenOff, delegate_.GetActions());
  AdvanceTime(
      StateController::kUserActivityAfterScreenOffIncreaseDelaysInterval +
      base::Seconds(1));
  controller_.HandleUserActivity();
  EXPECT_EQ(JoinActions(kScreenUndim, kScreenOn, nullptr),
            delegate_.GetActions());
  ASSERT_TRUE(AdvanceTimeAndTriggerTimeout(kDimDelay));
  EXPECT_EQ(kScreenDim, delegate_.GetActions());

  // Shorten the screen off delay after the screen is already off such that
  // we're now outside the window in which user activity should scale the
  // delays.  The delays should still be scaled.
  controller_.HandleUserActivity();
  EXPECT_EQ(JoinActions(kScreenUndim, nullptr), delegate_.GetActions());
  controller_.HandleSessionStateChange(SessionState::STOPPED);
  ResetLastStepDelay();
  ASSERT_TRUE(StepTimeAndTriggerTimeout(kDimDelay));
  EXPECT_EQ(kScreenDim, delegate_.GetActions());
  ASSERT_TRUE(StepTimeAndTriggerTimeout(kOffDelay));
  EXPECT_EQ(kScreenOff, delegate_.GetActions());
  const base::TimeDelta kShortOffDelay =
      kOffDelay -
      StateController::kUserActivityAfterScreenOffIncreaseDelaysInterval +
      base::Seconds(1);
  policy.mutable_ac_delays()->set_screen_off_ms(
      kShortOffDelay.InMilliseconds());
  controller_.HandlePolicyChange(policy);
  controller_.HandleUserActivity();
  EXPECT_EQ(JoinActions(kScreenUndim, kScreenOn, nullptr),
            delegate_.GetActions());
  ASSERT_TRUE(AdvanceTimeAndTriggerTimeout(kScaledDimDelay));
  EXPECT_EQ(kScreenDim, delegate_.GetActions());
}

// Tests that the system is suspended as soon as the display mode is received if
// the lid is closed at startup (e.g. due to powerd crashing during a suspend
// attempt and getting restarted or the user closing the lid while the system is
// booting).
TEST_F(StateControllerTest, SuspendIfLidClosedAtStartup) {
  // Nothing should happen yet; we need to wait to see if the system is about to
  // go into docked mode.
  initial_lid_state_ = LidState::CLOSED;
  send_initial_display_mode_ = false;
  Init();
  EXPECT_EQ(kNoActions, delegate_.GetActions());

  controller_.HandleDisplayModeChange(DisplayMode::NORMAL);
  EXPECT_EQ(kSuspendLidClosed, delegate_.GetActions());
  EXPECT_FALSE(test_api_.TriggerInitialStateTimeout());
}

// If the lid is already closed at startup but a notification about presentation
// mode is received soon afterwards, the system should go into docked mode
// instead of suspending (http://crbug.com/277091).
TEST_F(StateControllerTest, EnterDockedModeAtStartup) {
  initial_lid_state_ = LidState::CLOSED;
  initial_display_mode_ = DisplayMode::PRESENTATION;
  Init();
  EXPECT_EQ(kNoActions, delegate_.GetActions());
  EXPECT_FALSE(test_api_.TriggerInitialStateTimeout());
}

// If the lid is already closed at startup but a display-mode notification never
// arrives, StateController should give up eventually and just suspend the
// system.
TEST_F(StateControllerTest, TimeOutIfInitialDisplayModeNotReceived) {
  initial_lid_state_ = LidState::CLOSED;
  send_initial_display_mode_ = false;
  Init();
  EXPECT_EQ(kNoActions, delegate_.GetActions());

  EXPECT_TRUE(test_api_.TriggerInitialStateTimeout());
  EXPECT_EQ(kSuspendLidClosed, delegate_.GetActions());
}

// The lid-closed action shouldn't be performed until the initial policy is
// received.
TEST_F(StateControllerTest, WaitForPolicyAtStartup) {
  initial_lid_state_ = LidState::CLOSED;
  send_initial_policy_ = false;
  Init();
  EXPECT_EQ(kNoActions, delegate_.GetActions());

  PowerManagementPolicy policy;
  policy.set_lid_closed_action(PowerManagementPolicy_Action_DO_NOTHING);
  controller_.HandlePolicyChange(policy);
  EXPECT_EQ(kNoActions, delegate_.GetActions());

  policy.set_lid_closed_action(PowerManagementPolicy_Action_SHUT_DOWN);
  controller_.HandlePolicyChange(policy);
  EXPECT_EQ(kShutDown, delegate_.GetActions());
}

// If the initial state timeout occurs before the initial policy is received,
// the default lid-closed action should be performed.
TEST_F(StateControllerTest, TimeOutIfInitialPolicyNotReceived) {
  initial_lid_state_ = LidState::CLOSED;
  send_initial_policy_ = false;
  Init();
  EXPECT_EQ(kNoActions, delegate_.GetActions());

  EXPECT_TRUE(test_api_.TriggerInitialStateTimeout());
  EXPECT_EQ(kSuspendLidClosed, delegate_.GetActions());
}

// Tests that user activity is ignored while the lid is closed. Spurious events
// can apparently be reported as a result of the user closing the lid
// (http://crbug.com/221228).
TEST_F(StateControllerTest, IgnoreUserActivityWhileLidClosed) {
  Init();

  // Wait for the screen to be dimmed and turned off.
  ASSERT_TRUE(StepTimeAndTriggerTimeout(default_ac_screen_dim_delay_));
  ASSERT_TRUE(StepTimeAndTriggerTimeout(default_ac_screen_off_delay_));
  EXPECT_EQ(JoinActions(kScreenDim, kScreenOff, nullptr),
            delegate_.GetActions());

  // User activity received while the lid is closed should be ignored.
  controller_.HandleLidStateChange(LidState::CLOSED);
  EXPECT_EQ(kSuspendLidClosed, delegate_.GetActions());
  controller_.HandleUserActivity();
  EXPECT_EQ(kNoActions, delegate_.GetActions());

  // Resume and go through the same sequence as before, but this time while
  // presenting so that docked mode will be used.
  controller_.HandleResume(LidState::OPEN);
  EXPECT_EQ(JoinActions(kScreenUndim, kScreenOn, nullptr),
            delegate_.GetActions());
  controller_.HandleLidStateChange(LidState::OPEN);
  controller_.HandleDisplayModeChange(DisplayMode::PRESENTATION);
  ResetLastStepDelay();
  ASSERT_TRUE(StepTimeAndTriggerTimeout(default_ac_screen_dim_delay_));
  ASSERT_TRUE(StepTimeAndTriggerTimeout(default_ac_screen_off_delay_));
  EXPECT_EQ(JoinActions(kScreenDim, kScreenOff, nullptr),
            delegate_.GetActions());

  // User activity while docked should turn the screen back on and undim it.
  controller_.HandleLidStateChange(LidState::CLOSED);
  EXPECT_EQ(kNoActions, delegate_.GetActions());
  controller_.HandleUserActivity();
  EXPECT_EQ(JoinActions(kScreenUndim, kScreenOn, nullptr),
            delegate_.GetActions());
}

// Tests that a wake notification is ignored while the lid is closed. Spurious
// events can apparently be reported as a result of the user closing the
// lid (http://crbug.com/221228).
TEST_F(StateControllerTest, IgnoreWakeNotificationWhileLidClosed) {
  Init();

  // Wait for the screen to be dimmed and turned off.
  ASSERT_TRUE(StepTimeAndTriggerTimeout(default_ac_screen_dim_delay_));
  ASSERT_TRUE(StepTimeAndTriggerTimeout(default_ac_screen_off_delay_));
  EXPECT_EQ(JoinActions(kScreenDim, kScreenOff, nullptr),
            delegate_.GetActions());

  // A wake notification received while the lid is closed should be ignored.
  controller_.HandleLidStateChange(LidState::CLOSED);
  EXPECT_EQ(kSuspendLidClosed, delegate_.GetActions());
  controller_.HandleWakeNotification();
  EXPECT_EQ(kNoActions, delegate_.GetActions());

  // Resume and go through the same sequence as before, but this time while
  // presenting so that docked mode will be used.
  controller_.HandleResume(LidState::OPEN);
  EXPECT_EQ(JoinActions(kScreenUndim, kScreenOn, nullptr),
            delegate_.GetActions());
  controller_.HandleLidStateChange(LidState::OPEN);
  controller_.HandleDisplayModeChange(DisplayMode::PRESENTATION);
  ResetLastStepDelay();
  ASSERT_TRUE(StepTimeAndTriggerTimeout(default_ac_screen_dim_delay_));
  ASSERT_TRUE(StepTimeAndTriggerTimeout(default_ac_screen_off_delay_));
  EXPECT_EQ(JoinActions(kScreenDim, kScreenOff, nullptr),
            delegate_.GetActions());

  // A wake notification while docked should turn the screen back on and undim
  // it.
  controller_.HandleLidStateChange(LidState::CLOSED);
  EXPECT_EQ(kNoActions, delegate_.GetActions());
  controller_.HandleWakeNotification();
  EXPECT_EQ(JoinActions(kScreenUndim, kScreenOn, nullptr),
            delegate_.GetActions());
}

// Tests that the timer doesn't run at all when all delays are disabled or
// blocked: http://crbug.com/308419
TEST_F(StateControllerTest, AudioDelay) {
  Init();

  // Make "now" advance if GetCurrentTime() is called multiple times.
  test_api_.clock()->set_time_step_for_testing(base::Milliseconds(1));

  const base::TimeDelta kIdleDelay = base::Seconds(600);
  PowerManagementPolicy policy;
  policy.mutable_ac_delays()->set_screen_dim_ms(0);
  policy.mutable_ac_delays()->set_screen_off_ms(0);
  policy.mutable_ac_delays()->set_screen_lock_ms(0);
  policy.mutable_ac_delays()->set_idle_ms(kIdleDelay.InMilliseconds());
  controller_.HandlePolicyChange(policy);

  // When no delays are active, the timer shouldn't run.
  controller_.HandleAudioStateChange(true);
  EXPECT_TRUE(test_api_.action_timer_time().is_null());
}

// Tests that when |wait_for_initial_user_activity| policy field is set,
// inactivity-triggered actions are deferred until user activity is reported.
TEST_F(StateControllerTest, WaitForInitialUserActivity) {
  Init();
  controller_.HandleSessionStateChange(SessionState::STARTED);

  const base::TimeDelta kWarningDelay = base::Seconds(585);
  const base::TimeDelta kIdleDelay = base::Seconds(600);

  PowerManagementPolicy policy;
  policy.mutable_ac_delays()->set_screen_dim_ms(0);
  policy.mutable_ac_delays()->set_screen_off_ms(0);
  policy.mutable_ac_delays()->set_screen_lock_ms(0);
  policy.mutable_ac_delays()->set_idle_warning_ms(
      kWarningDelay.InMilliseconds());
  policy.mutable_ac_delays()->set_idle_ms(kIdleDelay.InMilliseconds());
  policy.set_ac_idle_action(PowerManagementPolicy_Action_STOP_SESSION);
  policy.set_wait_for_initial_user_activity(true);
  controller_.HandlePolicyChange(policy);

  // Before user activity is seen, the timeout should be scheduled for the
  // soonest-occurring delay (i.e. the idle warning), but when it fires, no
  // actions should be performed and the timeout should just be scheduled again.
  EXPECT_EQ(kNoActions, delegate_.GetActions());
  ASSERT_TRUE(AdvanceTimeAndTriggerTimeout(kWarningDelay));
  EXPECT_EQ(kNoActions, delegate_.GetActions());
  ASSERT_TRUE(AdvanceTimeAndTriggerTimeout(kWarningDelay));
  EXPECT_EQ(kNoActions, delegate_.GetActions());

  // After user activity is seen, the delays should take effect.
  controller_.HandleUserActivity();
  EXPECT_EQ(kNoActions, delegate_.GetActions());
  ResetLastStepDelay();
  ASSERT_TRUE(StepTimeAndTriggerTimeout(kWarningDelay));
  EXPECT_EQ(GetIdleActionImminentString(kIdleDelay - kWarningDelay),
            GetDBusSignals(SignalType::ACTIONS));
  ASSERT_TRUE(StepTimeAndTriggerTimeout(kIdleDelay));
  EXPECT_EQ(kStopSession, delegate_.GetActions());

  // Restart the session and check that the actions are avoided again.
  // User activity reported while the session is stopped should be disregarded.
  controller_.HandleSessionStateChange(SessionState::STOPPED);
  controller_.HandleUserActivity();
  controller_.HandleSessionStateChange(SessionState::STARTED);
  EXPECT_EQ(kNoActions, delegate_.GetActions());
  ASSERT_TRUE(AdvanceTimeAndTriggerTimeout(kWarningDelay));
  EXPECT_EQ(kNoActions, delegate_.GetActions());

  // User activity should again result in the delays taking effect.
  controller_.HandleUserActivity();
  ResetLastStepDelay();
  EXPECT_EQ(kNoActions, delegate_.GetActions());
  ASSERT_TRUE(StepTimeAndTriggerTimeout(kWarningDelay));
  EXPECT_EQ(GetIdleActionImminentString(kIdleDelay - kWarningDelay),
            GetDBusSignals(SignalType::ACTIONS));
  ASSERT_TRUE(StepTimeAndTriggerTimeout(kIdleDelay));
  EXPECT_EQ(kStopSession, delegate_.GetActions());

  // User activity that is seen before the |wait| field is set should still be
  // honored and result in the delays taking effect.
  controller_.HandleSessionStateChange(SessionState::STOPPED);
  controller_.HandlePolicyChange(PowerManagementPolicy());
  controller_.HandleSessionStateChange(SessionState::STARTED);
  controller_.HandleUserActivity();
  controller_.HandlePolicyChange(policy);
  ResetLastStepDelay();
  EXPECT_EQ(kNoActions, delegate_.GetActions());
  ASSERT_TRUE(StepTimeAndTriggerTimeout(kWarningDelay));
  EXPECT_EQ(GetIdleActionImminentString(kIdleDelay - kWarningDelay),
            GetDBusSignals(SignalType::ACTIONS));
  ASSERT_TRUE(StepTimeAndTriggerTimeout(kIdleDelay));
  EXPECT_EQ(kStopSession, delegate_.GetActions());

  // If |wait| is set after the warning has been sent, the idle-deferred signal
  // should be emitted immediately.
  PowerManagementPolicy policy_without_wait = policy;
  policy_without_wait.set_wait_for_initial_user_activity(false);
  controller_.HandlePolicyChange(policy_without_wait);
  controller_.HandleSessionStateChange(SessionState::STOPPED);
  controller_.HandleSessionStateChange(SessionState::STARTED);
  ASSERT_TRUE(AdvanceTimeAndTriggerTimeout(kWarningDelay));
  EXPECT_EQ(GetIdleActionImminentString(kIdleDelay - kWarningDelay),
            GetDBusSignals(SignalType::ACTIONS));
  controller_.HandlePolicyChange(policy);
  EXPECT_EQ(kIdleActionDeferredSignal, GetDBusSignals(SignalType::ACTIONS));

  // |wait| should have no effect when no session is ongoing.
  controller_.HandleSessionStateChange(SessionState::STOPPED);
  ASSERT_TRUE(AdvanceTimeAndTriggerTimeout(kWarningDelay));
}

// Tests that idle and lid-closed "shut down" actions are overridden to instead
// suspend when the TPM dictionary-attack count is high.
TEST_F(StateControllerTest, SuspendInsteadOfShuttingDownForTpmCounter) {
  const base::TimeDelta kIdleDelay = base::Seconds(300);
  initial_policy_.mutable_ac_delays()->set_screen_dim_ms(0);
  initial_policy_.mutable_ac_delays()->set_screen_off_ms(0);
  initial_policy_.mutable_ac_delays()->set_screen_lock_ms(0);
  initial_policy_.mutable_ac_delays()->set_idle_ms(kIdleDelay.InMilliseconds());
  initial_policy_.set_ac_idle_action(PowerManagementPolicy_Action_SHUT_DOWN);
  initial_policy_.set_lid_closed_action(PowerManagementPolicy_Action_SHUT_DOWN);

  const int kThreshold = 10;
  prefs_.SetInt64(kTpmCounterSuspendThresholdPref, kThreshold);
  Init();

  // With the count below the threshold, the "shut down" lid-closed action
  // should be honored.
  controller_.HandleTpmStatus(kThreshold - 1);
  controller_.HandleLidStateChange(LidState::CLOSED);
  EXPECT_EQ(kShutDown, delegate_.GetActions());
  controller_.HandleLidStateChange(LidState::OPEN);

  // Ditto for the idle action.
  EXPECT_TRUE(AdvanceTimeAndTriggerTimeout(kIdleDelay));
  EXPECT_EQ(kShutDown, delegate_.GetActions());
  controller_.HandleUserActivity();

  // If the count reaches the threshold, the system should suspend instead of
  // shutting down.
  controller_.HandleTpmStatus(kThreshold);
  controller_.HandleLidStateChange(LidState::CLOSED);
  EXPECT_EQ(kSuspendLidClosed, delegate_.GetActions());
  controller_.HandleLidStateChange(LidState::OPEN);

  EXPECT_TRUE(AdvanceTimeAndTriggerTimeout(kIdleDelay));
  EXPECT_EQ(kSuspendIdle, delegate_.GetActions());
  controller_.HandleUserActivity();

  // If non-"shut down" actions are set, they shouldn't be overridden.
  initial_policy_.set_ac_idle_action(PowerManagementPolicy_Action_DO_NOTHING);
  initial_policy_.set_lid_closed_action(
      PowerManagementPolicy_Action_STOP_SESSION);
  controller_.HandlePolicyChange(initial_policy_);

  controller_.HandleLidStateChange(LidState::CLOSED);
  EXPECT_EQ(kStopSession, delegate_.GetActions());
  controller_.HandleLidStateChange(LidState::OPEN);

  EXPECT_TRUE(AdvanceTimeAndTriggerTimeout(kIdleDelay));
  EXPECT_EQ(kNoActions, delegate_.GetActions());
  controller_.HandleUserActivity();
}

TEST_F(StateControllerTest, ReportInactivityDelays) {
  send_initial_policy_ = false;
  Init();
  dbus_wrapper_.ClearSentSignals();

  constexpr base::TimeDelta kIdle = base::Seconds(300);
  constexpr base::TimeDelta kIdleWarn = base::Seconds(270);
  constexpr base::TimeDelta kScreenOff = base::Seconds(180);
  constexpr base::TimeDelta kScreenDim = base::Seconds(170);
  constexpr base::TimeDelta kScreenLock = base::Seconds(190);
  constexpr double kScreenDimFactor = 3.0;

  // Send an initial policy change and check that its delays are announced.
  PowerManagementPolicy policy;
  policy.mutable_ac_delays()->set_idle_ms(kIdle.InMilliseconds());
  policy.mutable_ac_delays()->set_idle_warning_ms(kIdleWarn.InMilliseconds());
  policy.mutable_ac_delays()->set_screen_off_ms(kScreenOff.InMilliseconds());
  policy.mutable_ac_delays()->set_screen_dim_ms(kScreenDim.InMilliseconds());
  policy.mutable_ac_delays()->set_screen_lock_ms(kScreenLock.InMilliseconds());
  policy.set_presentation_screen_dim_delay_factor(kScreenDimFactor);
  controller_.HandlePolicyChange(policy);

  PowerManagementPolicy::Delays delays;
  EXPECT_EQ(GetInactivityDelaysChangedString(kIdle, kIdleWarn, kScreenOff,
                                             kScreenDim, kScreenLock),
            GetDBusSignals(SignalType::ALL));

  // Nothing should be announced if the policy didn't change.
  controller_.HandlePolicyChange(policy);
  EXPECT_EQ("", GetDBusSignals(SignalType::ALL));

  // Clear a few fields and check that an update is sent.
  policy.mutable_ac_delays()->clear_idle_warning_ms();
  policy.mutable_ac_delays()->clear_screen_lock_ms();
  controller_.HandlePolicyChange(policy);

  EXPECT_EQ(
      GetInactivityDelaysChangedString(kIdle, base::TimeDelta(), kScreenOff,
                                       kScreenDim, base::TimeDelta()),
      GetDBusSignals(SignalType::ALL));

  // GetInactivityDelays D-Bus calls should return the correct values as well.
  dbus::MethodCall method_call(kPowerManagerInterface,
                               kGetInactivityDelaysMethod);
  std::unique_ptr<dbus::Response> response =
      dbus_wrapper_.CallExportedMethodSync(&method_call);
  ASSERT_TRUE(response);
  PowerManagementPolicy::Delays proto;
  ASSERT_TRUE(
      dbus::MessageReader(response.get()).PopArrayOfBytesAsProto(&proto));
  EXPECT_EQ(kIdle.InMilliseconds(), proto.idle_ms());
  EXPECT_FALSE(proto.has_idle_warning_ms());
  EXPECT_EQ(kScreenOff.InMilliseconds(), proto.screen_off_ms());
  EXPECT_EQ(kScreenDim.InMilliseconds(), proto.screen_dim_ms());
  EXPECT_FALSE(proto.has_screen_lock_ms());

  // Enter presentation mode and check that the reported delays are adjusted.
  const base::TimeDelta kScaledScreenDim =
      base::Microseconds(kScreenDim.InMicrosecondsF() * kScreenDimFactor);
  const base::TimeDelta kDelayDiff = kScaledScreenDim - kScreenDim;
  controller_.HandleDisplayModeChange(DisplayMode::PRESENTATION);
  EXPECT_EQ(GetInactivityDelaysChangedString(
                kIdle + kDelayDiff, base::TimeDelta(), kScreenOff + kDelayDiff,
                kScaledScreenDim, base::TimeDelta()),
            GetDBusSignals(SignalType::ALL));
}

TEST_F(StateControllerTest, ScreenDimTriggered) {
  Init();
  dbus_wrapper_.NotifyServiceAvailable(ml_decision_proxy_, true);
  defer_screen_dimming_ = false;

  // Set screen_dim_ms to a fix number.
  constexpr base::TimeDelta kDimDelay = base::Seconds(60);
  PowerManagementPolicy policy;
  policy.mutable_ac_delays()->set_screen_dim_ms(kDimDelay.InMilliseconds());
  controller_.HandlePolicyChange(policy);
  const base::TimeDelta kDimImminentDelay =
      kDimDelay - StateController::kScreenDimImminentInterval;

  // Case (1): We should see screen dim if RequestSmartDimDecision decides not
  // to defer.
  ASSERT_TRUE(StepTimeAndTriggerTimeout(kDimImminentDelay));
  // RequestSmartDimDecision runs asynchronously, we need wait until the last
  // call finishes.
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(chromeos::kMlDecisionServiceShouldDeferScreenDimMethod,
            GetDBusMethodCalls());
  EXPECT_EQ(kNoActions, delegate_.GetActions());

  ASSERT_TRUE(StepTimeAndTriggerTimeout(kDimDelay));
  EXPECT_EQ(kScreenDim, delegate_.GetActions());

  // Case (2): We should see screen dim if RequestSmartDimDecision timeout.
  defer_screen_dimming_ = true;
  simulate_smart_dim_timeout_ = true;
  // Turn the screen back on.
  controller_.HandleUserActivity();
  EXPECT_EQ(kScreenUndim, delegate_.GetActions());
  ResetLastStepDelay();

  ASSERT_TRUE(StepTimeAndTriggerTimeout(kDimImminentDelay));
  // RequestSmartDimDecision runs asynchronously, we need wait until the last
  // call finishes.
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(chromeos::kMlDecisionServiceShouldDeferScreenDimMethod,
            GetDBusMethodCalls());
  EXPECT_EQ(kNoActions, delegate_.GetActions());

  // Because screen dim is not delayed, this should dim the screen.
  ASSERT_TRUE(StepTimeAndTriggerTimeout(kDimDelay));
  EXPECT_EQ(kScreenDim, delegate_.GetActions());

  // Turn the screen back on.
  controller_.HandleUserActivity();
  EXPECT_EQ(kScreenUndim, delegate_.GetActions());
  ResetLastStepDelay();

  // Case (3): We shouldn't see screen dim if RequestSmartDimDecision decides to
  // defer.
  simulate_smart_dim_timeout_ = false;
  ASSERT_TRUE(StepTimeAndTriggerTimeout(kDimImminentDelay));
  // RequestSmartDimDecision runs asynchronously, we need wait until the last
  // call finishes.
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(chromeos::kMlDecisionServiceShouldDeferScreenDimMethod,
            GetDBusMethodCalls());
  // THe StepTimeAndTriggerTimeout above will cause RequestSmartDimDecision
  // to be called which will eventually calls
  // controller_.HandleDeferFromSmartDim, and thus resets the
  // GetLastActivityTimeForScreenDim(now) to be now. Therefore
  // screen_dim_duration is 0 now, and ShouldRequestDimDeferSuggestion should
  // return false
  EXPECT_FALSE(controller_.ShouldRequestDimDeferSuggestion(now_));

  // Because the GetLastActivityTimeForScreenDim(now) is reset to now. The
  // Next action was rescheduled to kDimImminentDelay in the controller; so we
  // need to AdvanceTime to kDimImminentDelay to trigger the next action.
  ASSERT_TRUE(AdvanceTimeAndTriggerTimeout(kDimImminentDelay));
  // RequestSmartDimDecision runs asynchronously, we need wait until the last
  // call finishes.
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(chromeos::kMlDecisionServiceShouldDeferScreenDimMethod,
            GetDBusMethodCalls());
  // And no action should happen until now since dimming is delayed.
  EXPECT_EQ("", delegate_.GetActions());
}

TEST_F(StateControllerTest, ShouldNotRequestDimDeferSuggestion) {
  Init();
  dbus_wrapper_.NotifyServiceAvailable(ml_decision_proxy_, true);
  defer_screen_dimming_ = false;

  // Set screen_dim_ms to a fix number.
  constexpr base::TimeDelta kDimDelay = base::Seconds(60);
  PowerManagementPolicy policy;
  policy.mutable_ac_delays()->set_screen_dim_ms(kDimDelay.InMilliseconds());
  controller_.HandlePolicyChange(policy);
  const base::TimeDelta kDimImminentDelay =
      kDimDelay - StateController::kScreenDimImminentInterval;

  // Case (1): Powerd shouldn't request a smart dim decision if
  // screen-dim-duration is <  kDimImminentDelay.
  EXPECT_FALSE(StepTimeAndTriggerTimeout(base::Seconds(5)));
  EXPECT_EQ(kNoActions, delegate_.GetActions());
  EXPECT_FALSE(controller_.ShouldRequestDimDeferSuggestion(now_));
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ("", GetDBusMethodCalls());

  // Case (2): Powerd should request a smart dim decision if
  // screen-dim-duration is >=  kDimImminentDelay
  EXPECT_TRUE(StepTimeAndTriggerTimeout(kDimImminentDelay));
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(chromeos::kMlDecisionServiceShouldDeferScreenDimMethod,
            GetDBusMethodCalls());
  EXPECT_EQ(kNoActions, delegate_.GetActions());

  // StepTime to dim the screen.
  EXPECT_TRUE(StepTimeAndTriggerTimeout(kDimDelay));
  // No need to wait for screen dim since TestDelegate::DimScreen is not async.
  EXPECT_EQ(kScreenDim, delegate_.GetActions());

  // Case (3) Powerd shouldn't request a smart dim decision if screen is already
  // dimmed.
  // Verify that controller_.ShouldRequestDimDeferSuggestion should return false
  // if the Screen is just dimmed.
  EXPECT_FALSE(controller_.ShouldRequestDimDeferSuggestion(now_));
  EXPECT_EQ("", GetDBusMethodCalls());

  // Turn the screen back on.
  controller_.HandleUserActivity();
  EXPECT_EQ(kScreenUndim, delegate_.GetActions());

  // Case (4) Powerd shouldn't request a smart dim decision if the defer will
  // cause the screen to be undimmed for more than kDeferDimmingTimeLimit.
  // Advance timer to be close to kDeferDimmingTimeLimit, so that there should
  // be no request for a dim defer suggestion.
  AdvanceTime(StateController::kDeferDimmingTimeLimit - base::Seconds(1));
  EXPECT_FALSE(controller_.ShouldRequestDimDeferSuggestion(now_));
}

TEST_F(StateControllerTest, ScheduleForQuickDim) {
  initial_power_source_ = PowerSource::AC;
  Init();

  const base::TimeDelta kDimImminentDelay =
      default_ac_screen_dim_delay_ -
      StateController::kScreenDimImminentInterval;

  // The next schedule should be at kDimDelay if
  // !IsSmartDimEnabled && !IsHpsSenseEnabled()
  ASSERT_TRUE(AdvanceTimeAndTriggerTimeout(default_ac_screen_dim_delay_));
  EXPECT_EQ(kScreenDim, delegate_.GetActions());
  // Turn the screen back on.
  controller_.HandleUserActivity();
  EXPECT_EQ(kScreenUndim, delegate_.GetActions());

  // The next block verifies that no quick dim should be scheduled if
  // hps_result_ is positive by EmitHpsSignal(HpsResult::POSITIVE); thus a
  // standard dim should be scheduled at kDimDelay.
  EmitHpsSignal(HpsResult::POSITIVE);
  ASSERT_TRUE(AdvanceTimeAndTriggerTimeout(default_ac_screen_dim_delay_));
  EXPECT_EQ(kScreenDim, delegate_.GetActions());
  // Turn the screen back on.
  controller_.HandleUserActivity();
  EXPECT_EQ(kScreenUndim, delegate_.GetActions());

  // The next block verifies that a quick dim should be scheduled at
  // kQuickDimDelay if if hps_result_ is negative by
  // EmitHpsSignal(HpsResult::NEGATIVE).
  EmitHpsSignal(HpsResult::NEGATIVE);
  ASSERT_TRUE(AdvanceTimeAndTriggerTimeout(default_ac_quick_dim_delay_));
  EXPECT_EQ(kScreenDim, delegate_.GetActions());
  // Turn the screen back on.
  controller_.HandleUserActivity();
  EXPECT_EQ(kScreenUndim, delegate_.GetActions());
  EmitHpsSignal(HpsResult::POSITIVE);

  // The next block verifies that a quick dim should not be scheduled if
  //  duration_since_last_activity_for_screen_dim >= kDimImminentDelay; thus a
  // standard dim will be scheduled at
  //  kQuickDimDelay = kDimImminentDelay + kScreenDimImminentInterval
  // Advance clock.
  AdvanceTime(kDimImminentDelay);
  // Send a hps negative signal.
  EmitHpsSignal(HpsResult::NEGATIVE);
  // Next action will be scheduled at after kScreenDimImminentInterval, not
  // after kQuickDimDelay.
  ASSERT_TRUE(AdvanceTimeAndTriggerTimeout(
      StateController::kScreenDimImminentInterval));
  EXPECT_EQ(kScreenDim, delegate_.GetActions());
  // Turn the screen back on.
  controller_.HandleUserActivity();
  EXPECT_EQ(kScreenUndim, delegate_.GetActions());
  EmitHpsSignal(HpsResult::POSITIVE);

  // The next block verifies that a quick dim should be scheduled at
  // kQuickDimDelay after hps_result_ becomes negative if the last activity is
  // earlier.
  // Advance 1 second.
  AdvanceTime(base::Seconds(1));
  EmitHpsSignal(HpsResult::NEGATIVE);
  // Next quick dim will be scheduled after kQuickDimDelay.
  ASSERT_TRUE(AdvanceTimeAndTriggerTimeout(default_ac_quick_dim_delay_));
  EXPECT_EQ(kScreenDim, delegate_.GetActions());
  // Turn the screen back on.
  controller_.HandleUserActivity();
  EXPECT_EQ(kScreenUndim, delegate_.GetActions());
  EmitHpsSignal(HpsResult::POSITIVE);

  // The next block verifies that a quick dim should be scheduled at
  // kQuickDimDelay after last user activity if hps_result_ turned to negative
  // earlier.
  EmitHpsSignal(HpsResult::NEGATIVE);
  // Advance 1 second.
  AdvanceTime(base::Seconds(1));
  controller_.HandleUserActivity();
  // Next quick dim will be scheduled after kQuickDimDelay.
  ASSERT_TRUE(AdvanceTimeAndTriggerTimeout(default_ac_quick_dim_delay_));
  EXPECT_EQ(kScreenDim, delegate_.GetActions());
  // Turn the screen back on.
  controller_.HandleUserActivity();
  EXPECT_EQ(kScreenUndim, delegate_.GetActions());
  EmitHpsSignal(HpsResult::POSITIVE);

  // The next block verifies that if MLDecision Service is available then the
  // MLDecision DBus call should be scheduled if that's earlier than the next
  // quick dim.
  // Turn on the MLDecision Service.
  dbus_wrapper_.NotifyServiceAvailable(ml_decision_proxy_, true);
  // Advance clock.
  AdvanceTime(kDimImminentDelay - base::Seconds(1));
  // |hps_result_| turned to negative only 1 second before kDimImminentDelay.
  EmitHpsSignal(HpsResult::NEGATIVE);
  // Next action will be scheduled at kDimImminentDelay for MLDecision query,
  // not kDimImminentDelay + kQuickDimDelay for a quick dim.
  ASSERT_TRUE(AdvanceTimeAndTriggerTimeout(base::Seconds(1)));
}

TEST_F(StateControllerTest, QuickDimAndUndim) {
  initial_power_source_ = PowerSource::AC;
  Init();
  // Turn on the MLDecision Service.
  dbus_wrapper_.NotifyServiceAvailable(ml_decision_proxy_, true);

  const base::TimeDelta kDimImminentDelay =
      default_ac_screen_dim_delay_ -
      StateController::kScreenDimImminentInterval;

  // Case (1) a quick dim undimmed by user activity.
  EmitHpsSignal(HpsResult::NEGATIVE);
  ASSERT_TRUE(AdvanceTimeAndTriggerTimeout(default_ac_quick_dim_delay_));
  EXPECT_EQ(kScreenDim, delegate_.GetActions());
  // Undim by user activity.
  controller_.HandleUserActivity();
  EXPECT_EQ(kScreenUndim, delegate_.GetActions());
  EmitHpsSignal(HpsResult::POSITIVE);

  // Case (2) a quick dim undimed by hps.
  EmitHpsSignal(HpsResult::NEGATIVE);
  ASSERT_TRUE(AdvanceTimeAndTriggerTimeout(default_ac_quick_dim_delay_));
  EXPECT_EQ(kScreenDim, delegate_.GetActions());
  // undim by Hps.
  EmitHpsSignal(HpsResult::POSITIVE);
  EXPECT_EQ(kScreenUndim, delegate_.GetActions());
  controller_.HandleUserActivity();

  // Case (3) a quick dim will not happen after kDimImminentDelay.
  AdvanceTime(kDimImminentDelay - default_ac_quick_dim_delay_);
  EmitHpsSignal(HpsResult::NEGATIVE);
  ASSERT_TRUE(AdvanceTimeAndTriggerTimeout(default_ac_quick_dim_delay_));
  // A quick dim will not happen because it is after kDimImminentDelay.
  EXPECT_EQ("", delegate_.GetActions());
  // Instead a standard dim is scheduled.
  ASSERT_TRUE(AdvanceTimeAndTriggerTimeout(
      StateController::kScreenDimImminentInterval));
  EXPECT_EQ(kScreenDim, delegate_.GetActions());
  // Undim by user activity.
  controller_.HandleUserActivity();
  EXPECT_EQ(kScreenUndim, delegate_.GetActions());
  EmitHpsSignal(HpsResult::POSITIVE);

  // Case (4) a hps signal can't revert a quick dim after kDimImminentDelay.
  EmitHpsSignal(HpsResult::NEGATIVE);
  ASSERT_TRUE(AdvanceTimeAndTriggerTimeout(default_ac_quick_dim_delay_));
  EXPECT_EQ(kScreenDim, delegate_.GetActions());
  // Advance to kDimImminentDelay.
  AdvanceTime(kDimImminentDelay - default_ac_quick_dim_delay_);
  // Send Hps positive signal.
  EmitHpsSignal(HpsResult::POSITIVE);
  // undim will not happen because it is after kDimImminentDelay.
  EXPECT_EQ(kNoActions, delegate_.GetActions());
  // A user activity will always undim the screen.
  controller_.HandleUserActivity();
  EXPECT_EQ(kScreenUndim, delegate_.GetActions());
}

TEST_F(StateControllerTest, QuickDimAndUndimMetrics) {
  Init();

  const base::TimeDelta kTimeForward = base::Seconds(6);

  delegate_.set_record_hps_event_metrics(true);

  // Case (1) trigger a standard dim.
  const std::string standard_dim_event =
      GetDimEventString(metrics::DimEvent::STANDARD_DIM);
  const std::string quick_dim_event =
      GetDimEventString(metrics::DimEvent::QUICK_DIM);

  // We have to advance the timer then send POSITIVE signal in order to avoid
  // a defer from HPS.
  AdvanceTime(default_ac_screen_dim_delay_ - kTimeForward);
  // Send Hps positive signal to enable HpsSense.
  EmitHpsSignal(HpsResult::POSITIVE);

  ASSERT_TRUE(AdvanceTimeAndTriggerTimeout(kTimeForward));
  EXPECT_EQ(JoinActions(kScreenDim, standard_dim_event.c_str(), nullptr),
            delegate_.GetActions());

  // Case (2) revert a standard dim.
  AdvanceTime(kTimeForward);
  controller_.HandleUserActivity();
  const std::string standard_dim_revert_duration_event =
      GetHpsEventDurationString(
          metrics::kStandardDimDurationBeforeRevertedByUserSec, kTimeForward);
  EXPECT_EQ(JoinActions(kScreenUndim,
                        standard_dim_revert_duration_event.c_str(), nullptr),
            delegate_.GetActions());

  // Case (3) revert a quick dim with hps.
  EmitHpsSignal(HpsResult::NEGATIVE);
  ASSERT_TRUE(AdvanceTimeAndTriggerTimeout(default_ac_quick_dim_delay_));
  // No metrics is logged, we recorded quick_dim when it is reverted.
  EXPECT_EQ(JoinActions(kScreenDim, quick_dim_event.c_str(), nullptr),
            delegate_.GetActions());
  AdvanceTime(kTimeForward);
  EmitHpsSignal(HpsResult::POSITIVE);
  const std::string quick_dim_revert_by_hps_duration_event =
      GetHpsEventDurationString(
          metrics::kQuickDimDurationBeforeRevertedByHpsSec, kTimeForward);
  const std::string quick_dim_revert_by_hps_event =
      GetDimEventString(metrics::DimEvent::QUICK_DIM_REVERTED_BY_HPS);
  EXPECT_EQ(
      JoinActions(kScreenUndim, quick_dim_revert_by_hps_duration_event.c_str(),
                  quick_dim_revert_by_hps_event.c_str(), nullptr),
      delegate_.GetActions());

  // Case (4) revert a quick dim with user activity before transitioning to a
  // standard dim.
  // Reset LastUserActivityForScreenDim.
  controller_.HandleUserActivity();
  EmitHpsSignal(HpsResult::NEGATIVE);
  ASSERT_TRUE(AdvanceTimeAndTriggerTimeout(default_ac_quick_dim_delay_));
  // No metrics is logged, we recorded quick_dim when it is reverted.
  EXPECT_EQ(JoinActions(kScreenDim, quick_dim_event.c_str(), nullptr),
            delegate_.GetActions());
  AdvanceTime(kTimeForward);
  controller_.HandleUserActivity();
  std::string quick_dim_revert_by_user_duration_event =
      GetHpsEventDurationString(
          metrics::kQuickDimDurationBeforeRevertedByUserSec, kTimeForward);
  const std::string quick_dim_revert_by_user_event =
      GetDimEventString(metrics::DimEvent::QUICK_DIM_REVERTED_BY_USER);
  EXPECT_EQ(
      JoinActions(kScreenUndim, quick_dim_revert_by_user_duration_event.c_str(),
                  quick_dim_revert_by_user_event.c_str(), nullptr),
      delegate_.GetActions());

  // Case (5) revert a quick dim with user activity after transitioning to
  // standard dim.
  EmitHpsSignal(HpsResult::NEGATIVE);
  ASSERT_TRUE(AdvanceTimeAndTriggerTimeout(default_ac_quick_dim_delay_));
  // No metrics is logged, we recorded quick_dim when it is reverted.
  EXPECT_EQ(JoinActions(kScreenDim, quick_dim_event.c_str(), nullptr),
            delegate_.GetActions());
  AdvanceTime(default_ac_screen_dim_delay_);
  controller_.HandleUserActivity();
  quick_dim_revert_by_user_duration_event = GetHpsEventDurationString(
      metrics::kQuickDimDurationBeforeRevertedByUserSec,
      default_ac_screen_dim_delay_);
  const std::string quick_dim_revert_transite_event = GetDimEventString(
      metrics::DimEvent::QUICK_DIM_TRANSITIONED_TO_STANDARD_DIM);
  EXPECT_EQ(
      JoinActions(kScreenUndim, quick_dim_revert_by_user_duration_event.c_str(),
                  quick_dim_revert_transite_event.c_str(), nullptr),
      delegate_.GetActions());
}

// Tests that display mode changes are ignored if the screens have been recently
// turned off. Buggy display hardware can cause HPDs (hot plug detection signal)
// to be issued when the screen is disabled which looks like the user has
// plugged/unplugged a new display. http://b/193374679, http://crrev/c/3124532
TEST_F(StateControllerTest, IgnoreDisplayModeChangesAfterScreenOff) {
  Init();

  // Wait for the screen to be dimmed and turned off.
  ASSERT_TRUE(StepTimeAndTriggerTimeout(default_ac_screen_dim_delay_));
  ASSERT_TRUE(StepTimeAndTriggerTimeout(default_ac_screen_off_delay_));
  EXPECT_EQ(JoinActions(kScreenDim, kScreenOff, nullptr),
            delegate_.GetActions());

  // User activity received while the lid is closed should be ignored.
  controller_.HandleDisplayModeChange(DisplayMode::NORMAL);
  EXPECT_EQ(kNoActions, delegate_.GetActions());
  controller_.HandleDisplayModeChange(DisplayMode::PRESENTATION);
  EXPECT_EQ(kNoActions, delegate_.GetActions());

  // Wait for the ignore timeout to expire
  AdvanceTime(StateController::kIgnoreDisplayModeAfterScreenOffInterval +
              base::Seconds(1));

  controller_.HandleDisplayModeChange(DisplayMode::NORMAL);
  EXPECT_EQ(JoinActions(kScreenUndim, kScreenOn, nullptr),
            delegate_.GetActions());
}

TEST_F(StateControllerTest, LoadPrefShouldSetCorrectQuickDimDelaysAC) {
  initial_power_source_ = PowerSource::AC;
  Init();
  EmitHpsSignal(HpsResult::NEGATIVE);
  ASSERT_TRUE(AdvanceTimeAndTriggerTimeout(default_ac_quick_dim_delay_));
  EXPECT_EQ(kScreenDim, delegate_.GetActions());
}

TEST_F(StateControllerTest, LoadPrefShouldSetCorrectQuickDimDelaysBattery) {
  initial_power_source_ = PowerSource::BATTERY;
  Init();
  EmitHpsSignal(HpsResult::NEGATIVE);
  ASSERT_TRUE(AdvanceTimeAndTriggerTimeout(default_battery_quick_dim_delay_));
  EXPECT_EQ(kScreenDim, delegate_.GetActions());
}

TEST_F(StateControllerTest, HandlePolicyChangeShouldSetCorrectQuickDimDelays) {
  Init();

  const base::TimeDelta quick_dim_delay = base::Seconds(52);

  // Next block verifies that delays are set properly from HandlePolicyChange.
  PowerManagementPolicy policy;
  auto& ac_delays = *policy.mutable_ac_delays();
  ac_delays.set_quick_dim_ms(quick_dim_delay.InMilliseconds());
  controller_.HandlePolicyChange(policy);
  EmitHpsSignal(HpsResult::NEGATIVE);
  ASSERT_TRUE(AdvanceTimeAndTriggerTimeout(quick_dim_delay));
  EXPECT_EQ(kScreenDim, delegate_.GetActions());

  // Undim by user activity.
  controller_.HandleUserActivity();
  EXPECT_EQ(kScreenUndim, delegate_.GetActions());
  EmitHpsSignal(HpsResult::POSITIVE);

  // If quick_dim_delay > default_ac_screen_dim_delay_ then a standard dim will
  // will happen.
  ac_delays.set_quick_dim_ms(default_ac_screen_dim_delay_.InMilliseconds() + 1);
  controller_.HandlePolicyChange(policy);
  EmitHpsSignal(HpsResult::NEGATIVE);

  // A quick lock should happen at default_ac_quick_lock_delay_.
  ASSERT_TRUE(AdvanceTimeAndTriggerTimeout(default_ac_quick_lock_delay_));
  EXPECT_EQ(kScreenLock, delegate_.GetActions());

  // A standard dim should happen at default_ac_screen_dim_delay_.
  ASSERT_TRUE(AdvanceTimeAndTriggerTimeout(default_ac_screen_dim_delay_ -
                                           default_ac_quick_lock_delay_));
  EXPECT_EQ(kScreenDim, delegate_.GetActions());
}

TEST_F(StateControllerTest, LoadPrefShouldSetCorrectQuickLockDelaysAC) {
  initial_power_source_ = PowerSource::AC;
  Init();
  // Enables HpsSense with signal NEGATIVE.
  EmitHpsSignal(HpsResult::NEGATIVE);

  // A quick dim should happen at default_ac_quick_dim_delay_.
  ASSERT_TRUE(StepTimeAndTriggerTimeout(default_ac_quick_dim_delay_));
  EXPECT_EQ(kScreenDim, delegate_.GetActions());

  // A quick lock should happen at default_ac_quick_lock_delay_.
  ASSERT_TRUE(StepTimeAndTriggerTimeout(default_ac_quick_lock_delay_));
  EXPECT_EQ(kScreenLock, delegate_.GetActions());
}

TEST_F(StateControllerTest, LoadPrefShouldSetCorrectQuickLockDelaysBattery) {
  initial_power_source_ = PowerSource::BATTERY;
  Init();
  // Enables HpsSense with signal NEGATIVE.
  EmitHpsSignal(HpsResult::NEGATIVE);

  // A quick dim should happen at default_battery_quick_dim_delay_.
  ASSERT_TRUE(StepTimeAndTriggerTimeout(default_battery_quick_dim_delay_));
  EXPECT_EQ(kScreenDim, delegate_.GetActions());

  // A quick lock should happen at default_battery_quick_lock_delay_.
  ASSERT_TRUE(StepTimeAndTriggerTimeout(default_battery_quick_lock_delay_));
  EXPECT_EQ(kScreenLock, delegate_.GetActions());
}

TEST_F(StateControllerTest, QuickLockAfterQuickDim) {
  initial_power_source_ = PowerSource::AC;
  Init();
  // Enables HpsSense with signal NEGATIVE.
  EmitHpsSignal(HpsResult::NEGATIVE);

  // A quick dim should happen at default_ac_quick_dim_delay_.
  ASSERT_TRUE(StepTimeAndTriggerTimeout(default_ac_quick_dim_delay_));
  EXPECT_EQ(kScreenDim, delegate_.GetActions());

  // A quick lock should happen at default_ac_quick_lock_delay_.
  ASSERT_TRUE(StepTimeAndTriggerTimeout(default_ac_quick_lock_delay_));
  EXPECT_EQ(kScreenLock, delegate_.GetActions());

  // Undim by user activity.
  controller_.HandleUserActivity();
  EXPECT_EQ(kScreenUndim, delegate_.GetActions());
  EmitHpsSignal(HpsResult::POSITIVE);
  ResetLastStepDelay();

  // Check that after undim, the same quick dim, quick_lock will happen again.
  EmitHpsSignal(HpsResult::NEGATIVE);
  // A quick dim should happen at default_ac_quick_dim_delay_.
  ASSERT_TRUE(StepTimeAndTriggerTimeout(default_ac_quick_dim_delay_));
  EXPECT_EQ(kScreenDim, delegate_.GetActions());

  // A quick lock should happen at default_ac_quick_lock_delay_.
  ASSERT_TRUE(StepTimeAndTriggerTimeout(default_ac_quick_lock_delay_));
  EXPECT_EQ(kScreenLock, delegate_.GetActions());
}

TEST_F(StateControllerTest, QuickLockAfterStandardDim) {
  initial_power_source_ = PowerSource::BATTERY;
  Init();
  delegate_.set_record_hps_event_metrics(true);
  const std::string standard_dim_event =
      GetDimEventString(metrics::DimEvent::STANDARD_DIM);
  const std::string quick_lock_event =
      GetLockEventString(metrics::LockEvent::QUICK_LOCK);

  const auto delta_quick_dim_to_standard_dim =
      default_battery_screen_dim_delay_ - default_battery_quick_dim_delay_ +
      base::Seconds(1);

  StepTime(delta_quick_dim_to_standard_dim);
  EmitHpsSignal(HpsResult::NEGATIVE);

  // There is not enough delay for a quick dim, so a standard dim will happen.
  ASSERT_TRUE(StepTimeAndTriggerTimeout(default_battery_screen_dim_delay_));
  EXPECT_EQ(JoinActions(kScreenDim, standard_dim_event.c_str(), nullptr),
            delegate_.GetActions());

  // A quick lock will then happen.
  ASSERT_TRUE(StepTimeAndTriggerTimeout(default_battery_quick_lock_delay_ +
                                        delta_quick_dim_to_standard_dim));
  EXPECT_EQ(JoinActions(kScreenLock, quick_lock_event.c_str(), nullptr),
            delegate_.GetActions());

  // A screen off will then happen.
  ASSERT_TRUE(StepTimeAndTriggerTimeout(default_battery_screen_off_delay_));
  EXPECT_EQ(kScreenOff, delegate_.GetActions());
}

TEST_F(StateControllerTest, QuickLockAfterScreenOff) {
  initial_power_source_ = PowerSource::BATTERY;
  Init();

  const auto delta = default_battery_screen_dim_delay_ -
                     default_battery_quick_dim_delay_ + base::Seconds(6);

  StepTime(delta);
  EmitHpsSignal(HpsResult::NEGATIVE);

  // There is not enough delay for a quick dim, so a standard dim will happen.
  ASSERT_TRUE(StepTimeAndTriggerTimeout(default_battery_screen_dim_delay_));
  EXPECT_EQ(kScreenDim, delegate_.GetActions());

  // A screen off will then happen.
  ASSERT_TRUE(StepTimeAndTriggerTimeout(default_battery_screen_off_delay_));
  EXPECT_EQ(kScreenOff, delegate_.GetActions());

  // A quick lock will then happen.
  ASSERT_TRUE(
      StepTimeAndTriggerTimeout(default_battery_quick_lock_delay_ + delta));
  EXPECT_EQ(kScreenLock, delegate_.GetActions());
}

TEST_F(StateControllerTest, DimDeferWithHps) {
  initial_power_source_ = PowerSource::AC;
  Init();
  // Turn on the MLDecision Service.
  dbus_wrapper_.NotifyServiceAvailable(ml_decision_proxy_, true);

  const base::TimeDelta kDimImminentDelay =
      default_ac_screen_dim_delay_ -
      StateController::kScreenDimImminentInterval;

  controller_.HandleUserActivity();
  // Case (1) hps_result is UNKNOWN which will not defer the dim.
  EmitHpsSignal(HpsResult::UNKNOWN);
  // Next timeout should be scheduled at kDimImminentDelay for a dim defer
  // query.
  ASSERT_TRUE(AdvanceTimeAndTriggerTimeout(kDimImminentDelay));
  EXPECT_EQ("", delegate_.GetActions());
  // There should be no defer, so dim happens after kScreenDimImminentInterval.
  ASSERT_TRUE(AdvanceTimeAndTriggerTimeout(
      StateController::kScreenDimImminentInterval));
  EXPECT_EQ(kScreenDim, delegate_.GetActions());
  // Undim by user activity.
  controller_.HandleUserActivity();
  EXPECT_EQ(kScreenUndim, delegate_.GetActions());

  // Case (2) hps_result is POSITIVE for a little while (less than
  // kHpsPositiveForDimDefer * delays_.screen_dim) will not defer the dim.
  // Next timeout should be scheduled at kDimImminentDelay for a dim defer
  // query.

  // Set hps_result_ to POSITIVE 1 seconds before kDimImminentDelay.
  constexpr auto delta_of_hps_positive_before_dim_imminent = base::Seconds(1);
  AdvanceTime(kDimImminentDelay - delta_of_hps_positive_before_dim_imminent);
  EmitHpsSignal(HpsResult::POSITIVE);

  // A timeout should be triggered at kDimImminentDelay.
  ASSERT_TRUE(
      AdvanceTimeAndTriggerTimeout(delta_of_hps_positive_before_dim_imminent));
  EXPECT_EQ("", delegate_.GetActions());

  // There should be no defer, so dim happens after kScreenDimImminentInterval.
  ASSERT_TRUE(AdvanceTimeAndTriggerTimeout(
      StateController::kScreenDimImminentInterval));
  EXPECT_EQ(kScreenDim, delegate_.GetActions());
  // Undim by user activity.
  controller_.HandleUserActivity();
  EXPECT_EQ(kScreenUndim, delegate_.GetActions());

  // Case (3) dim will be deferred twice.
  // Next timeout should be scheduled at kDimImminentDelay for a dim defer
  // query. And there should be a defer caused by hps.
  ASSERT_TRUE(AdvanceTimeAndTriggerTimeout(kDimImminentDelay));
  EXPECT_EQ("", delegate_.GetActions());
  // Next timeout should be scheduled at kDimImminentDelay for a dim defer
  // query. And there should be a second defer caused by hps.
  ASSERT_TRUE(AdvanceTimeAndTriggerTimeout(kDimImminentDelay));
  EXPECT_EQ("", delegate_.GetActions());
  // Next timeout should be scheduled at kDimImminentDelay for a dim defer
  // query. And there should be no defer this time.
  ASSERT_TRUE(AdvanceTimeAndTriggerTimeout(kDimImminentDelay));
  EXPECT_EQ("", delegate_.GetActions());
  // Dim should happen after kScreenDimImminentInterval.
  ASSERT_TRUE(AdvanceTimeAndTriggerTimeout(
      StateController::kScreenDimImminentInterval));
  EXPECT_EQ(kScreenDim, delegate_.GetActions());

  // Case (4) dim will be deferred only once if HpsSense becomes Negative after
  // the first defer.

  // Undim by user activity.
  controller_.HandleUserActivity();
  EXPECT_EQ(kScreenUndim, delegate_.GetActions());
  // Next timeout should be scheduled at kDimImminentDelay for a dim defer
  // query. And there should be a defer caused by hps.
  ASSERT_TRUE(AdvanceTimeAndTriggerTimeout(kDimImminentDelay));
  EXPECT_EQ("", delegate_.GetActions());

  // Advance the timer to the point that is close to the next DimDefer query.
  constexpr auto delta_before_next_dim_defer_query = base::Seconds(1);
  AdvanceTime(kDimImminentDelay - delta_before_next_dim_defer_query);
  // Emit a NEGATIVE Hps signal so that dim will not be deferred any more.
  EmitHpsSignal(HpsResult::NEGATIVE);

  // Next timeout happens after delta_before_next_dim_defer_query for a dim
  // defer query. And there should be no defer caused by hps.
  ASSERT_TRUE(AdvanceTimeAndTriggerTimeout(delta_before_next_dim_defer_query));
  EXPECT_EQ("", delegate_.GetActions());

  // Dim should happen after kScreenDimImminentInterval.
  ASSERT_TRUE(AdvanceTimeAndTriggerTimeout(
      StateController::kScreenDimImminentInterval));
  EXPECT_EQ(kScreenDim, delegate_.GetActions());
}

TEST_F(StateControllerTest, NoDimDeferAfterkDeferDimmingTimeLimit) {
  initial_power_source_ = PowerSource::AC;

  // Set screen_dim_delay to be 7 minutes, so that dimming defer will only
  // happen once instead of two.
  default_ac_screen_dim_delay_ = base::Minutes(7);

  // Disable all other functionalities so that they don't intervene.
  default_ac_suspend_delay_ = base::Minutes(8);
  default_ac_screen_off_delay_ = base::Minutes(8);
  default_ac_quick_dim_delay_ = base::Minutes(8);
  default_ac_quick_lock_delay_ = base::Minutes(8);

  Init();
  delegate_.set_record_hps_event_metrics(true);

  // Turn on the MLDecision Service.
  dbus_wrapper_.NotifyServiceAvailable(ml_decision_proxy_, true);

  const base::TimeDelta kDimImminentDelay =
      default_ac_screen_dim_delay_ -
      StateController::kScreenDimImminentInterval;

  controller_.HandleUserActivity();
  EmitHpsSignal(HpsResult::POSITIVE);

  // Next timeout should be scheduled at kDimImminentDelay for a dim defer
  // query. And there should be a defer caused by hps.
  ASSERT_TRUE(AdvanceTimeAndTriggerTimeout(kDimImminentDelay));

  const std::string standard_dim_deferred_by_hps_event =
      GetHpsEventDurationString(metrics::kStandardDimDeferredByHpsSec,
                                kDimImminentDelay);

  EXPECT_EQ(JoinActions(standard_dim_deferred_by_hps_event.c_str(), nullptr),
            delegate_.GetActions());

  // Next timeout should be scheduled at kDimImminentDelay for a dim defer
  // query. But there will be no defer this time even if MLDecision service
  // says defer.
  defer_screen_dimming_ = true;
  ASSERT_TRUE(AdvanceTimeAndTriggerTimeout(kDimImminentDelay));
  EXPECT_EQ("", delegate_.GetActions());

  // Dim should happen after kScreenDimImminentInterval.
  ASSERT_TRUE(AdvanceTimeAndTriggerTimeout(
      StateController::kScreenDimImminentInterval));
  EXPECT_EQ(kScreenDim, delegate_.GetActions());
}

}  // namespace power_manager::policy
