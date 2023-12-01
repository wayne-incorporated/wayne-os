// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/powerd/policy/keyboard_backlight_controller.h"

#include <cmath>
#include <limits>
#include <string>

#include <base/strings/stringprintf.h>
#include <base/test/task_environment.h>
#include <base/time/time.h>
#include <dbus/power_manager/dbus-constants.h>
#include <gtest/gtest.h>

#include "power_manager/common/fake_prefs.h"
#include "power_manager/common/power_constants.h"
#include "power_manager/powerd/policy/backlight_controller.h"
#include "power_manager/powerd/policy/backlight_controller_observer_stub.h"
#include "power_manager/powerd/policy/backlight_controller_stub.h"
#include "power_manager/powerd/policy/backlight_controller_test_util.h"
#include "power_manager/powerd/system/ambient_light_sensor_stub.h"
#include "power_manager/powerd/system/backlight_stub.h"
#include "power_manager/powerd/system/dbus_wrapper_stub.h"
#include "power_manager/proto_bindings/backlight.pb.h"
#include "power_manager/proto_bindings/policy.pb.h"

namespace power_manager::policy {

class KeyboardBacklightControllerTest : public ::testing::Test {
 public:
  KeyboardBacklightControllerTest()
      : backlight_(max_backlight_level_,
                   initial_backlight_level_,
                   system::BacklightInterface::BrightnessScale::kUnknown),
        light_sensor_(initial_als_lux_) {
    controller_.AddObserver(&observer_);
  }

  ~KeyboardBacklightControllerTest() override {
    controller_.RemoveObserver(&observer_);
  }

  // Initializes |controller_|.
  virtual void Init() {
    backlight_.set_max_level(max_backlight_level_);
    backlight_.set_current_level(initial_backlight_level_);
    light_sensor_.set_lux(initial_als_lux_);

    prefs_.SetString(kKeyboardBacklightAlsStepsPref, als_steps_pref_);
    prefs_.SetString(kKeyboardBacklightUserStepsPref, user_steps_pref_);
    prefs_.SetDouble(kKeyboardBacklightNoAlsBrightnessPref,
                     no_als_brightness_pref_);
    prefs_.SetDouble(kAlsSmoothingConstantPref, 1.0);
    prefs_.SetInt64(kDetectHoverPref, detect_hover_pref_);
    prefs_.SetInt64(kKeyboardBacklightKeepOnMsPref, keep_on_ms_pref_);
    prefs_.SetInt64(kKeyboardBacklightKeepOnDuringVideoMsPref,
                    keep_on_during_video_ms_pref_);

    controller_.Init(&backlight_, &prefs_,
                     pass_light_sensor_ ? &light_sensor_ : nullptr,
                     &dbus_wrapper_, initial_lid_state_, initial_tablet_mode_);
  }

 protected:
  // Returns the hardware-specific brightness level that should be used when the
  // display is dimmed.
  int64_t GetDimmedLevel() {
    return static_cast<int64_t>(
        lround(KeyboardBacklightController::kDimPercent / 100 *
               static_cast<double>(max_backlight_level_)));
  }

  // Advances |controller_|'s clock by |interval|.
  void AdvanceTime(const base::TimeDelta& interval) {
    task_environment_.FastForwardBy(interval);
  }

  // Calls the IncreaseKeyboardBrightness D-Bus method.
  void CallIncreaseKeyboardBrightness() {
    dbus::MethodCall method_call(kPowerManagerInterface,
                                 kIncreaseKeyboardBrightnessMethod);
    ASSERT_TRUE(dbus_wrapper_.CallExportedMethodSync(&method_call));
  }

  // Calls the DecreaseKeyboardBrightness D-Bus method.
  void CallDecreaseKeyboardBrightness() {
    dbus::MethodCall method_call(kPowerManagerInterface,
                                 kDecreaseKeyboardBrightnessMethod);
    ASSERT_TRUE(dbus_wrapper_.CallExportedMethodSync(&method_call));
  }

  // Calls the GetKeyboardBrightnessPercent D-Bus method and returns the
  // percentage from the reply. Adds a failure and returns 0 on error.
  double CallGetKeyboardBrightnessPercent() {
    dbus::MethodCall method_call(kPowerManagerInterface,
                                 kGetKeyboardBrightnessPercentMethod);
    std::unique_ptr<dbus::Response> response =
        dbus_wrapper_.CallExportedMethodSync(&method_call);
    if (!response) {
      ADD_FAILURE() << kGetKeyboardBrightnessPercentMethod << " call failed";
      return 0.0;
    }

    double percent = 0.0;
    if (!dbus::MessageReader(response.get()).PopDouble(&percent))
      ADD_FAILURE() << "Bad " << kGetKeyboardBrightnessPercentMethod << " arg";
    return percent;
  }

  // Calls the SetKeyboardBrightness D-Bus method.
  void CallSetKeyboardBrightness(
      double percent,
      SetBacklightBrightnessRequest_Transition transition,
      SetBacklightBrightnessRequest_Cause cause) {
    dbus::MethodCall method_call(kPowerManagerInterface,
                                 kSetKeyboardBrightnessMethod);
    dbus::MessageWriter writer(&method_call);
    SetBacklightBrightnessRequest proto;
    proto.set_percent(percent);
    proto.set_transition(transition);
    proto.set_cause(cause);
    writer.AppendProtoAsArrayOfBytes(proto);
    ASSERT_TRUE(dbus_wrapper_.CallExportedMethodSync(&method_call));
  }

  void CallToggleKeyboardBacklight() {
    dbus::MethodCall method_call(kPowerManagerInterface,
                                 kToggleKeyboardBacklightMethod);
    ASSERT_TRUE(dbus_wrapper_.CallExportedMethodSync(&method_call));
  }

  base::test::SingleThreadTaskEnvironment task_environment_{
      base::test::TaskEnvironment::MainThreadType::IO,
      base::test::TaskEnvironment::TimeSource::MOCK_TIME};

  // Max and initial brightness levels for |backlight_|.
  int64_t max_backlight_level_ = 100;
  int64_t initial_backlight_level_ = 50;

  // Should |light_sensor_| be passed to |controller_|?
  bool pass_light_sensor_ = true;

  // Initial lux level reported by |light_sensor_|.
  int initial_als_lux_ = 0;

  // Initial  lid state and tablet mode passed to |controller_|.
  LidState initial_lid_state_ = LidState::NOT_PRESENT;
  TabletMode initial_tablet_mode_ = TabletMode::UNSUPPORTED;

  // Values for various preferences.  These can be changed by tests before
  // Init() is called.
  std::string als_steps_pref_ = "20.0 -1 50\n50.0 35 75\n75.0 60 -1";
  std::string user_steps_pref_ = "0.0\n10.0\n40.0\n60.0\n100.0";
  double no_als_brightness_pref_ = 40.0;
  int64_t detect_hover_pref_ = 0;
  int64_t keep_on_ms_pref_ = 30'000;
  int64_t keep_on_during_video_ms_pref_ = 3'000;

  FakePrefs prefs_;
  system::BacklightStub backlight_;
  system::AmbientLightSensorStub light_sensor_;
  system::DBusWrapperStub dbus_wrapper_;
  BacklightControllerObserverStub observer_;
  KeyboardBacklightController controller_;
};

TEST_F(KeyboardBacklightControllerTest, GetBrightnessPercent) {
  // Initialize the backlight, and simulate a button press to turn it on.
  Init();
  controller_.HandleUserActivity(USER_ACTIVITY_OTHER);

  // GetKeyboardBrightnessPercent should initially return the backlight's
  // starting level.  (It's safe to compare levels and percents since we're
  // using a [0, 100] range to make things simpler.)
  EXPECT_DOUBLE_EQ(static_cast<double>(initial_backlight_level_),
                   CallGetKeyboardBrightnessPercent());

  // After increasing the brightness, the new level should be returned.
  CallIncreaseKeyboardBrightness();
  EXPECT_DOUBLE_EQ(static_cast<double>(backlight_.current_level()),
                   CallGetKeyboardBrightnessPercent());
}

TEST_F(KeyboardBacklightControllerTest, GetBrightnessPercentWithScaling) {
  user_steps_pref_ = "0.0\n5.0\n20.0\n30.0\n50.0";
  initial_backlight_level_ = 0;
  Init();

  // Level              0    5   20   30    50
  // Raw percentages    0.0  5.0 20.0 30.0  50.0
  // Scaled percentages 0.0 10.0 40.0 60.0 100.0
  std::vector<double> scaled_percents{0.0, 10.0, 40.0, 60.0, 100.0};
  std::vector<int> levels{0, 5, 20, 30, 50};

  for (size_t i = 0; i < levels.size(); i++) {
    EXPECT_DOUBLE_EQ(scaled_percents[i], CallGetKeyboardBrightnessPercent());
    EXPECT_EQ(levels[i], backlight_.current_level());
    CallIncreaseKeyboardBrightness();
  }
}

TEST_F(KeyboardBacklightControllerTest, TurnOffFasterForFullscreenVideo) {
  als_steps_pref_ = "20.0 -1 50\n50.0 35 75\n75.0 60 -1";
  user_steps_pref_ = "0.0\n100.0";
  keep_on_ms_pref_ = 30'000;
  keep_on_during_video_ms_pref_ = 3'000;
  Init();
  controller_.HandleSessionStateChange(SessionState::STARTED);
  light_sensor_.NotifyObservers();

  // Non-fullscreen video shouldn't affect when the backlight is turned off.
  controller_.HandleUserActivity(USER_ACTIVITY_OTHER);
  controller_.HandleVideoActivity(false);
  EXPECT_EQ(20, backlight_.current_level());
  AdvanceTime(base::Milliseconds(keep_on_ms_pref_ / 2));
  EXPECT_EQ(20, backlight_.current_level());
  AdvanceTime(base::Milliseconds(keep_on_ms_pref_ / 2));
  EXPECT_EQ(0, backlight_.current_level());
  EXPECT_EQ(kSlowBacklightTransition, backlight_.current_interval());

  // When fullscreen video is playing, turn off the video after 3 seconds.
  controller_.HandleUserActivity(USER_ACTIVITY_OTHER);
  controller_.HandleVideoActivity(true);
  EXPECT_EQ(20, backlight_.current_level());
  AdvanceTime(base::Milliseconds(keep_on_during_video_ms_pref_));
  EXPECT_EQ(0, backlight_.current_level());
  EXPECT_EQ(kSlowBacklightTransition, backlight_.current_interval());

  // If the video switches to non-fullscreen, the backlight should be turned on
  // again.
  controller_.HandleVideoActivity(false);
  EXPECT_EQ(20, backlight_.current_level());
  EXPECT_EQ(kSlowBacklightTransition, backlight_.current_interval());

  // Let fullscreen video turn it off again.
  controller_.HandleVideoActivity(true);
  EXPECT_EQ(0, backlight_.current_level());
  EXPECT_EQ(kSlowBacklightTransition, backlight_.current_interval());

  // If the timeout fires to indicate that video has stopped, the backlight
  // should be turned on.
  AdvanceTime(KeyboardBacklightController::kVideoTimeoutInterval);
  EXPECT_EQ(20, backlight_.current_level());
  EXPECT_EQ(kFastBacklightTransition, backlight_.current_interval());

  // Fullscreen video should be ignored when the user isn't logged in.
  controller_.HandleSessionStateChange(SessionState::STOPPED);
  controller_.HandleVideoActivity(true);
  EXPECT_EQ(20, backlight_.current_level());

  // It should also be ignored after the brightness has been set by the user.
  controller_.HandleSessionStateChange(SessionState::STARTED);
  controller_.HandleVideoActivity(true);
  EXPECT_EQ(0, backlight_.current_level());
  CallIncreaseKeyboardBrightness();
  EXPECT_EQ(100, backlight_.current_level());
  controller_.HandleVideoActivity(true);
  EXPECT_EQ(100, backlight_.current_level());
  CallDecreaseKeyboardBrightness();
  EXPECT_EQ(0, backlight_.current_level());
  AdvanceTime(KeyboardBacklightController::kVideoTimeoutInterval);
  EXPECT_EQ(0, backlight_.current_level());
}

TEST_F(KeyboardBacklightControllerTest, OnAmbientLightUpdated) {
  initial_backlight_level_ = 20;
  als_steps_pref_ = "20.0 -1 50\n50.0 35 75\n75.0 60 -1";
  Init();

  // Press a button. Expect the backlight comes on to its startup value.
  controller_.HandleUserActivity(USER_ACTIVITY_OTHER);
  ASSERT_EQ(20, backlight_.current_level());
  EXPECT_EQ(0, controller_.GetNumAmbientLightSensorAdjustments());

  // ALS returns bad value.
  light_sensor_.set_lux(-1);
  light_sensor_.NotifyObservers();
  EXPECT_EQ(20, backlight_.current_level());

  // ALS returns a value in the middle of the initial step.
  light_sensor_.set_lux(25);
  light_sensor_.NotifyObservers();
  EXPECT_EQ(20, backlight_.current_level());

  // First increase; hysteresis not overcome.
  light_sensor_.set_lux(80);
  light_sensor_.NotifyObservers();
  EXPECT_EQ(20, backlight_.current_level());

  // Second increase; hysteresis overcome.  The lux is high enough that the
  // controller should skip over the middle step and use the top step.
  light_sensor_.NotifyObservers();
  EXPECT_EQ(75, backlight_.current_level());
  EXPECT_EQ(kSlowBacklightTransition, backlight_.current_interval());
  EXPECT_EQ(1, controller_.GetNumAmbientLightSensorAdjustments());

  // First decrease; hysteresis not overcome.
  light_sensor_.set_lux(50);
  light_sensor_.NotifyObservers();
  EXPECT_EQ(75, backlight_.current_level());

  // Second decrease; hysteresis overcome.  The controller should decrease
  // to the middle step.
  light_sensor_.NotifyObservers();
  EXPECT_EQ(50, backlight_.current_level());
  EXPECT_EQ(kSlowBacklightTransition, backlight_.current_interval());
  EXPECT_EQ(2, controller_.GetNumAmbientLightSensorAdjustments());

  // The count should be reset after a new session starts.
  controller_.HandleSessionStateChange(SessionState::STARTED);
  EXPECT_EQ(0, controller_.GetNumAmbientLightSensorAdjustments());
}

TEST_F(KeyboardBacklightControllerTest, InactivityInManualMode) {
  // Configure a single step for ALS and three steps for user control.
  als_steps_pref_ = "50.0 -1 -1";
  user_steps_pref_ = "0.0\n10.0\n100.0";
  initial_backlight_level_ = 50;
  Init();
  light_sensor_.NotifyObservers();
  controller_.HandleUserActivity(USER_ACTIVITY_OTHER);

  // Send an increase request to switch to user control.
  CallIncreaseKeyboardBrightness();
  EXPECT_EQ(100, backlight_.current_level());
  EXPECT_EQ(kFastBacklightTransition, backlight_.current_interval());

  // Requests to dim the backlight and turn it off should be honored, as
  // should changes to turn it back on and undim.
  controller_.SetDimmedForInactivity(true);
  EXPECT_EQ(GetDimmedLevel(), backlight_.current_level());
  EXPECT_EQ(kSlowBacklightTransition, backlight_.current_interval());
  controller_.SetOffForInactivity(true);
  EXPECT_EQ(0, backlight_.current_level());
  EXPECT_EQ(kSlowBacklightTransition, backlight_.current_interval());
  controller_.SetOffForInactivity(false);
  EXPECT_EQ(GetDimmedLevel(), backlight_.current_level());
  EXPECT_EQ(kSlowBacklightTransition, backlight_.current_interval());
  controller_.SetDimmedForInactivity(false);
  EXPECT_EQ(100, backlight_.current_level());
  EXPECT_EQ(kSlowBacklightTransition, backlight_.current_interval());
}

TEST_F(KeyboardBacklightControllerTest, DeferChangesWhileOffForInactivty) {
  als_steps_pref_ = "20.0 -1 60\n80.0 40 -1";
  initial_als_lux_ = 20;
  keep_on_ms_pref_ = 30'000;
  Init();

  // Ensure we use the correct initial value after user activity.
  controller_.HandleUserActivity(USER_ACTIVITY_OTHER);
  light_sensor_.NotifyObservers();
  ASSERT_EQ(initial_als_lux_, backlight_.current_level());

  // Turn off due to time passing.
  AdvanceTime(base::Milliseconds(keep_on_ms_pref_));
  EXPECT_EQ(backlight_.current_level(), 0);

  // ALS-driven changes shouldn't be applied while the keyboard backlight
  // is off.
  light_sensor_.set_lux(80);
  light_sensor_.NotifyObservers();
  light_sensor_.NotifyObservers();
  EXPECT_EQ(backlight_.current_level(), 0);

  // The new ALS level should be used immediately after user activity, though.
  controller_.HandleUserActivity(USER_ACTIVITY_OTHER);
  EXPECT_EQ(80, backlight_.current_level());
  EXPECT_EQ(backlight_.current_interval(), kFastBacklightTransition);
}

TEST_F(KeyboardBacklightControllerTest, InitialUserLevelDownFirst) {
  // Set user steps at 0, 10, 40, 60, and 100.  The backlight should remain
  // at its starting level when Init() is called.
  user_steps_pref_ = "0.0\n10.0\n40.0\n60.0\n100.0";
  initial_backlight_level_ = 15;
  Init();
  controller_.HandleUserActivity(USER_ACTIVITY_OTHER);
  EXPECT_EQ(15, backlight_.current_level());

  // After an increase request switches to user control of the brightness
  // level, the controller should first choose the step (10) nearest to the
  // initial level (15) and then increase to the next step (40).
  CallIncreaseKeyboardBrightness();
  EXPECT_EQ(40, backlight_.current_level());
  EXPECT_EQ(kFastBacklightTransition, backlight_.current_interval());
}

TEST_F(KeyboardBacklightControllerTest, InitialUserLevelUpFirst) {
  // Set user steps at 0, 10, 40, 60, and 100.  The backlight should remain
  // at its starting level when Init() is called.
  user_steps_pref_ = "0.0\n10.0\n40.0\n60.0\n100.0";
  initial_backlight_level_ = 30;
  Init();
  controller_.HandleUserActivity(USER_ACTIVITY_OTHER);
  EXPECT_EQ(30, backlight_.current_level());

  // After an increase request switches to user control of the brightness
  // level, the controller should first choose the step (40) nearest to the
  // initial level (30) and then increase to the next step (60).
  CallIncreaseKeyboardBrightness();
  EXPECT_EQ(60, backlight_.current_level());
  EXPECT_EQ(kFastBacklightTransition, backlight_.current_interval());
}

TEST_F(KeyboardBacklightControllerTest, InitialAlsLevel) {
  // Set an initial backlight level that's closest to the 60% step and
  // within its lux range of [50, 90].
  als_steps_pref_ = "0.0 -1 30\n30.0 20 60\n60.0 50 90\n100.0 80 -1";
  initial_backlight_level_ = 55;
  initial_als_lux_ = 85;
  Init();
  controller_.HandleUserActivity(USER_ACTIVITY_OTHER);
  EXPECT_EQ(55, backlight_.current_level());

  // After an ambient light reading, the controller should slowly
  // transition to the 60% level.
  light_sensor_.NotifyObservers();
  EXPECT_EQ(60, backlight_.current_level());
  EXPECT_EQ(kSlowBacklightTransition, backlight_.current_interval());
}

TEST_F(KeyboardBacklightControllerTest, InitialAlsLevelWithUserActivity) {
  als_steps_pref_ = "20.0 -1 60\n80.0 40 -1";
  initial_backlight_level_ = 55;
  Init();

  // Have the controller receiver user activity before the first sensor
  // reading is received.
  //
  // Expect that the backlight is turned on to its default level.
  controller_.HandleUserActivity(USER_ACTIVITY_OTHER);
  EXPECT_EQ(55, backlight_.current_level());
}

TEST_F(KeyboardBacklightControllerTest, IncreaseBrightness) {
  user_steps_pref_ = "0.0\n10.0\n40.0\n60.0\n100.0";
  initial_backlight_level_ = 0;
  Init();

  EXPECT_EQ(0, backlight_.current_level());

  dbus_wrapper_.ClearSentSignals();
  CallIncreaseKeyboardBrightness();
  test::CheckBrightnessChangedSignal(
      &dbus_wrapper_, 0, kKeyboardBrightnessChangedSignal, 10.0,
      BacklightBrightnessChange_Cause_USER_REQUEST);
  EXPECT_EQ(10, backlight_.current_level());
  EXPECT_EQ(kFastBacklightTransition, backlight_.current_interval());
  EXPECT_EQ(1, controller_.GetNumUserAdjustments());
  EXPECT_EQ(1, dbus_wrapper_.num_sent_signals());

  CallIncreaseKeyboardBrightness();
  EXPECT_EQ(40, backlight_.current_level());
  EXPECT_EQ(2, controller_.GetNumUserAdjustments());
  EXPECT_EQ(2, dbus_wrapper_.num_sent_signals());

  CallIncreaseKeyboardBrightness();
  EXPECT_EQ(60, backlight_.current_level());
  EXPECT_EQ(3, controller_.GetNumUserAdjustments());
  EXPECT_EQ(3, dbus_wrapper_.num_sent_signals());

  CallIncreaseKeyboardBrightness();
  EXPECT_EQ(100, backlight_.current_level());
  EXPECT_EQ(4, controller_.GetNumUserAdjustments());
  EXPECT_EQ(4, dbus_wrapper_.num_sent_signals());

  // A no-op increase should still emit a signal.
  dbus_wrapper_.ClearSentSignals();
  CallIncreaseKeyboardBrightness();
  test::CheckBrightnessChangedSignal(
      &dbus_wrapper_, 0, kKeyboardBrightnessChangedSignal, 100.0,
      BacklightBrightnessChange_Cause_USER_REQUEST);
  EXPECT_EQ(1, dbus_wrapper_.num_sent_signals());
  EXPECT_EQ(100, backlight_.current_level());
  EXPECT_EQ(5, controller_.GetNumUserAdjustments());

  // The count should be reset after a new session starts.
  controller_.HandleSessionStateChange(SessionState::STARTED);
  EXPECT_EQ(0, controller_.GetNumUserAdjustments());
}

TEST_F(KeyboardBacklightControllerTest, DecreaseBrightness) {
  user_steps_pref_ = "0.0\n10.0\n40.0\n60.0\n100.0";
  initial_backlight_level_ = 100;
  Init();
  controller_.HandleUserActivity(USER_ACTIVITY_OTHER);

  EXPECT_EQ(100, backlight_.current_level());

  dbus_wrapper_.ClearSentSignals();
  CallDecreaseKeyboardBrightness();
  test::CheckBrightnessChangedSignal(
      &dbus_wrapper_, 0, kKeyboardBrightnessChangedSignal, 60.0,
      BacklightBrightnessChange_Cause_USER_REQUEST);
  EXPECT_EQ(60, backlight_.current_level());
  EXPECT_EQ(kFastBacklightTransition, backlight_.current_interval());
  EXPECT_EQ(1, controller_.GetNumUserAdjustments());
  EXPECT_EQ(1, dbus_wrapper_.num_sent_signals());

  CallDecreaseKeyboardBrightness();
  EXPECT_EQ(40, backlight_.current_level());
  EXPECT_EQ(2, controller_.GetNumUserAdjustments());
  EXPECT_EQ(2, dbus_wrapper_.num_sent_signals());

  CallDecreaseKeyboardBrightness();
  EXPECT_EQ(10, backlight_.current_level());
  EXPECT_EQ(3, controller_.GetNumUserAdjustments());
  EXPECT_EQ(3, dbus_wrapper_.num_sent_signals());

  CallDecreaseKeyboardBrightness();
  EXPECT_EQ(0, backlight_.current_level());
  EXPECT_EQ(4, controller_.GetNumUserAdjustments());
  EXPECT_EQ(4, dbus_wrapper_.num_sent_signals());

  // A no-op decrease should still emit a signal.
  dbus_wrapper_.ClearSentSignals();
  CallDecreaseKeyboardBrightness();
  test::CheckBrightnessChangedSignal(
      &dbus_wrapper_, 0, kKeyboardBrightnessChangedSignal, 0.0,
      BacklightBrightnessChange_Cause_USER_REQUEST);
  EXPECT_EQ(1, dbus_wrapper_.num_sent_signals());
  EXPECT_EQ(0, backlight_.current_level());
  EXPECT_EQ(5, controller_.GetNumUserAdjustments());
}

TEST_F(KeyboardBacklightControllerTest, TurnOffWhenSuspended) {
  initial_backlight_level_ = 50;
  no_als_brightness_pref_ = 50;
  pass_light_sensor_ = false;
  Init();
  controller_.HandleUserActivity(USER_ACTIVITY_OTHER);
  controller_.SetSuspended(true);
  EXPECT_EQ(0, backlight_.current_level());
  EXPECT_EQ(0, backlight_.current_interval().InMilliseconds());

  controller_.SetSuspended(false);
  EXPECT_EQ(50, backlight_.current_level());
}

TEST_F(KeyboardBacklightControllerTest, TurnOffWhenShuttingDown) {
  Init();
  controller_.HandleUserActivity(USER_ACTIVITY_OTHER);

  controller_.SetShuttingDown(true);
  EXPECT_EQ(0, backlight_.current_level());
  EXPECT_EQ(0, backlight_.current_interval().InMilliseconds());
}

TEST_F(KeyboardBacklightControllerTest, TurnOffWhenLidClosed) {
  initial_lid_state_ = LidState::OPEN;
  Init();
  controller_.HandleUserActivity(USER_ACTIVITY_OTHER);
  ASSERT_EQ(initial_backlight_level_, backlight_.current_level());

  controller_.HandleLidStateChange(LidState::CLOSED);
  EXPECT_EQ(0, backlight_.current_level());
  EXPECT_EQ(0, backlight_.current_interval().InMilliseconds());

  // User requests to increase the brightness shouldn't turn the backlight on.
  CallIncreaseKeyboardBrightness();
  EXPECT_EQ(0, backlight_.current_level());
}

TEST_F(KeyboardBacklightControllerTest, Hover) {
  als_steps_pref_ = "50.0 -1 -1";
  user_steps_pref_ = "0.0\n100.0";
  detect_hover_pref_ = 1;
  keep_on_ms_pref_ = 30000;
  keep_on_during_video_ms_pref_ = 3000;
  initial_backlight_level_ = 0;
  Init();
  controller_.HandleSessionStateChange(SessionState::STARTED);
  light_sensor_.NotifyObservers();

  // The backlight should initially be off since the user isn't hovering.
  EXPECT_EQ(0, backlight_.current_level());

  // If hovering is detected, the backlight should be turned on quickly.
  controller_.HandleHoverStateChange(true);
  EXPECT_EQ(50, backlight_.current_level());
  EXPECT_EQ(kFastBacklightTransition, backlight_.current_interval());

  // It should remain on despite fullscreen video if hovering continues.
  controller_.HandleVideoActivity(true);
  EXPECT_EQ(50, backlight_.current_level());

  // It should remain on for a short period of time if hovering stops while the
  // video is still playing.
  controller_.HandleHoverStateChange(false);
  EXPECT_EQ(50, backlight_.current_level());

  // After enough time, the backlight should turn off.
  AdvanceTime(base::Milliseconds(keep_on_during_video_ms_pref_));
  EXPECT_EQ(0, backlight_.current_level());
  EXPECT_EQ(kSlowBacklightTransition, backlight_.current_interval());

  // Stop the video. Since the user was hovering recently, the backlight should
  // turn back on.
  AdvanceTime(KeyboardBacklightController::kVideoTimeoutInterval);
  EXPECT_EQ(50, backlight_.current_level());
  EXPECT_EQ(kFastBacklightTransition, backlight_.current_interval());

  // After the rest of the full timeout, the backlight should turn off slowly.
  AdvanceTime(
      base::Milliseconds(keep_on_ms_pref_ - keep_on_during_video_ms_pref_) -
      KeyboardBacklightController::kVideoTimeoutInterval);
  EXPECT_EQ(0, backlight_.current_level());
  EXPECT_EQ(kSlowBacklightTransition, backlight_.current_interval());

  // User activity should also turn the keyboard backlight on for the full
  // delay.
  controller_.HandleUserActivity(USER_ACTIVITY_OTHER);
  EXPECT_EQ(50, backlight_.current_level());
  EXPECT_EQ(kFastBacklightTransition, backlight_.current_interval());
  AdvanceTime(base::Milliseconds(keep_on_ms_pref_));
  EXPECT_EQ(0, backlight_.current_level());
  EXPECT_EQ(kSlowBacklightTransition, backlight_.current_interval());

  // Increase the brightness to 100, dim for inactivity, and check that hover
  // restores the user-requested level.
  CallIncreaseKeyboardBrightness();
  EXPECT_EQ(100, backlight_.current_level());
  controller_.SetDimmedForInactivity(true);
  EXPECT_EQ(GetDimmedLevel(), backlight_.current_level());
  controller_.HandleHoverStateChange(true);
  EXPECT_EQ(100, backlight_.current_level());
  EXPECT_EQ(kFastBacklightTransition, backlight_.current_interval());

  // The backlight should stay on while hovering even if it's requested to turn
  // off for inactivity.
  controller_.SetOffForInactivity(true);
  EXPECT_EQ(100, backlight_.current_level());

  // Stop hovering and check that starting again turns the backlight on again.
  controller_.HandleHoverStateChange(false);
  EXPECT_EQ(0, backlight_.current_level());
  EXPECT_EQ(kSlowBacklightTransition, backlight_.current_interval());
  controller_.HandleHoverStateChange(true);
  EXPECT_EQ(100, backlight_.current_level());
  EXPECT_EQ(kFastBacklightTransition, backlight_.current_interval());

  // A notification that the system is shutting down should take precedence.
  controller_.SetShuttingDown(true);
  EXPECT_EQ(0, backlight_.current_level());
}

TEST_F(KeyboardBacklightControllerTest, NoAmbientLightSensor) {
  initial_backlight_level_ = 0;
  no_als_brightness_pref_ = 40.0;
  user_steps_pref_ = "0.0\n10.0\n100.0";
  pass_light_sensor_ = false;
  Init();

  // The brightness should start at the level from the pref.
  controller_.HandleUserActivity(USER_ACTIVITY_OTHER);
  EXPECT_EQ(40, backlight_.current_level());
  EXPECT_EQ(kFastBacklightTransition, backlight_.current_interval());

  // Subsequent adjustments should move between the user steps.
  CallIncreaseKeyboardBrightness();
  EXPECT_EQ(100, backlight_.current_level());
  CallDecreaseKeyboardBrightness();
  EXPECT_EQ(10, backlight_.current_level());
}

TEST_F(KeyboardBacklightControllerTest, EnableForUserActivity) {
  initial_backlight_level_ = 50;
  no_als_brightness_pref_ = 40.0;
  user_steps_pref_ = "0.0\n100.0";
  keep_on_ms_pref_ = 30000;
  pass_light_sensor_ = false;
  Init();

  // The backlight should turn off initially.
  EXPECT_EQ(0, backlight_.current_level());
  EXPECT_EQ(kSlowBacklightTransition, backlight_.current_interval());

  // User activity should result in the backlight being turned on quickly.
  controller_.HandleUserActivity(USER_ACTIVITY_OTHER);
  EXPECT_EQ(40, backlight_.current_level());
  EXPECT_EQ(kFastBacklightTransition, backlight_.current_interval());

  // Advance the time and report user activity again.
  AdvanceTime(base::Milliseconds(keep_on_ms_pref_ / 2));
  controller_.HandleUserActivity(USER_ACTIVITY_OTHER);
  EXPECT_EQ(40, backlight_.current_level());

  // The backlight should be turned off |keep_on_ms_pref_| after the last report
  // of user activity.
  AdvanceTime(base::Milliseconds(keep_on_ms_pref_));
  EXPECT_EQ(0, backlight_.current_level());
  EXPECT_EQ(kSlowBacklightTransition, backlight_.current_interval());
}

TEST_F(KeyboardBacklightControllerTest, EnableForPowerSourceChange) {
  initial_backlight_level_ = 50;
  no_als_brightness_pref_ = 40.0;
  user_steps_pref_ = "0.0\n100.0";
  keep_on_ms_pref_ = 30'000;
  pass_light_sensor_ = false;
  Init();

  // The backlight should be off initially.
  EXPECT_EQ(0, backlight_.current_level());
  EXPECT_EQ(kSlowBacklightTransition, backlight_.current_interval());

  // The first report of a power source is shouldn't turn the backlight on,
  // but just be recorded as the initial power source state.
  controller_.HandlePowerSourceChange(PowerSource::AC);
  EXPECT_EQ(0, backlight_.current_level());

  // When the device is unplugged from AC, the backlight should come on.
  controller_.HandlePowerSourceChange(PowerSource::BATTERY);
  EXPECT_EQ(40, backlight_.current_level());
  EXPECT_EQ(kFastBacklightTransition, backlight_.current_interval());
  EXPECT_EQ(test::GetLastBrightnessChangedSignal(&dbus_wrapper_).cause(),
            BacklightBrightnessChange_Cause_EXTERNAL_POWER_DISCONNECTED);

  // After a period of inactivity, the backlight should slowly turn off again.
  AdvanceTime(base::Milliseconds(keep_on_ms_pref_));
  EXPECT_EQ(0, backlight_.current_level());
  EXPECT_EQ(kSlowBacklightTransition, backlight_.current_interval());

  // A repeated notification that the device is connected to battery
  // shouldn't update the brightness.
  controller_.HandlePowerSourceChange(PowerSource::BATTERY);
  EXPECT_EQ(0, backlight_.current_level());

  // However, when the device is plugged back into AC, the backlight should
  // turn on once more.
  controller_.HandlePowerSourceChange(PowerSource::AC);
  EXPECT_EQ(40, backlight_.current_level());
  EXPECT_EQ(kFastBacklightTransition, backlight_.current_interval());
  EXPECT_EQ(test::GetLastBrightnessChangedSignal(&dbus_wrapper_).cause(),
            BacklightBrightnessChange_Cause_EXTERNAL_POWER_CONNECTED);
}

TEST_F(KeyboardBacklightControllerTest, PreemptTransitionForShutdown) {
  initial_backlight_level_ = 50;
  keep_on_ms_pref_ = 30'000;
  Init();
  controller_.HandleUserActivity(USER_ACTIVITY_OTHER);

  // Wait 30 seconds to start fading for user inactivty.
  AdvanceTime(base::Milliseconds(keep_on_ms_pref_));
  EXPECT_EQ(0, backlight_.current_level());
  EXPECT_EQ(kSlowBacklightTransition, backlight_.current_interval());

  // Now notify the keyboard controller that the system is shutting down and
  // check that the previous transition is preempted in favor of turning off the
  // keyboard backlight immediately.
  backlight_.set_transition_in_progress(true);
  controller_.SetShuttingDown(true);
  EXPECT_EQ(0, backlight_.current_level());
  EXPECT_EQ(0, backlight_.current_interval().InMilliseconds());
}

TEST_F(KeyboardBacklightControllerTest, TurnOffWhenInTabletMode) {
  // The backlight should be initially turned off if the device is already in
  // tablet mode.
  initial_backlight_level_ = 100;
  no_als_brightness_pref_ = 100.0;
  pass_light_sensor_ = false;
  initial_tablet_mode_ = TabletMode::ON;
  Init();
  controller_.HandleUserActivity(USER_ACTIVITY_OTHER);
  EXPECT_EQ(0, backlight_.current_level());
  EXPECT_EQ(kSlowBacklightTransition, backlight_.current_interval());

  // It should quickly turn on when the device leaves tablet mode.
  controller_.HandleTabletModeChange(TabletMode::OFF);
  EXPECT_EQ(100, backlight_.current_level());
  EXPECT_EQ(kFastBacklightTransition, backlight_.current_interval());

  // Going back to tablet mode should turn the backlight off again.
  controller_.HandleTabletModeChange(TabletMode::ON);
  EXPECT_EQ(0, backlight_.current_level());
  EXPECT_EQ(kFastBacklightTransition, backlight_.current_interval());
}

TEST_F(KeyboardBacklightControllerTest, ForcedOff) {
  initial_backlight_level_ = 50;
  Init();
  controller_.HandleUserActivity(USER_ACTIVITY_OTHER);
  ASSERT_GT(backlight_.current_level(), 0);

  controller_.SetForcedOff(true);
  EXPECT_EQ(0, backlight_.current_level());
  EXPECT_EQ(0, backlight_.current_interval().InMilliseconds());

  controller_.SetForcedOff(false);
  EXPECT_GT(backlight_.current_level(), 0);
  EXPECT_EQ(0, backlight_.current_interval().InMilliseconds());
}

TEST_F(KeyboardBacklightControllerTest, ToggleKeyboardBacklight) {
  // Initial brightness is zero.
  initial_backlight_level_ = 0;
  user_steps_pref_ = "0.0\n10.0\n40.0\n60.0\n100.0";
  Init();
  ASSERT_EQ(backlight_.current_level(), 0);

  // Increase the brightness twice, as if the user did two increases with the
  // keyboard.
  CallIncreaseKeyboardBrightness();
  CallIncreaseKeyboardBrightness();
  EXPECT_EQ(backlight_.current_level(), 40);

  // Toggle keyboard backlight. Brightness should instantly move to zero.
  CallToggleKeyboardBacklight();
  EXPECT_EQ(CallGetKeyboardBrightnessPercent(), 0);
  EXPECT_EQ(backlight_.current_level(), 0);
  EXPECT_EQ(backlight_.current_interval().InMilliseconds(), 0);

  // Toggle keyboard backlight. Brightness should now be what it was before we
  // toggled off.
  CallToggleKeyboardBacklight();
  EXPECT_EQ(CallGetKeyboardBrightnessPercent(), 40.0);
  EXPECT_EQ(backlight_.current_level(), 40);
  EXPECT_EQ(backlight_.current_interval().InMilliseconds(), 0);

  // "Manually" turn the brightness all the way down.
  while (backlight_.current_level() > 0) {
    CallDecreaseKeyboardBrightness();
  }
  EXPECT_EQ(backlight_.current_level(), 0);
  EXPECT_EQ(CallGetKeyboardBrightnessPercent(), 0.0);

  // Toggle the backlight. It should come on again at the last non-zero
  // brightness we set.
  CallToggleKeyboardBacklight();
  EXPECT_EQ(CallGetKeyboardBrightnessPercent(), 10.0);
  EXPECT_EQ(backlight_.current_level(), 10.0);
  EXPECT_EQ(backlight_.current_interval().InMilliseconds(), 0);
}

TEST_F(KeyboardBacklightControllerTest, ToggleBacklightAfterInactivity) {
  // Set up a system with no ALS, but user activity-based dimming enabled.
  user_steps_pref_ = "0.0\n10.0\n40.0\n60.0\n100.0";
  pass_light_sensor_ = false;
  no_als_brightness_pref_ = 40.0;
  keep_on_ms_pref_ = 30'000;  // 30 seconds
  initial_backlight_level_ = 40.0;
  Init();

  // Wait for the backlight to dim due to inactivity.
  AdvanceTime(base::Milliseconds(keep_on_ms_pref_));
  EXPECT_EQ(backlight_.current_level(), 0);

  // Hit the toggle button. Backlight should come back to the default value.
  CallToggleKeyboardBacklight();
  EXPECT_EQ(backlight_.current_level(), 40.0);

  // Now that it has been manually set, the backlight should not dim
  // after the keep-on delay expires.
  AdvanceTime(base::Milliseconds(keep_on_ms_pref_));
  EXPECT_EQ(backlight_.current_level(), 40.0);

  // However, it should still dim an turn off for the system-wide inactivity.
  controller_.SetDimmedForInactivity(true);
  EXPECT_EQ(backlight_.current_level(), 10.0);
  controller_.SetOffForInactivity(true);
  EXPECT_EQ(backlight_.current_level(), 0.0);
}

TEST_F(KeyboardBacklightControllerTest, ToggleBacklightAfterUserActivity) {
  // Set up a system with no ALS, but user activity-based dimming enabled.
  user_steps_pref_ = "0.0\n10.0\n40.0\n60.0\n100.0";
  pass_light_sensor_ = false;
  no_als_brightness_pref_ = 40.0;
  keep_on_ms_pref_ = 30'000;  // 30 seconds
  initial_backlight_level_ = 40.0;
  Init();

  // Notify about user activity. Backlight should be on.
  controller_.HandleUserActivity(USER_ACTIVITY_OTHER);
  EXPECT_EQ(backlight_.current_level(), 40.0);

  // Hit the toggle button. Backlight should turn off.
  CallToggleKeyboardBacklight();
  EXPECT_EQ(backlight_.current_level(), 0.0);

  // Further user activity shouldn't turn it on again.
  controller_.HandleUserActivity(USER_ACTIVITY_OTHER);
  EXPECT_EQ(backlight_.current_level(), 0);
}

TEST_F(KeyboardBacklightControllerTest, ToggleBacklightAfterAlsDim) {
  // Set up a system with an ALS in bright light, such that the keyboard
  // backlight is turned off.
  user_steps_pref_ = "0.0\n10.0\n40.0\n60.0\n100.0";
  als_steps_pref_ = "30.0 -1 20\n0.0 40 -1";
  initial_backlight_level_ = 60;
  initial_als_lux_ = 100;
  Init();

  // Expect the backlight to turn off.
  light_sensor_.NotifyObservers();
  EXPECT_EQ(0, backlight_.current_level());

  // Hit the toggle button. The backlight should turn on to the backlight's
  // initial value.
  CallToggleKeyboardBacklight();
  EXPECT_EQ(backlight_.current_level(), 60.0);
}

TEST_F(KeyboardBacklightControllerTest,
       ToggleBacklightAfterAlsDimNoInitialBrightness) {
  // Set up a system with an ALS in bright light, such that the keyboard
  // backlight is turned off.
  user_steps_pref_ = "0.0\n10.0\n40.0\n60.0\n100.0";
  als_steps_pref_ = "30.0 -1 20\n0.0 40 -1";
  initial_backlight_level_ = 0;
  initial_als_lux_ = 100;
  Init();

  // Expect the backlight to turn off.
  light_sensor_.NotifyObservers();
  EXPECT_EQ(0, backlight_.current_level());

  // Hit the toggle button. Because the backlight wasn't on at init time,
  // we use the first non-zero user step.
  CallToggleKeyboardBacklight();
  EXPECT_EQ(backlight_.current_level(), 10.0);
}

TEST_F(KeyboardBacklightControllerTest, SetKeyboardBrightness) {
  initial_backlight_level_ = 0;
  user_steps_pref_ = "0.0\n10.0\n40.0\n60.0\n100.0";
  Init();
  EXPECT_EQ(backlight_.current_level(), 0);

  // Call SetUserBrightness, and ensure the brightness was updated and
  // a signal emitted.
  CallSetKeyboardBrightness(/*percent=*/45,
                            SetBacklightBrightnessRequest_Transition_FAST,
                            SetBacklightBrightnessRequest_Cause_USER_REQUEST);
  EXPECT_EQ(backlight_.current_level(), 45);
  test::CheckBrightnessChangedSignal(
      &dbus_wrapper_, 0, kKeyboardBrightnessChangedSignal,
      /*brightness_percent=*/45.0,
      BacklightBrightnessChange_Cause_USER_REQUEST);
}

TEST_F(KeyboardBacklightControllerTest,
       SetKeyboardBrightnessLowBrightnessValues) {
  initial_backlight_level_ = 0;
  user_steps_pref_ = "0.0\n10.0\n40.0\n60.0\n100.0";
  Init();
  EXPECT_EQ(backlight_.current_level(), 0);

  // Calls with a brightness >= 10 should use the user-specified value.
  CallSetKeyboardBrightness(/*percent=*/10,
                            SetBacklightBrightnessRequest_Transition_FAST,
                            SetBacklightBrightnessRequest_Cause_USER_REQUEST);
  EXPECT_EQ(backlight_.current_level(), 10);

  // Calls with a brightness < 10 should be truncated to zero.
  CallSetKeyboardBrightness(/*percent=*/9.5,
                            SetBacklightBrightnessRequest_Transition_FAST,
                            SetBacklightBrightnessRequest_Cause_USER_REQUEST);
  EXPECT_EQ(backlight_.current_level(), 0);
}

TEST_F(KeyboardBacklightControllerTest,
       SetKeyboardBrightnessSetsManualControl) {
  // Set up a system with no ALS, but user activity-based dimming enabled.
  user_steps_pref_ = "0.0\n10.0\n40.0\n60.0\n100.0";
  pass_light_sensor_ = false;
  no_als_brightness_pref_ = 40.0;
  keep_on_ms_pref_ = 30'000;  // 30 seconds
  initial_backlight_level_ = 40.0;
  Init();

  // Wait 30 seconds for the backlight to turn off due to inactivity.
  AdvanceTime(base::Milliseconds(keep_on_ms_pref_));
  EXPECT_EQ(backlight_.current_level(), 0);

  // Call SetUserBrightness with a custom brightness. Backlight should turn on.
  CallSetKeyboardBrightness(/*percent=*/45,
                            SetBacklightBrightnessRequest_Transition_FAST,
                            SetBacklightBrightnessRequest_Cause_USER_REQUEST);
  EXPECT_EQ(backlight_.current_level(), 45);

  // The backlight should remain on, even after `keep_on_ms_pref_` has passed.
  AdvanceTime(base::Milliseconds(keep_on_ms_pref_));
  EXPECT_EQ(backlight_.current_level(), 45);
}

TEST_F(KeyboardBacklightControllerTest, SetKeyboardBrightnessWithIncrease) {
  initial_backlight_level_ = 0;
  user_steps_pref_ = "0.0\n10.0\n40.0\n60.0\n100.0";
  Init();
  ASSERT_EQ(backlight_.current_level(), 0);

  // Call SetUserBrightness, followed by an increase in brightness for various
  // values. The brightness should jump up by a non-trivial step.
  struct TestCase {
    double set_brightness;
    double expected;
  };
  for (TestCase test_case : std::vector<TestCase>{
           {0, 10},
           {1, 10},
           {10, 40},
           {11, 40},
           {39, 60},
           {41, 60},
           {85, 100},
           {99, 100},
           {100, 100},
       }) {
    SCOPED_TRACE(base::StringPrintf(
        "Setting brightness to %lf%% followed by an increase",
        test_case.set_brightness));

    // Manually set a brightness, followed by an increase.
    CallSetKeyboardBrightness(/*percent=*/test_case.set_brightness,
                              SetBacklightBrightnessRequest_Transition_FAST,
                              SetBacklightBrightnessRequest_Cause_USER_REQUEST);
    CallIncreaseKeyboardBrightness();

    EXPECT_EQ(backlight_.current_level(), test_case.expected);
  }
}

TEST_F(KeyboardBacklightControllerTest, SetKeyboardBrightnessWithDecrease) {
  initial_backlight_level_ = 0;
  user_steps_pref_ = "0.0\n10.0\n40.0\n60.0\n100.0";
  Init();
  ASSERT_EQ(backlight_.current_level(), 0);

  // Call SetUserBrightness, followed by an decrease in brightness for various
  // values. The brightness should decrease by a non-trivial step.
  struct TestCase {
    double set_brightness;
    double expected;
  };
  for (TestCase test_case : std::vector<TestCase>{
           {0, 0},
           {1, 0},
           {10, 0},
           {11, 0},
           {41, 10},
           {59, 40},
           {61, 40},
           {99, 60},
           {100, 60},
       }) {
    SCOPED_TRACE(
        base::StringPrintf("Setting brightness to %lf%% followed by a decrease",
                           test_case.set_brightness));

    // Manually set a brightness, followed by a decrease.
    CallSetKeyboardBrightness(/*percent=*/test_case.set_brightness,
                              SetBacklightBrightnessRequest_Transition_FAST,
                              SetBacklightBrightnessRequest_Cause_USER_REQUEST);
    CallDecreaseKeyboardBrightness();

    EXPECT_EQ(backlight_.current_level(), test_case.expected);
  }
}

TEST_F(KeyboardBacklightControllerTest,
       SetKeyboardBrightnessWithBadBrightness) {
  initial_backlight_level_ = 0;
  user_steps_pref_ = "0.0\n10.0\n40.0\n60.0\n100.0";
  Init();

  // Test bad `brightness` values.
  struct TestCase {
    double set_brightness;
    double expected;
  };
  for (TestCase test_case : std::vector<TestCase>{
           {-3, 0},
           {103, 100},
           {std::numeric_limits<double>::infinity(), 100},
           {-std::numeric_limits<double>::infinity(), 0},
           {std::nan("nan"), 0},
       }) {
    SCOPED_TRACE(base::StringPrintf("Testing input brightness of %lf%%",
                                    test_case.set_brightness));
    CallSetKeyboardBrightness(test_case.set_brightness,
                              SetBacklightBrightnessRequest_Transition_FAST,
                              SetBacklightBrightnessRequest_Cause_USER_REQUEST);
    EXPECT_EQ(backlight_.current_level(), test_case.expected);
  }
}

TEST_F(KeyboardBacklightControllerTest, ChangeBacklightDevice) {
  // Start out without a backlight device.
  user_steps_pref_ = "0.0\n50.0\n100.0";
  backlight_.set_device_exists(false);
  Init();
  CallIncreaseKeyboardBrightness();
  controller_.SetOffForInactivity(true);

  // Connect a device and check that the earlier off state is applied to it.
  backlight_.set_device_exists(true);
  backlight_.NotifyDeviceChanged();
  EXPECT_EQ(0, backlight_.current_level());
  controller_.SetOffForInactivity(false);
  CallIncreaseKeyboardBrightness();
  CallIncreaseKeyboardBrightness();
  EXPECT_EQ(max_backlight_level_, backlight_.current_level());

  // Disconnect the device and check that decrease requests are ignored.
  backlight_.set_device_exists(false);
  backlight_.NotifyDeviceChanged();
  CallDecreaseKeyboardBrightness();

  // The previous 100% brightness should be reapplied to a new device with a
  // different range.
  backlight_.set_device_exists(true);
  backlight_.set_max_level(200);
  backlight_.set_current_level(100);
  backlight_.NotifyDeviceChanged();
  EXPECT_EQ(200, backlight_.current_level());
}

TEST_F(KeyboardBacklightControllerTest, EmptyUserSteps) {
  user_steps_pref_ = "";
  EXPECT_DEATH(
      Init(),
      "No user brightness steps defined in keyboard_backlight_user_steps");
}

TEST_F(KeyboardBacklightControllerTest, UserStepsNotStartAt0) {
  user_steps_pref_ = "10.0\n50.0\n100.0";
  EXPECT_DEATH(
      Init(),
      "keyboard_backlight_user_steps starts at 10.000000 instead of 0.0");
}

TEST_F(KeyboardBacklightControllerTest, UserStepsTooBig) {
  user_steps_pref_ = "0.0\n50.0\n110.0";
  EXPECT_DEATH(Init(),
               "keyboard_backlight_user_steps step 110.000000 is outside "
               "\\[0.0, 100.0]");
}

TEST_F(KeyboardBacklightControllerTest, UserStepsTooSmall) {
  user_steps_pref_ = "0.0\n-10.0\n100.0";
  EXPECT_DEATH(Init(),
               "keyboard_backlight_user_steps step -10.000000 is outside "
               "\\[0.0, 100.0]");
}

TEST_F(KeyboardBacklightControllerTest, UserStepsNotStrictlyIncreasing) {
  user_steps_pref_ = "0.0\n0.0\n100.0";
  EXPECT_DEATH(Init(),
               "keyboard_backlight_user_steps is not strictly increasing");
}

TEST_F(KeyboardBacklightControllerTest, SetKeyboardBrightnessDbusCall) {
  Init();

  // Ensure we can call the "SetKeyboardBrightness" DBus API call.
  EXPECT_NO_FATAL_FAILURE(CallSetKeyboardBrightness(
      /*percent=*/50,
      SetBacklightBrightnessRequest_Transition::
          SetBacklightBrightnessRequest_Transition_FAST,
      SetBacklightBrightnessRequest_Cause::
          SetBacklightBrightnessRequest_Cause_USER_REQUEST));
}

}  // namespace power_manager::policy
