// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/powerd/policy/external_backlight_controller.h"

#include <base/compiler_specific.h>
#include <chromeos/dbus/service_constants.h>
#include <gtest/gtest.h>
#include <string>
#include <utility>

#include "power_manager/common/fake_prefs.h"
#include "power_manager/powerd/policy/backlight_controller_observer_stub.h"
#include "power_manager/powerd/policy/backlight_controller_test_util.h"
#include "power_manager/powerd/system/ambient_light_sensor_watcher_stub.h"
#include "power_manager/powerd/system/dbus_wrapper_stub.h"
#include "power_manager/powerd/system/display/display_power_setter_stub.h"
#include "power_manager/powerd/system/display/display_watcher_stub.h"
#include "power_manager/powerd/system/external_ambient_light_sensor_factory_stub.h"
#include "power_manager/powerd/testing/test_environment.h"
#include "power_manager/proto_bindings/backlight.pb.h"

namespace {

constexpr char kFirstDisplay[] = "/sys/devices/usb1/mydisplay";
constexpr char kFirstSensor[] = "/sys/devices/usb1/mysensor";
constexpr char kSecondDisplay[] = "/sys/devices/usb2/mydisplay";
constexpr char kSecondSensor[] = "/sys/devices/usb2/mysensor";

}  // namespace

namespace power_manager::policy {

class ExternalBacklightControllerTest : public TestEnvironment {
 public:
  ExternalBacklightControllerTest() {
    prefs_.SetString(kExternalBacklightAlsStepsPref, default_als_steps_);
    controller_.AddObserver(&observer_);
    controller_.Init(&prefs_, &ambient_light_sensor_watcher_,
                     &ambient_light_sensor_factory_, &display_watcher_,
                     &display_power_setter_, &dbus_wrapper_);
  }

  ~ExternalBacklightControllerTest() override {
    controller_.RemoveObserver(&observer_);
  }

 protected:
  void AddDisplay(const std::string& syspath) {
    system::DisplayInfo display = {
        .drm_path = base::FilePath(),
        .i2c_path = base::FilePath("/dev/i2c-1"),
        .sys_path = base::FilePath(syspath),
        .connector_status = system::DisplayInfo::ConnectorStatus::CONNECTED,
    };
    display_watcher_.AddDisplay(display);
  }
  void RemoveDisplay(const std::string& syspath) {
    system::DisplayInfo display = {
        .drm_path = base::FilePath(),
        .i2c_path = base::FilePath("/dev/i2c-1"),
        .sys_path = base::FilePath(syspath),
        .connector_status = system::DisplayInfo::ConnectorStatus::CONNECTED,
    };
    display_watcher_.RemoveDisplay(display);
  }
  void AddSensor(const std::string& syspath) {
    system::AmbientLightSensorInfo als = {
        .iio_path = base::FilePath(syspath),
        .device = std::string(),
    };
    ambient_light_sensor_watcher_.AddSensor(als);
  }
  void RemoveSensor(const std::string& syspath) {
    system::AmbientLightSensorInfo als = {
        .iio_path = base::FilePath(syspath),
        .device = std::string(),
    };
    ambient_light_sensor_watcher_.RemoveSensor(als);
  }

  void CallSetExternalDisplayALSBrightness(bool enabled) {
    dbus::MethodCall method_call(kPowerManagerInterface,
                                 kSetExternalDisplayALSBrightnessMethod);
    dbus::MessageWriter writer(&method_call);
    writer.AppendBool(enabled);
    ASSERT_TRUE(dbus_wrapper_.CallExportedMethodSync(&method_call));
  }

  void CallGetExternalDisplayALSBrightness(bool* enabled) {
    dbus::MethodCall method_call(kPowerManagerInterface,
                                 kGetExternalDisplayALSBrightnessMethod);
    dbus::MessageWriter writer(&method_call);
    std::unique_ptr<dbus::Response> response =
        dbus_wrapper_.CallExportedMethodSync(&method_call);
    ASSERT_TRUE(response.get());
    ASSERT_TRUE(dbus::MessageReader(response.get()).PopBool(enabled));
  }

  std::string default_als_steps_ = "5.0 -1 600\n100.0 500 -1";

  FakePrefs prefs_;
  BacklightControllerObserverStub observer_;
  system::AmbientLightSensorWatcherStub ambient_light_sensor_watcher_;
  system::ExternalAmbientLightSensorFactoryStub ambient_light_sensor_factory_;
  system::DisplayWatcherStub display_watcher_;
  system::DisplayPowerSetterStub display_power_setter_;
  system::DBusWrapperStub dbus_wrapper_;
  ExternalBacklightController controller_;
};

TEST_F(ExternalBacklightControllerTest, BrightnessRequests) {
  // ExternalBacklightController doesn't support absolute-brightness-related
  // requests, but it does allow relative adjustments.
  double percent = 0.0;
  EXPECT_FALSE(controller_.GetBrightnessPercent(&percent));
  test::CallSetScreenBrightness(
      &dbus_wrapper_, 50.0, SetBacklightBrightnessRequest_Transition_INSTANT,
      SetBacklightBrightnessRequest_Cause_USER_REQUEST);
  EXPECT_EQ(0, controller_.GetNumUserAdjustments());
  test::CallIncreaseScreenBrightness(&dbus_wrapper_);
  EXPECT_EQ(1, controller_.GetNumUserAdjustments());
  test::CallDecreaseScreenBrightness(&dbus_wrapper_, true /* allow_off */);
  EXPECT_EQ(2, controller_.GetNumUserAdjustments());

  controller_.HandleSessionStateChange(SessionState::STARTED);
  EXPECT_EQ(0, controller_.GetNumUserAdjustments());

  // If ALS-based brightness is disabled, the brightness of external displays
  // with an ambient light sensor can be adjusted with an absolute request or a
  // relative request.
  bool enabled = false;
  CallGetExternalDisplayALSBrightness(&enabled);
  EXPECT_TRUE(enabled);
  CallSetExternalDisplayALSBrightness(false);
  CallGetExternalDisplayALSBrightness(&enabled);
  EXPECT_FALSE(enabled);
  test::CallSetScreenBrightness(
      &dbus_wrapper_, 42.0, SetBacklightBrightnessRequest_Transition_INSTANT,
      SetBacklightBrightnessRequest_Cause_USER_REQUEST);
  EXPECT_EQ(1, controller_.GetNumUserAdjustments());
  EXPECT_TRUE(controller_.GetBrightnessPercent(&percent));
  EXPECT_EQ(42.0, percent);
  test::CallIncreaseScreenBrightness(&dbus_wrapper_);
  EXPECT_TRUE(controller_.GetBrightnessPercent(&percent));
  EXPECT_EQ(47.0, percent);
  EXPECT_EQ(2, controller_.GetNumUserAdjustments());
  test::CallDecreaseScreenBrightness(&dbus_wrapper_, true /* allow_off */);
  EXPECT_TRUE(controller_.GetBrightnessPercent(&percent));
  EXPECT_EQ(42.0, percent);
  EXPECT_EQ(3, controller_.GetNumUserAdjustments());
}

TEST_F(ExternalBacklightControllerTest, DimAndTurnOffScreen) {
  EXPECT_FALSE(display_power_setter_.dimmed());
  EXPECT_EQ(chromeos::DISPLAY_POWER_ALL_ON, display_power_setter_.state());

  observer_.Clear();
  controller_.SetDimmedForInactivity(true);
  EXPECT_TRUE(display_power_setter_.dimmed());
  EXPECT_EQ(chromeos::DISPLAY_POWER_ALL_ON, display_power_setter_.state());
  EXPECT_EQ(0, static_cast<int>(observer_.changes().size()));

  observer_.Clear();
  controller_.SetOffForInactivity(true);
  EXPECT_TRUE(display_power_setter_.dimmed());
  EXPECT_EQ(chromeos::DISPLAY_POWER_ALL_OFF, display_power_setter_.state());
  ASSERT_EQ(1, static_cast<int>(observer_.changes().size()));
  EXPECT_DOUBLE_EQ(0.0, observer_.changes()[0].percent);
  EXPECT_EQ(BacklightBrightnessChange_Cause_USER_INACTIVITY,
            observer_.changes()[0].cause);
  EXPECT_EQ(&controller_, observer_.changes()[0].source);

  observer_.Clear();
  controller_.SetSuspended(true);
  EXPECT_TRUE(display_power_setter_.dimmed());
  EXPECT_EQ(chromeos::DISPLAY_POWER_ALL_OFF, display_power_setter_.state());
  EXPECT_EQ(0, static_cast<int>(observer_.changes().size()));

  observer_.Clear();
  controller_.SetSuspended(false);
  controller_.SetOffForInactivity(false);
  controller_.SetDimmedForInactivity(false);
  EXPECT_FALSE(display_power_setter_.dimmed());
  EXPECT_EQ(chromeos::DISPLAY_POWER_ALL_ON, display_power_setter_.state());
  ASSERT_EQ(1, static_cast<int>(observer_.changes().size()));
  EXPECT_DOUBLE_EQ(100.0, observer_.changes()[0].percent);
  EXPECT_EQ(BacklightBrightnessChange_Cause_USER_ACTIVITY,
            observer_.changes()[0].cause);
  EXPECT_EQ(&controller_, observer_.changes()[0].source);
}

TEST_F(ExternalBacklightControllerTest, TurnDisplaysOffWhenShuttingDown) {
  controller_.SetShuttingDown(true);
  EXPECT_EQ(chromeos::DISPLAY_POWER_ALL_OFF, display_power_setter_.state());
  EXPECT_EQ(0, display_power_setter_.delay().InMilliseconds());
}

TEST_F(ExternalBacklightControllerTest, SetPowerOnDisplayServiceStart) {
  // The display power shouldn't be set by Init() (maybe Chrome hasn't started
  // yet).
  EXPECT_EQ(0, display_power_setter_.num_power_calls());
  EXPECT_EQ(0, static_cast<int>(observer_.changes().size()));

  // After Chrome starts, the state should be initialized to sane defaults.
  display_power_setter_.reset_num_power_calls();
  controller_.HandleDisplayServiceStart();
  EXPECT_EQ(1, display_power_setter_.num_power_calls());
  EXPECT_FALSE(display_power_setter_.dimmed());
  ASSERT_EQ(chromeos::DISPLAY_POWER_ALL_ON, display_power_setter_.state());
  ASSERT_EQ(1, static_cast<int>(observer_.changes().size()));
  EXPECT_DOUBLE_EQ(100.0, observer_.changes()[0].percent);
  EXPECT_EQ(BacklightBrightnessChange_Cause_OTHER,
            observer_.changes()[0].cause);
  EXPECT_EQ(&controller_, observer_.changes()[0].source);

  controller_.SetDimmedForInactivity(true);
  ASSERT_TRUE(display_power_setter_.dimmed());
  controller_.SetOffForInactivity(true);
  ASSERT_EQ(chromeos::DISPLAY_POWER_ALL_OFF, display_power_setter_.state());

  // Reset the power setter's dimming state so we can check that another dimming
  // request is sent when Chrome restarts.
  display_power_setter_.reset_num_power_calls();
  display_power_setter_.SetDisplaySoftwareDimming(false);
  observer_.Clear();
  controller_.HandleDisplayServiceStart();
  EXPECT_EQ(chromeos::DISPLAY_POWER_ALL_OFF, display_power_setter_.state());
  EXPECT_EQ(1, display_power_setter_.num_power_calls());
  EXPECT_TRUE(display_power_setter_.dimmed());
  ASSERT_EQ(1, static_cast<int>(observer_.changes().size()));
  EXPECT_DOUBLE_EQ(0.0, observer_.changes()[0].percent);
  EXPECT_EQ(BacklightBrightnessChange_Cause_OTHER,
            observer_.changes()[0].cause);
  EXPECT_EQ(&controller_, observer_.changes()[0].source);
}

TEST_F(ExternalBacklightControllerTest, ForcedOff) {
  controller_.SetForcedOff(true);
  EXPECT_EQ(chromeos::DISPLAY_POWER_ALL_OFF, display_power_setter_.state());
  EXPECT_EQ(0, display_power_setter_.delay().InMilliseconds());

  controller_.SetForcedOff(false);
  EXPECT_EQ(chromeos::DISPLAY_POWER_ALL_ON, display_power_setter_.state());
  EXPECT_EQ(0, display_power_setter_.delay().InMilliseconds());
}

TEST_F(ExternalBacklightControllerTest,
       MatchTwoDisplaysWithAmbientLightSensors) {
  AddDisplay(kFirstDisplay);

  // Connecting just the first display should not generate any matches.
  EXPECT_EQ(
      0, controller_.GetAmbientLightSensorAndDisplayMatchesForTesting().size());

  AddSensor(kFirstSensor);

  // After adding the first sensor, one match should be generated.
  std::vector<std::pair<base::FilePath, system::DisplayInfo>> matches =
      controller_.GetAmbientLightSensorAndDisplayMatchesForTesting();
  ASSERT_EQ(1, matches.size());
  EXPECT_STREQ(kFirstSensor, matches[0].first.value().c_str());
  EXPECT_STREQ(kFirstDisplay, matches[0].second.sys_path.value().c_str());

  AddSensor(kSecondSensor);

  // Adding a second sensor without the second display should still result in
  // one match.
  matches = controller_.GetAmbientLightSensorAndDisplayMatchesForTesting();
  ASSERT_EQ(1, matches.size());
  EXPECT_STREQ(kFirstSensor, matches[0].first.value().c_str());
  EXPECT_STREQ(kFirstDisplay, matches[0].second.sys_path.value().c_str());

  AddDisplay(kSecondDisplay);

  // After adding both sensors/displays, there should be two matches.
  matches = controller_.GetAmbientLightSensorAndDisplayMatchesForTesting();
  ASSERT_EQ(2, matches.size());
  if (matches[0].first.value().compare(kFirstSensor) == 0) {
    EXPECT_STREQ(kFirstSensor, matches[0].first.value().c_str());
    EXPECT_STREQ(kFirstDisplay, matches[0].second.sys_path.value().c_str());
    EXPECT_STREQ(kSecondSensor, matches[1].first.value().c_str());
    EXPECT_STREQ(kSecondDisplay, matches[1].second.sys_path.value().c_str());
  } else if (matches[0].first.value().compare(kSecondSensor) == 0) {
    EXPECT_STREQ(kSecondSensor, matches[0].first.value().c_str());
    EXPECT_STREQ(kSecondDisplay, matches[0].second.sys_path.value().c_str());
    EXPECT_STREQ(kFirstSensor, matches[1].first.value().c_str());
    EXPECT_STREQ(kFirstDisplay, matches[1].second.sys_path.value().c_str());
  } else {
    ADD_FAILURE();
  }

  RemoveDisplay(kFirstDisplay);

  // Removing the first display should drop that match.
  matches = controller_.GetAmbientLightSensorAndDisplayMatchesForTesting();
  ASSERT_EQ(1, matches.size());
  EXPECT_STREQ(kSecondSensor, matches[0].first.value().c_str());
  EXPECT_STREQ(kSecondDisplay, matches[0].second.sys_path.value().c_str());

  RemoveSensor(kSecondSensor);

  // There should be 0 matches after removing the second sensor. The first
  // sensor and second display should not match even though they are both
  // connected because their association score of 3 is not above the minimum
  // threshold.
  EXPECT_EQ(
      0, controller_.GetAmbientLightSensorAndDisplayMatchesForTesting().size());
}

}  // namespace power_manager::policy
