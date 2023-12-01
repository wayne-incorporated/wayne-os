// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/powerd/policy/ambient_light_handler.h"

#include <stdint.h>

#include <base/compiler_specific.h>
#include <gtest/gtest.h>

#include "power_manager/powerd/system/ambient_light_sensor_stub.h"
#include "power_manager/powerd/testing/test_environment.h"
#include "power_manager/proto_bindings/backlight.pb.h"

namespace power_manager::policy {

namespace {

// AmbientLightHandler::Delegate implementation that records the latest
// brightness percent that was passed to it.
class TestDelegate : public AmbientLightHandler::Delegate {
 public:
  TestDelegate() = default;
  TestDelegate(const TestDelegate&) = delete;
  TestDelegate& operator=(const TestDelegate&) = delete;

  ~TestDelegate() override = default;

  double percent() const { return percent_; }
  AmbientLightHandler::BrightnessChangeCause cause() const { return cause_; }
  int lux_on_resume() const { return resume_lux_; }

  void SetBrightnessPercentForAmbientLight(
      double brightness_percent,
      AmbientLightHandler::BrightnessChangeCause cause) override {
    percent_ = brightness_percent;
    cause_ = cause;
  }

  void OnColorTemperatureChanged(int color_temperature) override {}

  void ReportAmbientLightOnResumeMetrics(int lux) override {
    resume_lux_ = lux;
  }

 private:
  double percent_ = -1.0;
  AmbientLightHandler::BrightnessChangeCause cause_ =
      AmbientLightHandler::BrightnessChangeCause::AMBIENT_LIGHT;
  int resume_lux_ = 0;
};

class AmbientLightHandlerTest : public TestEnvironment {
 public:
  AmbientLightHandlerTest()
      : light_sensor_(0), handler_(&light_sensor_, &delegate_) {}
  AmbientLightHandlerTest(const AmbientLightHandlerTest&) = delete;
  AmbientLightHandlerTest& operator=(const AmbientLightHandlerTest&) = delete;

  ~AmbientLightHandlerTest() override = default;

 protected:
  // Initializes |handler_|.
  void Init() {
    light_sensor_.set_lux(initial_lux_);
    handler_.Init(steps_pref_, initial_brightness_percent_,
                  als_smoothing_constant_);
  }

  // Updates the lux level returned by |light_sensor_| and notifies
  // |handler_| about the change.
  void UpdateSensor(int64_t lux) {
    light_sensor_.set_lux(lux);
    handler_.OnAmbientLightUpdated(&light_sensor_);
  }

  system::AmbientLightSensorStub light_sensor_;
  TestDelegate delegate_;
  AmbientLightHandler handler_;

  // Initial value for pref passed to AmbientLightHandler::Init().
  std::string steps_pref_;

  // Initial light level reported by |light_sensor_|.
  int initial_lux_ = 0;

  // Initial backlight brightness level passed to AmbientLightHandler::Init().
  double initial_brightness_percent_ = 0.0;

  // Initial als smoothing constant passed to AmbientLightHandler::Init().
  double als_smoothing_constant_ = 1.0;
};

}  // namespace

TEST_F(AmbientLightHandlerTest, UpdatePercent) {
  steps_pref_ = "20.0 -1 40\n50.0 20 80\n100.0 60 -1";
  initial_lux_ = 50;
  initial_brightness_percent_ = 60.0;
  Init();
  EXPECT_LT(delegate_.percent(), 0.0);

  // The middle step should be used as soon as a light reading is received.
  UpdateSensor(50);
  EXPECT_DOUBLE_EQ(50.0, delegate_.percent());
  EXPECT_EQ(AmbientLightHandler::BrightnessChangeCause::AMBIENT_LIGHT,
            delegate_.cause());

  // An initial reading in the lower step should be ignored, but a second
  // reading should overcome hysteresis.
  UpdateSensor(10);
  EXPECT_DOUBLE_EQ(50.0, delegate_.percent());
  UpdateSensor(10);
  EXPECT_DOUBLE_EQ(20.0, delegate_.percent());
  EXPECT_EQ(AmbientLightHandler::BrightnessChangeCause::AMBIENT_LIGHT,
            delegate_.cause());

  // Send two high readings and check that the second one causes a jump to
  // the top step.
  UpdateSensor(110);
  EXPECT_DOUBLE_EQ(20.0, delegate_.percent());
  UpdateSensor(90);
  EXPECT_DOUBLE_EQ(100.0, delegate_.percent());
  EXPECT_EQ(AmbientLightHandler::BrightnessChangeCause::AMBIENT_LIGHT,
            delegate_.cause());
}

TEST_F(AmbientLightHandlerTest, SmoothedLux) {
  steps_pref_ = "20.0 -1 40\n50.0 20 80\n100.0 60 -1";
  initial_lux_ = 50;
  initial_brightness_percent_ = 60.0;
  als_smoothing_constant_ = 0.2;
  Init();
  EXPECT_LT(delegate_.percent(), 0.0);

  // The middle step should be used as soon as a light reading is received.
  UpdateSensor(50);  // smooth_lux_ = 50
  EXPECT_DOUBLE_EQ(50.0, delegate_.percent());
  EXPECT_EQ(AmbientLightHandler::BrightnessChangeCause::AMBIENT_LIGHT,
            delegate_.cause());

  // Contrary to UpdatePercent Test, this time 6 readings at 10 lux are needed
  // before the smoothed lux to go down to lower level
  for (int i = 0; i < 6; i++) {
    UpdateSensor(10);  // smooth_lux_ = 42, 36, 30, 26, 23, 20
    EXPECT_DOUBLE_EQ(50.0, delegate_.percent()) << " iteration: " << i;
  }
  UpdateSensor(10);  // smooth_lux_ = 18
  EXPECT_DOUBLE_EQ(20.0, delegate_.percent());
  EXPECT_EQ(AmbientLightHandler::BrightnessChangeCause::AMBIENT_LIGHT,
            delegate_.cause());

  // Send high readings and check that brightness gradually jumps to top step.
  for (int i = 0; i < 2; i++) {
    UpdateSensor(110);  // smooth_lux_ = 37, 51
    EXPECT_DOUBLE_EQ(20.0, delegate_.percent()) << " iteration: " << i;
  }
  UpdateSensor(110);  // smooth_lux_ = 63
  EXPECT_DOUBLE_EQ(50.0, delegate_.percent());
  EXPECT_EQ(AmbientLightHandler::BrightnessChangeCause::AMBIENT_LIGHT,
            delegate_.cause());
  UpdateSensor(110);  // smooth_lux_ = 72
  EXPECT_DOUBLE_EQ(50.0, delegate_.percent());
  UpdateSensor(110);  // smooth_lux_ = 80
  EXPECT_DOUBLE_EQ(100.0, delegate_.percent());
  EXPECT_EQ(AmbientLightHandler::BrightnessChangeCause::AMBIENT_LIGHT,
            delegate_.cause());
}

TEST_F(AmbientLightHandlerTest, HandleResume) {
  steps_pref_ = "20.0 -1 40\n50.0 20 80\n100.0 60 -1";
  initial_lux_ = 50;
  initial_brightness_percent_ = 60.0;
  als_smoothing_constant_ = 0.2;
  Init();
  EXPECT_LT(delegate_.percent(), 0.0);

  // The middle step should be used as soon as a light reading is received.
  UpdateSensor(50);  // smooth_lux_ = 50
  EXPECT_DOUBLE_EQ(50.0, delegate_.percent());
  EXPECT_EQ(AmbientLightHandler::BrightnessChangeCause::AMBIENT_LIGHT,
            delegate_.cause());

  // Contrary to SmoothedLux Test, this time 1 readings at 10 lux should make
  // brightness to go to lower level
  handler_.HandleResume();
  UpdateSensor(50);  // First reading is discard as it is probably cached value.
  EXPECT_EQ(delegate_.lux_on_resume(), 0);
  UpdateSensor(10);
  EXPECT_DOUBLE_EQ(20.0, delegate_.percent());
  EXPECT_EQ(AmbientLightHandler::BrightnessChangeCause::AMBIENT_LIGHT,
            delegate_.cause());
  // Second lux reading after resume is reported for metrics
  EXPECT_EQ(delegate_.lux_on_resume(), 10);
}

TEST_F(AmbientLightHandlerTest, PowerSources) {
  // Define a single target percent in the bottom step and separate AC and
  // battery targets for the middle and top steps.
  steps_pref_ = "20.0 -1 40\n50.0 40.0 20 80\n100.0 90.0 60 -1";
  initial_lux_ = 0;
  initial_brightness_percent_ = 10.0;
  Init();
  EXPECT_LT(delegate_.percent(), 0.0);

  // No changes should be made when switching to battery power at the
  // bottom step.
  UpdateSensor(0);
  EXPECT_DOUBLE_EQ(20.0, delegate_.percent());
  EXPECT_EQ(AmbientLightHandler::BrightnessChangeCause::AMBIENT_LIGHT,
            delegate_.cause());
  handler_.HandlePowerSourceChange(PowerSource::BATTERY);
  EXPECT_DOUBLE_EQ(20.0, delegate_.percent());

  // Check that the brightness is updated in response to power source
  // changes while at the middle and top steps.
  UpdateSensor(50);
  UpdateSensor(50);
  EXPECT_DOUBLE_EQ(40.0, delegate_.percent());
  EXPECT_EQ(AmbientLightHandler::BrightnessChangeCause::AMBIENT_LIGHT,
            delegate_.cause());
  handler_.HandlePowerSourceChange(PowerSource::AC);
  EXPECT_DOUBLE_EQ(50.0, delegate_.percent());
  EXPECT_EQ(
      AmbientLightHandler::BrightnessChangeCause::EXTERNAL_POWER_CONNECTED,
      delegate_.cause());

  UpdateSensor(100);
  UpdateSensor(100);
  EXPECT_DOUBLE_EQ(100.0, delegate_.percent());
  EXPECT_EQ(AmbientLightHandler::BrightnessChangeCause::AMBIENT_LIGHT,
            delegate_.cause());
  handler_.HandlePowerSourceChange(PowerSource::BATTERY);
  EXPECT_DOUBLE_EQ(90.0, delegate_.percent());
  EXPECT_EQ(
      AmbientLightHandler::BrightnessChangeCause::EXTERNAL_POWER_DISCONNECTED,
      delegate_.cause());
}

TEST_F(AmbientLightHandlerTest, DeferInitialChange) {
  steps_pref_ = "80.0 30.0 -1 400\n100.0 100 -1";
  initial_lux_ = 0;
  initial_brightness_percent_ = 60.0;

  // Power source changes before the ambient light has been measured
  // shouldn't trigger changes.
  Init();
  EXPECT_LT(delegate_.percent(), 0.0);
  handler_.HandlePowerSourceChange(PowerSource::BATTERY);
  EXPECT_LT(delegate_.percent(), 0.0);

  // After the first ambient light reading, the battery percent from the
  // bottom step should be used.
  UpdateSensor(0);
  EXPECT_DOUBLE_EQ(30.0, delegate_.percent());
  EXPECT_EQ(AmbientLightHandler::BrightnessChangeCause::AMBIENT_LIGHT,
            delegate_.cause());
}

TEST_F(AmbientLightHandlerTest, GetRecentReadingsString) {
  steps_pref_ = "100.0 -1 -1";
  Init();

  // Report three readings.
  ASSERT_LT(3, AmbientLightHandler::kNumRecentReadingsToLog);
  UpdateSensor(20);
  EXPECT_EQ("20", handler_.GetRecentReadingsString());
  UpdateSensor(25);
  EXPECT_EQ("25 20", handler_.GetRecentReadingsString());
  UpdateSensor(30);
  EXPECT_EQ("30 25 20", handler_.GetRecentReadingsString());

  // Report enough additional readings to fill the buffer.
  std::string expected = handler_.GetRecentReadingsString();
  for (int i = 0; i < AmbientLightHandler::kNumRecentReadingsToLog - 3; ++i) {
    UpdateSensor(i);
    expected = std::to_string(i) + " " + expected;
  }
  EXPECT_EQ(expected, handler_.GetRecentReadingsString());

  // Log one more value and check that the oldest reading (20) is dropped.
  UpdateSensor(35);
  ASSERT_EQ(" 20", expected.substr(expected.size() - 3));
  EXPECT_EQ("35 " + expected.substr(0, expected.size() - 3),
            handler_.GetRecentReadingsString());
}

}  // namespace power_manager::policy
