// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/powerd/system/ambient_light_sensor_manager_file.h"

#include <memory>
#include <string>

#include <base/check.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/strings/string_number_conversions.h>
#include <brillo/file_utils.h>
#include <gtest/gtest.h>

#include "power_manager/common/fake_prefs.h"
#include "power_manager/common/power_constants.h"
#include "power_manager/common/test_main_loop_runner.h"
#include "power_manager/powerd/system/ambient_light_observer.h"
#include "power_manager/powerd/testing/test_environment.h"

namespace power_manager::system {

namespace {

// Abort if it an expected brightness change hasn't been received after this
// much time.
constexpr base::TimeDelta kUpdateTimeout = base::Seconds(5);

// Frequency with which the ambient light sensor file is polled.
constexpr base::TimeDelta kPollInterval = base::Milliseconds(100);

// Simple AmbientLightObserver implementation that runs the event loop
// until it receives notification that the ambient light level has changed.
class TestObserver : public AmbientLightObserver {
 public:
  TestObserver() = default;
  TestObserver(const TestObserver&) = delete;
  TestObserver& operator=(const TestObserver&) = delete;

  ~TestObserver() override = default;

  // Runs |loop_| until OnAmbientLightUpdated() is called.
  bool RunUntilAmbientLightUpdated() {
    return loop_runner_.StartLoop(kUpdateTimeout);
  }

  // AmbientLightObserver implementation:
  void OnAmbientLightUpdated(AmbientLightSensorInterface* sensor) override {
    loop_runner_.StopLoop();
  }

 private:
  TestMainLoopRunner loop_runner_;
};

}  // namespace

class AmbientLightSensorManagerFileTest : public TestEnvironment {
 public:
  AmbientLightSensorManagerFileTest() = default;
  AmbientLightSensorManagerFileTest(const AmbientLightSensorManagerFileTest&) =
      delete;
  AmbientLightSensorManagerFileTest& operator=(
      const AmbientLightSensorManagerFileTest&) = delete;

  ~AmbientLightSensorManagerFileTest() override = default;

  void SetUp() override {
    prefs_.SetInt64(kAllowAmbientEQ, 0);
    CHECK(temp_dir_.CreateUniqueTempDir());
  }

  void TearDown() override {
    CHECK(base::DeletePathRecursively(temp_dir_.GetPath()));
  };

 protected:
  base::FilePath AddSensor(int lux, std::string loc, bool color) {
    base::FilePath device_dir = temp_dir_.GetPath().Append(
        "device" + base::NumberToString(num_sensors_++));
    CHECK(base::CreateDirectory(device_dir));
    base::FilePath data_file = device_dir.Append("illuminance0_input");
    CHECK(brillo::WriteStringToFile(data_file, base::NumberToString(lux)));
    base::FilePath loc_file = device_dir.Append("location");
    CHECK(brillo::WriteStringToFile(loc_file, loc));

    if (!color)
      return data_file;

    base::FilePath color_file = device_dir.Append("in_illuminance_red_raw");
    CHECK(brillo::WriteStringToFile(color_file, base::NumberToString(lux)));
    color_file = device_dir.Append("in_illuminance_blue_raw");
    CHECK(brillo::WriteStringToFile(color_file, base::NumberToString(lux)));
    color_file = device_dir.Append("in_illuminance_green_raw");
    CHECK(brillo::WriteStringToFile(color_file, base::NumberToString(lux)));
    return data_file;
  }

  // Temporary directory mimicking a /sys directory containing a set of sensor
  // devices.
  base::ScopedTempDir temp_dir_;

  size_t num_sensors_ = 0;

  FakePrefs prefs_;

  std::unique_ptr<AmbientLightSensorManagerFile> manager_;

  TestObserver internal_backlight_observer_;
  TestObserver keyboard_backlight_observer_;
};

TEST_F(AmbientLightSensorManagerFileTest, ZeroSensors) {
  prefs_.SetInt64(kHasAmbientLightSensorPref, 0);

  manager_ = std::make_unique<AmbientLightSensorManagerFile>(&prefs_);
  manager_->set_device_list_path_for_testing(temp_dir_.GetPath());
  manager_->Run(false /* read_immediately */);

  EXPECT_EQ(nullptr, manager_->GetSensorForInternalBacklight());
  EXPECT_EQ(nullptr, manager_->GetSensorForKeyboardBacklight());
  EXPECT_FALSE(manager_->HasColorSensor());
}

TEST_F(AmbientLightSensorManagerFileTest, OneSensor) {
  prefs_.SetInt64(kHasAmbientLightSensorPref, 1);
  base::FilePath data_file = AddSensor(0, "lid", false);

  manager_ = std::make_unique<AmbientLightSensorManagerFile>(&prefs_);
  manager_->set_device_list_path_for_testing(temp_dir_.GetPath());
  manager_->set_poll_interval_for_testing(kPollInterval);
  manager_->Run(false /* read_immediately */);

  auto internal_backlight_sensor = manager_->GetSensorForInternalBacklight();
  internal_backlight_sensor->AddObserver(&internal_backlight_observer_);
  ASSERT_TRUE(internal_backlight_observer_.RunUntilAmbientLightUpdated());
  EXPECT_EQ(0, internal_backlight_sensor->GetAmbientLightLux());
  EXPECT_EQ(data_file, internal_backlight_sensor->GetIlluminancePath());
  internal_backlight_sensor->RemoveObserver(&internal_backlight_observer_);

  auto keyboard_backlight_sensor = manager_->GetSensorForKeyboardBacklight();
  keyboard_backlight_sensor->AddObserver(&keyboard_backlight_observer_);
  ASSERT_TRUE(keyboard_backlight_observer_.RunUntilAmbientLightUpdated());
  EXPECT_EQ(0, keyboard_backlight_sensor->GetAmbientLightLux());
  EXPECT_EQ(data_file, keyboard_backlight_sensor->GetIlluminancePath());
  keyboard_backlight_sensor->RemoveObserver(&keyboard_backlight_observer_);

  EXPECT_FALSE(manager_->HasColorSensor());
}

TEST_F(AmbientLightSensorManagerFileTest, TwoSensors) {
  prefs_.SetInt64(kHasAmbientLightSensorPref, 2);
  base::FilePath data0_file = AddSensor(0, "lid", false);
  base::FilePath data1_file = AddSensor(1, "base", false);

  manager_ = std::make_unique<AmbientLightSensorManagerFile>(&prefs_);
  manager_->set_device_list_path_for_testing(temp_dir_.GetPath());
  manager_->set_poll_interval_for_testing(kPollInterval);
  manager_->Run(false /* read_immediately */);

  auto internal_backlight_sensor = manager_->GetSensorForInternalBacklight();
  internal_backlight_sensor->AddObserver(&internal_backlight_observer_);
  ASSERT_TRUE(internal_backlight_observer_.RunUntilAmbientLightUpdated());
  EXPECT_EQ(0, internal_backlight_sensor->GetAmbientLightLux());
  EXPECT_EQ(data0_file, internal_backlight_sensor->GetIlluminancePath());
  internal_backlight_sensor->RemoveObserver(&internal_backlight_observer_);

  auto keyboard_backlight_sensor = manager_->GetSensorForKeyboardBacklight();
  keyboard_backlight_sensor->AddObserver(&keyboard_backlight_observer_);
  ASSERT_TRUE(keyboard_backlight_observer_.RunUntilAmbientLightUpdated());
  EXPECT_EQ(1, keyboard_backlight_sensor->GetAmbientLightLux());
  EXPECT_EQ(data1_file, keyboard_backlight_sensor->GetIlluminancePath());
  keyboard_backlight_sensor->RemoveObserver(&keyboard_backlight_observer_);

  EXPECT_FALSE(manager_->HasColorSensor());
}

TEST_F(AmbientLightSensorManagerFileTest, HasColorSensor) {
  prefs_.SetInt64(kHasAmbientLightSensorPref, 2);
  prefs_.SetInt64(kAllowAmbientEQ, 1);
  base::FilePath data0_file = AddSensor(0, "lid", true);
  base::FilePath data1_file = AddSensor(1, "base", false);

  manager_ = std::make_unique<AmbientLightSensorManagerFile>(&prefs_);
  manager_->set_device_list_path_for_testing(temp_dir_.GetPath());
  manager_->set_poll_interval_for_testing(kPollInterval);
  manager_->Run(false /* read_immediately */);

  auto internal_backlight_sensor = manager_->GetSensorForInternalBacklight();
  internal_backlight_sensor->AddObserver(&internal_backlight_observer_);
  ASSERT_TRUE(internal_backlight_observer_.RunUntilAmbientLightUpdated());
  EXPECT_EQ(0, internal_backlight_sensor->GetAmbientLightLux());
  EXPECT_EQ(data0_file, internal_backlight_sensor->GetIlluminancePath());
  internal_backlight_sensor->RemoveObserver(&internal_backlight_observer_);

  auto keyboard_backlight_sensor = manager_->GetSensorForKeyboardBacklight();
  keyboard_backlight_sensor->AddObserver(&keyboard_backlight_observer_);
  ASSERT_TRUE(keyboard_backlight_observer_.RunUntilAmbientLightUpdated());
  EXPECT_EQ(1, keyboard_backlight_sensor->GetAmbientLightLux());
  EXPECT_EQ(data1_file, keyboard_backlight_sensor->GetIlluminancePath());
  keyboard_backlight_sensor->RemoveObserver(&keyboard_backlight_observer_);

  EXPECT_TRUE(manager_->HasColorSensor());
}

}  // namespace power_manager::system
