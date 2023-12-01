// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/powerd/system/ambient_light_sensor_delegate_file.h"

#include <memory>
#include <utility>

#include <base/check.h>
#include <base/compiler_specific.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/strings/string_number_conversions.h>
#include <brillo/file_utils.h>
#include <gtest/gtest.h>

#include "power_manager/common/test_main_loop_runner.h"
#include "power_manager/powerd/system/ambient_light_observer.h"
#include "power_manager/powerd/system/ambient_light_sensor.h"
#include "power_manager/powerd/testing/test_environment.h"

namespace power_manager::system {

namespace {

// Abort if it an expected brightness change hasn't been received after this
// much time.
constexpr base::TimeDelta kUpdateTimeout = base::Seconds(5);

// Frequency with which the ambient light sensor file is polled.
constexpr base::TimeDelta kPollInterval = base::Milliseconds(100);

constexpr char kDeviceName[] = "device0";

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

class AmbientLightSensorDelegateFileTest : public TestEnvironment {
 public:
  AmbientLightSensorDelegateFileTest() = default;
  AmbientLightSensorDelegateFileTest(
      const AmbientLightSensorDelegateFileTest&) = delete;
  AmbientLightSensorDelegateFileTest& operator=(
      const AmbientLightSensorDelegateFileTest&) = delete;
  ~AmbientLightSensorDelegateFileTest() override = default;

 protected:
  void SetUp() override {
    CHECK(temp_dir_.CreateUniqueTempDir());
    device_dir_ = temp_dir_.GetPath().Append(kDeviceName);
    CHECK(base::CreateDirectory(device_dir_));
    data_file_ = device_dir_.Append("in_illuminance_input");

    sensor_ = std::make_unique<system::AmbientLightSensor>();
    sensor_->AddObserver(&observer_);
  }

  void TearDown() override { sensor_->RemoveObserver(&observer_); }

  void CreateSensorByLocation(SensorLocation location, bool allow_ambient_eq) {
    auto als = std::make_unique<system::AmbientLightSensorDelegateFile>(
        location, allow_ambient_eq);
    als_ = als.get();
    sensor_->SetDelegate(std::move(als));
    als_->set_device_list_path_for_testing(temp_dir_.GetPath());
    als_->set_poll_interval_for_testing(kPollInterval);
    als_->Init(false /* read_immediately */);
  }

  void CreateSensorByName(const std::string& device, bool allow_ambient_eq) {
    auto als = std::make_unique<system::AmbientLightSensorDelegateFile>(
        device, allow_ambient_eq);
    als_ = als.get();
    sensor_->SetDelegate(std::move(als));
    als_->set_device_list_path_for_testing(temp_dir_.GetPath());
    als_->set_poll_interval_for_testing(kPollInterval);
    als_->Init(false /* read_immediately */);
  }

  // Writes |lux| to |data_file_| to simulate the ambient light sensor reporting
  // a new light level.
  void WriteLux(int lux) {
    std::string lux_string = base::NumberToString(lux);
    CHECK(brillo::WriteStringToFile(data_file_, lux_string));
  }

  // Temporary directory mimicking a /sys directory containing a set of sensor
  // devices.
  base::ScopedTempDir temp_dir_;

  base::FilePath device_dir_;

  // Illuminance file containing the sensor's current brightness level.
  base::FilePath data_file_;

  TestObserver observer_;

  std::unique_ptr<AmbientLightSensor> sensor_;
  AmbientLightSensorDelegateFile* als_;
};

TEST_F(AmbientLightSensorDelegateFileTest, Basic) {
  CreateSensorByLocation(SensorLocation::UNKNOWN, false);

  WriteLux(100);
  ASSERT_TRUE(observer_.RunUntilAmbientLightUpdated());
  EXPECT_EQ(100, sensor_->GetAmbientLightLux());

  WriteLux(200);
  ASSERT_TRUE(observer_.RunUntilAmbientLightUpdated());
  EXPECT_EQ(200, sensor_->GetAmbientLightLux());

  // When the lux value doesn't change, we should still be called.
  WriteLux(200);
  ASSERT_TRUE(observer_.RunUntilAmbientLightUpdated());
  EXPECT_EQ(200, sensor_->GetAmbientLightLux());
}

TEST_F(AmbientLightSensorDelegateFileTest, GiveUpAfterTooManyFailures) {
  CreateSensorByLocation(SensorLocation::UNKNOWN, false);

  // Test that the timer is eventually stopped after many failures.
  base::DeleteFile(data_file_);
  for (int i = 0;
       i < AmbientLightSensorDelegateFile::kNumInitAttemptsBeforeGivingUp;
       ++i) {
    EXPECT_TRUE(als_->TriggerPollTimerForTesting());
    EXPECT_LT(sensor_->GetAmbientLightLux(), 0);
  }

  EXPECT_FALSE(als_->TriggerPollTimerForTesting());
  EXPECT_LT(sensor_->GetAmbientLightLux(), 0);
}

TEST_F(AmbientLightSensorDelegateFileTest, FailToFindSensorAtLid) {
  // Test that the timer is eventually stopped after many failures if |sensor_|
  // is unable to find the sensor at the expected location.
  CreateSensorByLocation(SensorLocation::LID, false);

  for (int i = 0;
       i < AmbientLightSensorDelegateFile::kNumInitAttemptsBeforeGivingUp;
       ++i) {
    EXPECT_TRUE(als_->TriggerPollTimerForTesting());
    EXPECT_LT(sensor_->GetAmbientLightLux(), 0);
  }

  EXPECT_FALSE(als_->TriggerPollTimerForTesting());
  EXPECT_LT(sensor_->GetAmbientLightLux(), 0);
}

TEST_F(AmbientLightSensorDelegateFileTest, FindSensorAtBase) {
  // Test that |sensor_| is able to find the correct sensor at the expected
  // location.
  base::FilePath loc_file = device_dir_.Append("location");
  CHECK(brillo::WriteStringToFile(loc_file, "base"));

  CreateSensorByLocation(SensorLocation::BASE, false);

  WriteLux(100);
  ASSERT_TRUE(observer_.RunUntilAmbientLightUpdated());
  EXPECT_EQ(100, sensor_->GetAmbientLightLux());
}

TEST_F(AmbientLightSensorDelegateFileTest, IsColorSensor) {
  CreateSensorByLocation(SensorLocation::UNKNOWN, false);

  WriteLux(100);
  ASSERT_TRUE(observer_.RunUntilAmbientLightUpdated());
  EXPECT_EQ(100, sensor_->GetAmbientLightLux());
  // Default sensor does not have color support.
  EXPECT_FALSE(sensor_->IsColorSensor());

  // Add one color channel.
  base::FilePath color_file = device_dir_.Append("in_illuminance_red_raw");
  CHECK(brillo::WriteStringToFile(color_file, "50"));

  CreateSensorByLocation(SensorLocation::UNKNOWN, false);

  WriteLux(100);
  ASSERT_TRUE(observer_.RunUntilAmbientLightUpdated());
  EXPECT_EQ(100, sensor_->GetAmbientLightLux());
  // The sensor should still not have color support -- it needs all 3.
  EXPECT_FALSE(sensor_->IsColorSensor());

  // Add the other two channels.
  color_file = device_dir_.Append("in_illuminance_green_raw");
  CHECK(brillo::WriteStringToFile(color_file, "50"));
  color_file = device_dir_.Append("in_illuminance_blue_raw");
  CHECK(brillo::WriteStringToFile(color_file, "50"));

  CreateSensorByLocation(SensorLocation::UNKNOWN, true);

  WriteLux(100);
  ASSERT_TRUE(observer_.RunUntilAmbientLightUpdated());
  EXPECT_EQ(100, sensor_->GetAmbientLightLux());
  // Now we have all channels. The sensor should support color.
  EXPECT_TRUE(sensor_->IsColorSensor());
}

TEST_F(AmbientLightSensorDelegateFileTest, FindSensorByName) {
  CreateSensorByName(kDeviceName, false);

  WriteLux(100);
  ASSERT_TRUE(observer_.RunUntilAmbientLightUpdated());
  EXPECT_EQ(100, sensor_->GetAmbientLightLux());
}

TEST_F(AmbientLightSensorDelegateFileTest, FailToFindSensorByName) {
  // Test that the timer is eventually stopped after many failures if |sensor_|
  // is unable to find the sensor with the expected name.
  CreateSensorByName("bad-name", false);

  for (int i = 0;
       i < AmbientLightSensorDelegateFile::kNumInitAttemptsBeforeGivingUp;
       ++i) {
    EXPECT_TRUE(als_->TriggerPollTimerForTesting());
    EXPECT_LT(sensor_->GetAmbientLightLux(), 0);
  }

  EXPECT_FALSE(als_->TriggerPollTimerForTesting());
  EXPECT_LT(sensor_->GetAmbientLightLux(), 0);
}

}  // namespace power_manager::system
