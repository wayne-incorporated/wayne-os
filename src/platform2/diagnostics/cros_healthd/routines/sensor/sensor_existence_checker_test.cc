// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <algorithm>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/test/test_future.h>
#include <base/test/task_environment.h>
#include <gtest/gtest.h>

#include "diagnostics/cros_healthd/routines/sensor/sensor_existence_checker.h"
#include "diagnostics/cros_healthd/system/fake_mojo_service.h"
#include "diagnostics/cros_healthd/system/mock_context.h"

namespace diagnostics {
namespace {

class SensorExistenceCheckerTest : public testing::Test {
 protected:
  SensorExistenceCheckerTest() = default;
  SensorExistenceCheckerTest(const SensorExistenceCheckerTest&) = delete;
  SensorExistenceCheckerTest& operator=(const SensorExistenceCheckerTest&) =
      delete;

  void SetUp() override {
    mock_context_.fake_mojo_service()->InitializeFakeMojoService();
  }

  FakeSensorService& fake_sensor_service() {
    return mock_context_.fake_mojo_service()->fake_sensor_service();
  }

  FakeSystemConfig* fake_system_config() {
    return mock_context_.fake_system_config();
  }

  std::string GetSensorLocation(SensorType sensor) {
    switch (sensor) {
      case kBaseAccelerometer:
      case kBaseGyroscope:
      case kBaseMagnetometer:
      case kBaseGravitySensor:
        return cros::mojom::kLocationBase;
      case kLidAccelerometer:
      case kLidGyroscope:
      case kLidMagnetometer:
      case kLidGravitySensor:
        return cros::mojom::kLocationLid;
    }
  }

  cros::mojom::DeviceType GetSensorType(SensorType sensor) {
    switch (sensor) {
      case kBaseAccelerometer:
      case kLidAccelerometer:
        return cros::mojom::DeviceType::ACCEL;
      case kBaseGyroscope:
      case kLidGyroscope:
        return cros::mojom::DeviceType::ANGLVEL;
      case kBaseMagnetometer:
      case kLidMagnetometer:
        return cros::mojom::DeviceType::MAGN;
      case kBaseGravitySensor:
      case kLidGravitySensor:
        return cros::mojom::DeviceType::GRAVITY;
    }
  }

  base::flat_map<int32_t, std::vector<cros::mojom::DeviceType>>
  SetupSensorDevice(std::vector<SensorType> present_sensors) {
    base::flat_map<int32_t, std::vector<cros::mojom::DeviceType>> ids_types{};

    for (const auto& sensor : present_sensors) {
      // Get unique sensor id from enum.
      const auto& device_id = static_cast<int32_t>(sensor);
      auto device = std::make_unique<FakeSensorDevice>(
          /*name=*/std::nullopt, GetSensorLocation(sensor));
      fake_sensor_service().SetSensorDevice(device_id, std::move(device));

      // Prepare fake data for sensor checker.
      ids_types.insert({device_id, {GetSensorType(sensor)}});
    }

    // Setup fake sensors.
    fake_sensor_service().SetIdsTypes(ids_types);
    return ids_types;
  }

  std::map<SensorType, SensorExistenceChecker::Result> VerifySensorInfoSync(
      std::vector<SensorType> present_sensors) {
    base::test::TestFuture<std::map<SensorType, SensorExistenceChecker::Result>>
        future;
    const auto& ids_types = SetupSensorDevice(present_sensors);
    sensor_checker_.VerifySensorInfo(ids_types, future.GetCallback());
    return future.Get();
  }

 private:
  base::test::TaskEnvironment task_environment_;
  MockContext mock_context_;
  SensorExistenceChecker sensor_checker_{mock_context_.mojo_service(),
                                         mock_context_.fake_system_config()};
};

TEST_F(SensorExistenceCheckerTest, PassWithAllSensorsPresent) {
  const auto& present_sensors = {kBaseAccelerometer, kLidAccelerometer,
                                 kBaseGyroscope,     kLidGyroscope,
                                 kBaseMagnetometer,  kLidMagnetometer,
                                 kBaseGravitySensor, kLidGravitySensor};
  // Setup fake configurations.
  for (const auto& sensor : present_sensors) {
    fake_system_config()->SetSensor(sensor, true);
  }

  auto sensor_check_result = VerifySensorInfoSync(present_sensors);
  for (const auto& sensor : present_sensors) {
    EXPECT_EQ(sensor_check_result[sensor].state,
              SensorExistenceChecker::Result::kPassed);
    EXPECT_EQ(sensor_check_result[sensor].sensor_ids,
              std::vector<int32_t>{static_cast<int32_t>(sensor)});
  }
}

TEST_F(SensorExistenceCheckerTest, NoSensor) {
  const auto& sensors = {kBaseAccelerometer, kLidAccelerometer,
                         kBaseGyroscope,     kLidGyroscope,
                         kBaseMagnetometer,  kLidMagnetometer,
                         kBaseGravitySensor, kLidGravitySensor};
  // Setup fake configurations.
  for (const auto& sensor : sensors) {
    fake_system_config()->SetSensor(sensor, false);
  }

  auto sensor_check_result = VerifySensorInfoSync(/*present_sensors=*/{});
  for (const auto& sensor : sensors) {
    EXPECT_EQ(sensor_check_result[sensor].state,
              SensorExistenceChecker::Result::kPassed);
    EXPECT_EQ(sensor_check_result[sensor].sensor_ids, std::vector<int32_t>{});
  }
}

TEST_F(SensorExistenceCheckerTest, NullConfig) {
  const auto& sensors = {kBaseAccelerometer, kLidAccelerometer,
                         kBaseGyroscope,     kLidGyroscope,
                         kBaseMagnetometer,  kLidMagnetometer,
                         kBaseGravitySensor, kLidGravitySensor};
  const auto& present_sensors = {kBaseAccelerometer, kBaseGyroscope,
                                 kLidGyroscope, kLidMagnetometer};
  // Setup fake configurations.
  for (const auto& sensor : sensors) {
    fake_system_config()->SetSensor(sensor, std::nullopt);
  }

  auto sensor_check_result = VerifySensorInfoSync(present_sensors);
  for (const auto& sensor : sensors) {
    EXPECT_EQ(sensor_check_result[sensor].state,
              SensorExistenceChecker::Result::kSkipped);
    if (std::find(present_sensors.begin(), present_sensors.end(), sensor) !=
        present_sensors.end()) {
      EXPECT_EQ(sensor_check_result[sensor].sensor_ids,
                std::vector<int32_t>{static_cast<int32_t>(sensor)});
    } else {
      EXPECT_EQ(sensor_check_result[sensor].sensor_ids, std::vector<int32_t>{});
    }
  }
}

TEST_F(SensorExistenceCheckerTest, MissingSensors) {
  const auto& missing_sensors = {kBaseAccelerometer, kLidAccelerometer,
                                 kBaseGyroscope,     kLidGyroscope,
                                 kBaseMagnetometer,  kLidMagnetometer,
                                 kBaseGravitySensor, kLidGravitySensor};
  // Setup fake configurations.
  for (const auto& sensor : missing_sensors) {
    fake_system_config()->SetSensor(sensor, true);
  }

  auto sensor_check_result = VerifySensorInfoSync(/*present_sensors=*/{});
  for (const auto& sensor : missing_sensors) {
    EXPECT_EQ(sensor_check_result[sensor].state,
              SensorExistenceChecker::Result::kMissing);
    EXPECT_EQ(sensor_check_result[sensor].sensor_ids, std::vector<int32_t>{});
  }
}

TEST_F(SensorExistenceCheckerTest, UnexpectedSensors) {
  const auto& unexpected_sensors = {kBaseAccelerometer, kLidAccelerometer,
                                    kBaseGyroscope,     kLidGyroscope,
                                    kBaseMagnetometer,  kLidMagnetometer,
                                    kBaseGravitySensor, kLidGravitySensor};
  // Setup fake configurations.
  for (const auto& sensor : unexpected_sensors) {
    fake_system_config()->SetSensor(sensor, false);
  }
  auto sensor_check_result =
      VerifySensorInfoSync(/*present_sensors=*/unexpected_sensors);
  for (const auto& sensor : unexpected_sensors) {
    EXPECT_EQ(sensor_check_result[sensor].state,
              SensorExistenceChecker::Result::kUnexpected);
    EXPECT_EQ(sensor_check_result[sensor].sensor_ids,
              std::vector<int32_t>{static_cast<int32_t>(sensor)});
  }
}

}  // namespace
}  // namespace diagnostics
