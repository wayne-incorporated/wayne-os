// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <string>
#include <utility>

#include <base/files/file_util.h>
#include <base/test/gmock_callback_support.h>
#include <base/test/task_environment.h>
#include <base/test/test_future.h>
#include <brillo/files/file_util.h>
#include <chromeos/ec/ec_commands.h>
#include <gtest/gtest.h>

#include "diagnostics/cros_healthd/fetchers/sensor_fetcher.h"
#include "diagnostics/cros_healthd/mojom/executor.mojom.h"
#include "diagnostics/cros_healthd/system/fake_mojo_service.h"
#include "diagnostics/cros_healthd/system/mock_context.h"
#include "diagnostics/cros_healthd/utils/mojo_type_utils.h"
#include "diagnostics/mojom/public/cros_healthd_probe.mojom.h"

namespace diagnostics {
namespace {

namespace mojom = ::ash::cros_healthd::mojom;

using ::testing::_;
using ::testing::Invoke;

// Relative filepath used to determine whether a device has a Google EC.
constexpr char kRelativeCrosEcPath[] = "sys/class/chromeos/cros_ec";

class SensorFetcherTest : public ::testing::Test {
 protected:
  void SetUp() override {
    ASSERT_TRUE(base::CreateDirectory(root_dir().Append(kRelativeCrosEcPath)));
    mock_context_.fake_mojo_service()->InitializeFakeMojoService();
  }

  const base::FilePath& root_dir() { return mock_context_.root_dir(); }

  MockExecutor* mock_executor() { return mock_context_.mock_executor(); }

  FakeSensorService& fake_sensor_service() {
    return mock_context_.fake_mojo_service()->fake_sensor_service();
  }

  mojom::SensorResultPtr FetchSensorInfoSync() {
    base::test::TestFuture<mojom::SensorResultPtr> future;
    FetchSensorInfo(&mock_context_, future.GetCallback());
    return future.Take();
  }

  void SetExecutorResponse(std::optional<uint16_t> lid_angle = 120) {
    EXPECT_CALL(*mock_executor(), GetLidAngle(_))
        .WillOnce(base::test::RunOnceCallback<0>(lid_angle));
  }

 private:
  base::test::TaskEnvironment task_environment_;
  MockContext mock_context_;
};

// Test that normal lid_angle can be fetched successfully.
TEST_F(SensorFetcherTest, Success) {
  SetExecutorResponse(120);

  auto sensor_result = FetchSensorInfoSync();
  ASSERT_TRUE(sensor_result->is_sensor_info());
  const auto& sensor_info = sensor_result->get_sensor_info();
  ASSERT_TRUE(sensor_info->lid_angle);
  ASSERT_EQ(sensor_info->lid_angle->value, 120);
  ASSERT_TRUE(sensor_info->sensors.has_value());
  ASSERT_TRUE(sensor_info->sensors.value().empty());
}

// Test that unreliable lid_angle can be handled and gets null.
TEST_F(SensorFetcherTest, LidAngleUnreliable) {
  SetExecutorResponse(LID_ANGLE_UNRELIABLE);

  auto sensor_result = FetchSensorInfoSync();
  ASSERT_TRUE(sensor_result->is_sensor_info());
  const auto& sensor_info = sensor_result->get_sensor_info();
  ASSERT_FALSE(sensor_info->lid_angle);
  ASSERT_TRUE(sensor_info->sensors.has_value());
  ASSERT_TRUE(sensor_info->sensors.value().empty());
}

// Test that invalid lid_angle can be handled and gets SystemUtilityError.
TEST_F(SensorFetcherTest, LidAngleInvalidValue) {
  SetExecutorResponse(720);

  auto sensor_result = FetchSensorInfoSync();
  ASSERT_TRUE(sensor_result->is_error());
  EXPECT_EQ(sensor_result->get_error()->type,
            mojom::ErrorType::kSystemUtilityError);
}

// Test that null lid_angle can be handled and gets SystemUtilityError.
TEST_F(SensorFetcherTest, LidAngleNull) {
  SetExecutorResponse(std::nullopt);

  auto sensor_result = FetchSensorInfoSync();
  ASSERT_TRUE(sensor_result->is_error());
  EXPECT_EQ(sensor_result->get_error()->type,
            mojom::ErrorType::kSystemUtilityError);
}

// Test that without Google EC can be handled and gets null lid_angle.
TEST_F(SensorFetcherTest, LidAngleWithoutEC) {
  ASSERT_TRUE(
      brillo::DeletePathRecursively(root_dir().Append(kRelativeCrosEcPath)));

  auto sensor_result = FetchSensorInfoSync();
  ASSERT_TRUE(sensor_result->is_sensor_info());
  const auto& sensor_info = sensor_result->get_sensor_info();
  ASSERT_FALSE(sensor_info->lid_angle);
  ASSERT_TRUE(sensor_info->sensors.has_value());
  ASSERT_TRUE(sensor_info->sensors.value().empty());
}

// Test that single sensor's attributes can be fetched successfully.
TEST_F(SensorFetcherTest, FetchSensorAttribue) {
  SetExecutorResponse();
  fake_sensor_service().SetIdsTypes({{0, {cros::mojom::DeviceType::ACCEL}}});
  fake_sensor_service().SetSensorDevice(
      0, std::make_unique<FakeSensorDevice>("cros-ec-accel", "lid"));

  auto sensor_result = FetchSensorInfoSync();
  ASSERT_TRUE(sensor_result->is_sensor_info());
  const auto& sensor_info = sensor_result->get_sensor_info();
  ASSERT_TRUE(sensor_info->sensors.has_value());
  const auto& sensors = sensor_info->sensors.value();
  ASSERT_EQ(sensors.size(), 1);
  ASSERT_TRUE(sensors[0]->name.has_value());
  ASSERT_EQ(sensors[0]->name.value(), "cros-ec-accel");
  ASSERT_EQ(sensors[0]->device_id, 0);
  ASSERT_EQ(sensors[0]->type, mojom::Sensor::Type::kAccel);
  ASSERT_EQ(sensors[0]->location, mojom::Sensor::Location::kLid);
}

// Test that multiple sensors' attributes can be fetched successfully.
TEST_F(SensorFetcherTest, FetchMultipleSensorAttribue) {
  SetExecutorResponse();
  fake_sensor_service().SetIdsTypes(
      {{1, {cros::mojom::DeviceType::ANGL}},
       {3, {cros::mojom::DeviceType::ANGLVEL}},
       {4, {cros::mojom::DeviceType::LIGHT}},
       {10000, {cros::mojom::DeviceType::GRAVITY}}});

  fake_sensor_service().SetSensorDevice(
      1, std::make_unique<FakeSensorDevice>("cros-ec-lid-angle", std::nullopt));
  fake_sensor_service().SetSensorDevice(
      3, std::make_unique<FakeSensorDevice>("cros-ec-gyro", "base"));
  fake_sensor_service().SetSensorDevice(
      4, std::make_unique<FakeSensorDevice>("acpi-als", std::nullopt));
  fake_sensor_service().SetSensorDevice(
      10000, std::make_unique<FakeSensorDevice>("iioservice-gravity", "base"));

  auto sensor_result = FetchSensorInfoSync();
  ASSERT_TRUE(sensor_result->is_sensor_info());
  const auto& sensor_info = sensor_result->get_sensor_info();
  ASSERT_TRUE(sensor_info->sensors.has_value());

  // Sort the sensors by name.
  const auto& sensors = Sorted(sensor_info->sensors.value());
  ASSERT_EQ(sensors.size(), 4);

  ASSERT_TRUE(sensors[0]->name.has_value());
  ASSERT_EQ(sensors[0]->device_id, 4);
  ASSERT_EQ(sensors[0]->name.value(), "acpi-als");
  ASSERT_EQ(sensors[0]->type, mojom::Sensor::Type::kLight);
  ASSERT_EQ(sensors[0]->location, mojom::Sensor::Location::kUnknown);

  ASSERT_TRUE(sensors[1]->name.has_value());
  ASSERT_EQ(sensors[1]->name.value(), "cros-ec-gyro");
  ASSERT_EQ(sensors[1]->device_id, 3);
  ASSERT_EQ(sensors[1]->type, mojom::Sensor::Type::kGyro);
  ASSERT_EQ(sensors[1]->location, mojom::Sensor::Location::kBase);

  ASSERT_TRUE(sensors[2]->name.has_value());
  ASSERT_EQ(sensors[2]->name.value(), "cros-ec-lid-angle");
  ASSERT_EQ(sensors[2]->device_id, 1);
  ASSERT_EQ(sensors[2]->type, mojom::Sensor::Type::kAngle);
  ASSERT_EQ(sensors[2]->location, mojom::Sensor::Location::kUnknown);

  ASSERT_TRUE(sensors[3]->name.has_value());
  ASSERT_EQ(sensors[3]->name.value(), "iioservice-gravity");
  ASSERT_EQ(sensors[3]->device_id, 10000);
  ASSERT_EQ(sensors[3]->type, mojom::Sensor::Type::kGravity);
  ASSERT_EQ(sensors[3]->location, mojom::Sensor::Location::kBase);
}

// Test that combo sensor's attributes can be fetched successfully.
TEST_F(SensorFetcherTest, FetchSensorAttribueComboSensor) {
  SetExecutorResponse();
  fake_sensor_service().SetIdsTypes(
      {{100, {cros::mojom::DeviceType::ANGL, cros::mojom::DeviceType::ACCEL}}});
  fake_sensor_service().SetSensorDevice(
      100, std::make_unique<FakeSensorDevice>("cros-combo-angle-accel",
                                              std::nullopt));

  auto sensor_result = FetchSensorInfoSync();
  ASSERT_TRUE(sensor_result->is_sensor_info());
  const auto& sensor_info = sensor_result->get_sensor_info();
  ASSERT_TRUE(sensor_info->sensors.has_value());
  const auto& sensors = sensor_info->sensors.value();
  ASSERT_EQ(sensors.size(), 2);
  ASSERT_TRUE(sensors[0]->name.has_value());
  ASSERT_EQ(sensors[0]->name.value(), "cros-combo-angle-accel");
  ASSERT_EQ(sensors[0]->device_id, 100);
  ASSERT_EQ(sensors[0]->type, mojom::Sensor::Type::kAngle);
  ASSERT_EQ(sensors[0]->location, mojom::Sensor::Location::kUnknown);

  ASSERT_TRUE(sensors[1]->name.has_value());
  ASSERT_EQ(sensors[1]->name.value(), "cros-combo-angle-accel");
  ASSERT_EQ(sensors[1]->device_id, 100);
  ASSERT_EQ(sensors[1]->type, mojom::Sensor::Type::kAccel);
  ASSERT_EQ(sensors[1]->location, mojom::Sensor::Location::kUnknown);
}

}  // namespace
}  // namespace diagnostics
