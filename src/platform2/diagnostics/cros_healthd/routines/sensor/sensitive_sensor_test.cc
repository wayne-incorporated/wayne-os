// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/json/json_reader.h>
#include <base/strings/stringprintf.h>
#include <base/test/task_environment.h>
#include <gtest/gtest.h>
#include <mojo/public/cpp/bindings/remote.h>

#include "diagnostics/cros_healthd/routines/routine_test_utils.h"
#include "diagnostics/cros_healthd/routines/sensor/sensitive_sensor.h"
#include "diagnostics/cros_healthd/system/fake_mojo_service.h"
#include "diagnostics/cros_healthd/system/mock_context.h"
#include "diagnostics/cros_healthd/utils/callback_barrier.h"
#include "diagnostics/mojom/public/cros_healthd_diagnostics.mojom.h"

namespace diagnostics {
namespace {

namespace mojom = ::ash::cros_healthd::mojom;

class SensitiveSensorRoutineTest : public testing::Test {
 protected:
  SensitiveSensorRoutineTest() = default;
  SensitiveSensorRoutineTest(const SensitiveSensorRoutineTest&) = delete;
  SensitiveSensorRoutineTest& operator=(const SensitiveSensorRoutineTest&) =
      delete;

  void SetUp() override {
    mock_context_.fake_mojo_service()->InitializeFakeMojoService();
    routine_ = std::make_unique<SensitiveSensorRoutine>(
        mock_context_.mojo_service(), mock_context_.fake_system_config());
  }

  base::test::TaskEnvironment* task_environment() { return &task_environment_; }

  FakeSensorService& fake_sensor_service() {
    return mock_context_.fake_mojo_service()->fake_sensor_service();
  }

  FakeSystemConfig* fake_system_config() {
    return mock_context_.fake_system_config();
  }

  void CheckRoutineUpdate(uint32_t progress_percent,
                          mojom::DiagnosticRoutineStatusEnum status,
                          std::string status_message,
                          base::Value::Dict output_dict) {
    routine_->PopulateStatusUpdate(&update_, true);
    EXPECT_EQ(update_.progress_percent, progress_percent);
    VerifyNonInteractiveUpdate(update_.routine_update_union, status,
                               status_message);
    EXPECT_EQ(output_dict, base::JSONReader::Read(
                               GetStringFromValidReadOnlySharedMemoryMapping(
                                   std::move(update_.output))));
  }

  base::Value::Dict ConstructDefaultOutput() {
    base::Value::Dict output;
    for (const auto& sensor_name :
         {"base_accelerometer", "base_gyroscope", "base_magnetometer",
          "base_gravity_sensor", "lid_accelerometer", "lid_gyroscope",
          "lid_magnetometer", "lid_gravity_sensor"}) {
      base::Value::Dict sensor_dict;
      sensor_dict.Set("passed_sensors", base::Value::List());
      sensor_dict.Set("failed_sensors", base::Value::List());
      sensor_dict.Set("existence_check_result", "skipped");
      output.Set(sensor_name, std::move(sensor_dict));
    }
    return output;
  }

  std::unique_ptr<FakeSensorDevice> MakeSensorDevice(
      std::vector<std::string> channels = {},
      base::OnceClosure remote_on_bound = base::DoNothing()) {
    return std::make_unique<FakeSensorDevice>(
        /*name=*/std::nullopt, /*location=*/cros::mojom::kLocationBase,
        channels, std::move(remote_on_bound));
  }

  mojo::Remote<cros::mojom::SensorDeviceSamplesObserver>&
  SetupSensorDeviceAndGetObserverRemote(
      int32_t device_id, std::unique_ptr<FakeSensorDevice> device) {
    auto& remote = device->observer();
    fake_sensor_service().SetSensorDevice(device_id, std::move(device));
    return remote;
  }

  void StartRoutine() {
    routine_->Start();
    CheckRoutineUpdate(0, mojom::DiagnosticRoutineStatusEnum::kRunning,
                       kSensitiveSensorRoutineRunningMessage,
                       base::Value::Dict());
  }

  // Helper function for creating a list containing one sensor with given
  // properties.
  base::Value::List MakeListWithOneSensor(int32_t id,
                                          std::vector<std::string> types,
                                          std::vector<std::string> channels) {
    base::Value::List out_sensors;
    base::Value::Dict out_sensor;
    out_sensor.Set("id", id);
    base::Value::List out_types;
    for (const auto& type : types)
      out_types.Append(type);
    out_sensor.Set("types", std::move(out_types));
    base::Value::List out_channels;
    for (const auto& channel : channels)
      out_channels.Append(channel);
    out_sensor.Set("channels", std::move(out_channels));
    out_sensors.Append(std::move(out_sensor));
    return out_sensors;
  }

  // Helper function for creating a list containing one accelerometer.
  base::Value::List MakeListWithOneAccelerometer() {
    return MakeListWithOneSensor(
        0, {kSensitiveSensorRoutineTypeAccel},
        {cros::mojom::kTimestampChannel, "accel_x", "accel_y", "accel_z"});
  }

 private:
  base::test::TaskEnvironment task_environment_{
      base::test::TaskEnvironment::TimeSource::MOCK_TIME};
  MockContext mock_context_;
  std::unique_ptr<DiagnosticRoutine> routine_;
  mojom::RoutineUpdate update_{0, mojo::ScopedHandle(),
                               mojom::RoutineUpdateUnionPtr()};
};

// Test that the SensitiveSensorRoutine can be run successfully.
TEST_F(SensitiveSensorRoutineTest, RoutineSuccess) {
  fake_sensor_service().SetIdsTypes({{0, {cros::mojom::DeviceType::ACCEL}}});
  base::RunLoop run_loop;
  auto& remote = SetupSensorDeviceAndGetObserverRemote(
      /*device_id=*/0, MakeSensorDevice({cros::mojom::kTimestampChannel,
                                         "accel_x", "accel_y", "accel_z"},
                                        run_loop.QuitClosure()));
  StartRoutine();

  // Wait for the observer remote to be bound.
  run_loop.Run();

  // Send sample data.
  remote->OnSampleUpdated({{0, 21}, {1, 14624}, {2, 6373}, {3, 2389718579704}});
  remote->OnSampleUpdated({{0, 5}, {1, 14613}, {2, 6336}, {3, 2389880497684}});
  remote.FlushForTesting();

  auto output = ConstructDefaultOutput();
  output.SetByDottedPath("base_accelerometer.passed_sensors",
                         MakeListWithOneAccelerometer());
  CheckRoutineUpdate(100, mojom::DiagnosticRoutineStatusEnum::kPassed,
                     kSensitiveSensorRoutinePassedMessage, std::move(output));
}

// Test that the SensitiveSensorRoutine can be run successfully with multiple
// sensor devices.
TEST_F(SensitiveSensorRoutineTest, RoutineSuccessWithMultipleSensors) {
  // Set up multiple sensors.
  fake_sensor_service().SetIdsTypes({
      {0, {cros::mojom::DeviceType::ACCEL}},
      {1, {cros::mojom::DeviceType::LIGHT}},  // Unsupported.
      {4, {cros::mojom::DeviceType::ANGLVEL}},
      {5, {cros::mojom::DeviceType::MAGN}},
      {10000, {cros::mojom::DeviceType::GRAVITY}},
  });

  base::RunLoop run_loop;
  auto barrier =
      std::make_unique<CallbackBarrier>(/*on_success=*/run_loop.QuitClosure(),
                                        /*on_error=*/base::DoNothing());
  auto& remote1 = SetupSensorDeviceAndGetObserverRemote(
      /*device_id=*/0, MakeSensorDevice({cros::mojom::kTimestampChannel,
                                         "accel_x", "accel_y", "accel_z"},
                                        barrier->CreateDependencyClosure()));
  auto& remote2 = SetupSensorDeviceAndGetObserverRemote(
      /*device_id=*/4, MakeSensorDevice({cros::mojom::kTimestampChannel,
                                         "anglvel_x", "anglvel_y", "anglvel_z"},
                                        barrier->CreateDependencyClosure()));
  auto& remote3 = SetupSensorDeviceAndGetObserverRemote(
      /*device_id=*/5, MakeSensorDevice({cros::mojom::kTimestampChannel,
                                         "magn_x", "magn_y", "magn_z"},
                                        barrier->CreateDependencyClosure()));
  auto& remote4 = SetupSensorDeviceAndGetObserverRemote(
      /*device_id=*/10000,
      MakeSensorDevice({cros::mojom::kTimestampChannel, "gravity_x",
                        "gravity_y", "gravity_z"},
                       barrier->CreateDependencyClosure()));
  barrier.reset();
  StartRoutine();

  // Wait for the observer remotes to be bound.
  run_loop.Run();

  // Send sample data.
  remote1->OnSampleUpdated({{0, 2}, {1, 14624}, {2, 6373}, {3, 2389718579704}});
  remote1->OnSampleUpdated({{0, 5}, {1, 14613}, {2, 6336}, {3, 2389880497684}});

  remote2->OnSampleUpdated({{0, 12}, {1, 1}, {2, -9}, {3, 2389839652059}});
  remote2->OnSampleUpdated({{0, 13}, {1, 1}, {2, -8}, {3, 2390042356277}});
  remote2->OnSampleUpdated({{0, 13}, {1, 1}, {2, -9}, {3, 2390244860172}});
  remote2->OnSampleUpdated({{0, 13}, {1, 0}, {2, -8}, {3, 2390453843393}});

  remote3->OnSampleUpdated({{0, 144}, {1, -178}, {2, 311}, {3, 2389922994702}});
  remote3->OnSampleUpdated({{0, 146}, {1, -178}, {2, 290}, {3, 2390085944536}});
  remote3->OnSampleUpdated({{0, 145}, {1, -179}, {2, 311}, {3, 2390285345718}});

  remote4->OnSampleUpdated({{0, 270}, {1, -98}, {2, 8186}, {3, 2390085944536}});
  remote4->OnSampleUpdated({{0, 269}, {1, -87}, {2, 8187}, {3, 2390285345717}});

  remote1.FlushForTesting();
  remote2.FlushForTesting();
  remote3.FlushForTesting();
  remote4.FlushForTesting();

  auto output = ConstructDefaultOutput();
  output.SetByDottedPath("base_accelerometer.passed_sensors",
                         MakeListWithOneAccelerometer());
  output.SetByDottedPath(
      "base_gyroscope.passed_sensors",
      MakeListWithOneSensor(4, {kSensitiveSensorRoutineTypeGyro},
                            {cros::mojom::kTimestampChannel, "anglvel_x",
                             "anglvel_y", "anglvel_z"}));
  output.SetByDottedPath(
      "base_magnetometer.passed_sensors",
      MakeListWithOneSensor(
          5, {kSensitiveSensorRoutineTypeMagn},
          {cros::mojom::kTimestampChannel, "magn_x", "magn_y", "magn_z"}));
  output.SetByDottedPath(
      "base_gravity_sensor.passed_sensors",
      MakeListWithOneSensor(10000, {kSensitiveSensorRoutineTypeGravity},
                            {cros::mojom::kTimestampChannel, "gravity_x",
                             "gravity_y", "gravity_z"}));
  CheckRoutineUpdate(100, mojom::DiagnosticRoutineStatusEnum::kPassed,
                     kSensitiveSensorRoutinePassedMessage, std::move(output));
}

// Test that the SensitiveSensorRoutine can be run successfully without sensor.
TEST_F(SensitiveSensorRoutineTest, RoutineSuccessWithoutSensor) {
  fake_sensor_service().SetIdsTypes({});
  StartRoutine();

  // Wait for the routine to finish.
  task_environment()->RunUntilIdle();
  CheckRoutineUpdate(100, mojom::DiagnosticRoutineStatusEnum::kPassed,
                     kSensitiveSensorRoutinePassedMessage,
                     ConstructDefaultOutput());
}

// Test that the SensitiveSensorRoutine returns a kError status when the
// existence check is failed.
TEST_F(SensitiveSensorRoutineTest, RoutineExistenceCheckError) {
  fake_sensor_service().SetIdsTypes({});
  // Setup wrong configuration.
  fake_system_config()->SetSensor(kBaseAccelerometer, true);
  StartRoutine();

  // Wait for the error to occur.
  task_environment()->RunUntilIdle();

  auto output = ConstructDefaultOutput();
  output.SetByDottedPath("base_accelerometer.existence_check_result",
                         "missing");
  CheckRoutineUpdate(100, mojom::DiagnosticRoutineStatusEnum::kError,
                     kSensitiveSensorRoutineFailedCheckConfigMessage,
                     std::move(output));
}

// Test that the SensitiveSensorRoutine returns a kError status when sensor
// device failed to set frequency.
TEST_F(SensitiveSensorRoutineTest, RoutineSetFrequencyError) {
  fake_sensor_service().SetIdsTypes({{0, {cros::mojom::DeviceType::ACCEL}}});
  auto device = MakeSensorDevice();
  device->set_return_frequency(-1);
  SetupSensorDeviceAndGetObserverRemote(/*device_id=*/0, std::move(device));
  StartRoutine();

  // Wait for the error to occur.
  task_environment()->RunUntilIdle();

  auto output = ConstructDefaultOutput();
  output.SetByDottedPath(
      "base_accelerometer.failed_sensors",
      MakeListWithOneSensor(0, {kSensitiveSensorRoutineTypeAccel}, {}));
  CheckRoutineUpdate(100, mojom::DiagnosticRoutineStatusEnum::kError,
                     kSensitiveSensorRoutineFailedUnexpectedlyMessage,
                     std::move(output));
}

// Test that the SensitiveSensorRoutine returns a kError status when sensor
// device doesn't have required channels.
TEST_F(SensitiveSensorRoutineTest, RoutineGetRequiredChannelsError) {
  fake_sensor_service().SetIdsTypes({{0, {cros::mojom::DeviceType::ACCEL}}});
  SetupSensorDeviceAndGetObserverRemote(
      /*device_id=*/0,
      MakeSensorDevice({cros::mojom::kTimestampChannel, "accel_x", "accel_z"}));
  StartRoutine();

  // Wait for the error to occur.
  task_environment()->RunUntilIdle();

  auto output = ConstructDefaultOutput();
  output.SetByDottedPath(
      "base_accelerometer.failed_sensors",
      MakeListWithOneSensor(
          0, {kSensitiveSensorRoutineTypeAccel},
          {cros::mojom::kTimestampChannel, "accel_x", "accel_z"}));
  CheckRoutineUpdate(100, mojom::DiagnosticRoutineStatusEnum::kError,
                     kSensitiveSensorRoutineFailedUnexpectedlyMessage,
                     std::move(output));
}

// Test that the SensitiveSensorRoutine returns a kError status when sensor
// device failed to set all channels enabled.
TEST_F(SensitiveSensorRoutineTest, RoutineSetChannelsEnabledError) {
  fake_sensor_service().SetIdsTypes({{0, {cros::mojom::DeviceType::ACCEL}}});
  auto device = MakeSensorDevice(
      {cros::mojom::kTimestampChannel, "accel_x", "accel_y", "accel_z"});
  device->set_failed_channel_indices({0});
  SetupSensorDeviceAndGetObserverRemote(/*device_id=*/0, std::move(device));
  StartRoutine();

  // Wait for the error to occur.
  task_environment()->RunUntilIdle();
  auto output = ConstructDefaultOutput();
  output.SetByDottedPath("base_accelerometer.failed_sensors",
                         MakeListWithOneAccelerometer());
  CheckRoutineUpdate(100, mojom::DiagnosticRoutineStatusEnum::kError,
                     kSensitiveSensorRoutineFailedUnexpectedlyMessage,
                     std::move(output));
}

// Test that the SensitiveSensorRoutine returns a kError status when sensor
// device return error.
TEST_F(SensitiveSensorRoutineTest, RoutineReadSampleError) {
  fake_sensor_service().SetIdsTypes({{0, {cros::mojom::DeviceType::ACCEL}}});
  base::RunLoop run_loop;
  auto& remote = SetupSensorDeviceAndGetObserverRemote(
      /*device_id=*/0, MakeSensorDevice({cros::mojom::kTimestampChannel,
                                         "accel_x", "accel_y", "accel_z"},
                                        run_loop.QuitClosure()));
  StartRoutine();

  // Wait for the observer remote to be bound.
  run_loop.Run();

  // Send observer error.
  remote->OnErrorOccurred(cros::mojom::ObserverErrorType::READ_TIMEOUT);
  remote.FlushForTesting();

  auto output = ConstructDefaultOutput();
  output.SetByDottedPath("base_accelerometer.failed_sensors",
                         MakeListWithOneAccelerometer());
  CheckRoutineUpdate(100, mojom::DiagnosticRoutineStatusEnum::kError,
                     kSensitiveSensorRoutineFailedUnexpectedlyMessage,
                     std::move(output));
}

// Test that the SensitiveSensorRoutine returns a kFailed status when timeout
// occurred.
TEST_F(SensitiveSensorRoutineTest, RoutineTimeoutOccurredError) {
  fake_sensor_service().SetIdsTypes({{0, {cros::mojom::DeviceType::ACCEL}}});
  SetupSensorDeviceAndGetObserverRemote(
      /*device_id=*/0, MakeSensorDevice({cros::mojom::kTimestampChannel,
                                         "accel_x", "accel_y", "accel_z"}));
  StartRoutine();

  // Trigger timeout.
  task_environment()->FastForwardBy(kSensitiveSensorRoutineTimeout);

  auto output = ConstructDefaultOutput();
  output.SetByDottedPath("base_accelerometer.failed_sensors",
                         MakeListWithOneAccelerometer());
  CheckRoutineUpdate(100, mojom::DiagnosticRoutineStatusEnum::kFailed,
                     kSensitiveSensorRoutineFailedMessage, std::move(output));
}

}  // namespace
}  // namespace diagnostics
