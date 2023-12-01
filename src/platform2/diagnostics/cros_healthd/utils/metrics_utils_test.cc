// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <set>
#include <string>
#include <utility>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <metrics/metrics_library_mock.h>

#include "diagnostics/cros_healthd/utils/metrics_utils.h"
#include "diagnostics/cros_healthd/utils/metrics_utils_constants.h"

using ::testing::_;
using ::testing::Return;

namespace diagnostics {
namespace {

namespace mojom = ::ash::cros_healthd::mojom;

class MetricsUtilsTest : public ::testing::Test {
 protected:
  template <typename T>
  void ExpectSendEnumToUMA(const std::string& name, T sample) {
    EXPECT_CALL(metrics_library_,
                SendEnumToUMA(name, static_cast<int>(sample), _))
        .WillOnce(Return(true));
  }

  void SendTelemetryResult(const std::set<mojom::ProbeCategoryEnum>& categories,
                           const mojom::TelemetryInfoPtr& info) {
    SendTelemetryResultToUMA(&metrics_library_, categories, info);
  }

  void SendDiagnosticResult(mojom::DiagnosticRoutineEnum routine,
                            mojom::DiagnosticRoutineStatusEnum status) {
    SendDiagnosticResultToUMA(&metrics_library_, routine, status);
  }

  testing::StrictMock<MetricsLibraryMock> metrics_library_;
};

TEST_F(MetricsUtilsTest, SendBatteryTelemetryResult) {
  ExpectSendEnumToUMA(metrics_name::kTelemetryResultBattery,
                      CrosHealthdTelemetryResult::kSuccess);
  auto info = mojom::TelemetryInfo::New();
  info->battery_result = mojom::BatteryResult::NewBatteryInfo({});
  SendTelemetryResult({mojom::ProbeCategoryEnum::kBattery}, info);
}

TEST_F(MetricsUtilsTest, SendCpuTelemetryResult) {
  ExpectSendEnumToUMA(metrics_name::kTelemetryResultCpu,
                      CrosHealthdTelemetryResult::kSuccess);
  auto info = mojom::TelemetryInfo::New();
  info->cpu_result = mojom::CpuResult::NewCpuInfo({});
  SendTelemetryResult({mojom::ProbeCategoryEnum::kCpu}, info);
}

TEST_F(MetricsUtilsTest, SendBlockDeviceTelemetryResult) {
  ExpectSendEnumToUMA(metrics_name::kTelemetryResultBlockDevice,
                      CrosHealthdTelemetryResult::kSuccess);
  auto info = mojom::TelemetryInfo::New();
  info->block_device_result =
      mojom::NonRemovableBlockDeviceResult::NewBlockDeviceInfo({});
  SendTelemetryResult({mojom::ProbeCategoryEnum::kNonRemovableBlockDevices},
                      info);
}

TEST_F(MetricsUtilsTest, SendTimezoneTelemetryResult) {
  ExpectSendEnumToUMA(metrics_name::kTelemetryResultTimezone,
                      CrosHealthdTelemetryResult::kSuccess);
  auto info = mojom::TelemetryInfo::New();
  info->timezone_result = mojom::TimezoneResult::NewTimezoneInfo({});
  SendTelemetryResult({mojom::ProbeCategoryEnum::kTimezone}, info);
}

TEST_F(MetricsUtilsTest, SendMemoryTelemetryResult) {
  ExpectSendEnumToUMA(metrics_name::kTelemetryResultMemory,
                      CrosHealthdTelemetryResult::kSuccess);
  auto info = mojom::TelemetryInfo::New();
  info->memory_result = mojom::MemoryResult::NewMemoryInfo({});
  SendTelemetryResult({mojom::ProbeCategoryEnum::kMemory}, info);
}

TEST_F(MetricsUtilsTest, SendBacklightTelemetryResult) {
  ExpectSendEnumToUMA(metrics_name::kTelemetryResultBacklight,
                      CrosHealthdTelemetryResult::kSuccess);
  auto info = mojom::TelemetryInfo::New();
  info->backlight_result = mojom::BacklightResult::NewBacklightInfo({});
  SendTelemetryResult({mojom::ProbeCategoryEnum::kBacklight}, info);
}

TEST_F(MetricsUtilsTest, SendFanTelemetryResult) {
  ExpectSendEnumToUMA(metrics_name::kTelemetryResultFan,
                      CrosHealthdTelemetryResult::kSuccess);
  auto info = mojom::TelemetryInfo::New();
  info->fan_result = mojom::FanResult::NewFanInfo({});
  SendTelemetryResult({mojom::ProbeCategoryEnum::kFan}, info);
}

TEST_F(MetricsUtilsTest, SendStatefulPartitionTelemetryResult) {
  ExpectSendEnumToUMA(metrics_name::kTelemetryResultStatefulPartition,
                      CrosHealthdTelemetryResult::kSuccess);
  auto info = mojom::TelemetryInfo::New();
  info->stateful_partition_result =
      mojom::StatefulPartitionResult::NewPartitionInfo({});
  SendTelemetryResult({mojom::ProbeCategoryEnum::kStatefulPartition}, info);
}

TEST_F(MetricsUtilsTest, SendBluetoothTelemetryResult) {
  ExpectSendEnumToUMA(metrics_name::kTelemetryResultBluetooth,
                      CrosHealthdTelemetryResult::kSuccess);
  auto info = mojom::TelemetryInfo::New();
  info->bluetooth_result = mojom::BluetoothResult::NewBluetoothAdapterInfo({});
  SendTelemetryResult({mojom::ProbeCategoryEnum::kBluetooth}, info);
}

TEST_F(MetricsUtilsTest, SendSystemTelemetryResult) {
  ExpectSendEnumToUMA(metrics_name::kTelemetryResultSystem,
                      CrosHealthdTelemetryResult::kSuccess);
  auto info = mojom::TelemetryInfo::New();
  info->system_result = mojom::SystemResult::NewSystemInfo({});
  SendTelemetryResult({mojom::ProbeCategoryEnum::kSystem}, info);
}

TEST_F(MetricsUtilsTest, SendNetworkTelemetryResult) {
  ExpectSendEnumToUMA(metrics_name::kTelemetryResultNetwork,
                      CrosHealthdTelemetryResult::kSuccess);
  auto info = mojom::TelemetryInfo::New();
  info->network_result = mojom::NetworkResult::NewNetworkHealth({});
  SendTelemetryResult({mojom::ProbeCategoryEnum::kNetwork}, info);
}

TEST_F(MetricsUtilsTest, SendAudioTelemetryResult) {
  ExpectSendEnumToUMA(metrics_name::kTelemetryResultAudio,
                      CrosHealthdTelemetryResult::kSuccess);
  auto info = mojom::TelemetryInfo::New();
  info->audio_result = mojom::AudioResult::NewAudioInfo({});
  SendTelemetryResult({mojom::ProbeCategoryEnum::kAudio}, info);
}

TEST_F(MetricsUtilsTest, SendBootPerformanceTelemetryResult) {
  ExpectSendEnumToUMA(metrics_name::kTelemetryResultBootPerformance,
                      CrosHealthdTelemetryResult::kSuccess);
  auto info = mojom::TelemetryInfo::New();
  info->boot_performance_result =
      mojom::BootPerformanceResult::NewBootPerformanceInfo({});
  SendTelemetryResult({mojom::ProbeCategoryEnum::kBootPerformance}, info);
}

TEST_F(MetricsUtilsTest, SendBusTelemetryResult) {
  ExpectSendEnumToUMA(metrics_name::kTelemetryResultBus,
                      CrosHealthdTelemetryResult::kSuccess);
  auto info = mojom::TelemetryInfo::New();
  info->bus_result = mojom::BusResult::NewBusDevices({});
  SendTelemetryResult({mojom::ProbeCategoryEnum::kBus}, info);
}

TEST_F(MetricsUtilsTest, SendTpmTelemetryResult) {
  ExpectSendEnumToUMA(metrics_name::kTelemetryResultTpm,
                      CrosHealthdTelemetryResult::kSuccess);
  auto info = mojom::TelemetryInfo::New();
  info->tpm_result = mojom::TpmResult::NewTpmInfo({});
  SendTelemetryResult({mojom::ProbeCategoryEnum::kTpm}, info);
}

TEST_F(MetricsUtilsTest, SendNetworkInterfaceTelemetryResult) {
  ExpectSendEnumToUMA(metrics_name::kTelemetryResultNetworkInterface,
                      CrosHealthdTelemetryResult::kSuccess);
  auto info = mojom::TelemetryInfo::New();
  info->network_interface_result =
      mojom::NetworkInterfaceResult::NewNetworkInterfaceInfo({});
  SendTelemetryResult({mojom::ProbeCategoryEnum::kNetworkInterface}, info);
}

TEST_F(MetricsUtilsTest, SendGraphicsTelemetryResult) {
  ExpectSendEnumToUMA(metrics_name::kTelemetryResultGraphics,
                      CrosHealthdTelemetryResult::kSuccess);
  auto info = mojom::TelemetryInfo::New();
  info->graphics_result = mojom::GraphicsResult::NewGraphicsInfo({});
  SendTelemetryResult({mojom::ProbeCategoryEnum::kGraphics}, info);
}

TEST_F(MetricsUtilsTest, SendDisplayTelemetryResult) {
  ExpectSendEnumToUMA(metrics_name::kTelemetryResultDisplay,
                      CrosHealthdTelemetryResult::kSuccess);
  auto info = mojom::TelemetryInfo::New();
  info->display_result = mojom::DisplayResult::NewDisplayInfo({});
  SendTelemetryResult({mojom::ProbeCategoryEnum::kDisplay}, info);
}

TEST_F(MetricsUtilsTest, SendInputTelemetryResult) {
  ExpectSendEnumToUMA(metrics_name::kTelemetryResultInput,
                      CrosHealthdTelemetryResult::kSuccess);
  auto info = mojom::TelemetryInfo::New();
  info->input_result = mojom::InputResult::NewInputInfo({});
  SendTelemetryResult({mojom::ProbeCategoryEnum::kInput}, info);
}

TEST_F(MetricsUtilsTest, SendAudioHardwareTelemetryResult) {
  ExpectSendEnumToUMA(metrics_name::kTelemetryResultAudioHardware,
                      CrosHealthdTelemetryResult::kSuccess);
  auto info = mojom::TelemetryInfo::New();
  info->audio_hardware_result =
      mojom::AudioHardwareResult::NewAudioHardwareInfo({});
  SendTelemetryResult({mojom::ProbeCategoryEnum::kAudioHardware}, info);
}

TEST_F(MetricsUtilsTest, SendSensorTelemetryResult) {
  ExpectSendEnumToUMA(metrics_name::kTelemetryResultSensor,
                      CrosHealthdTelemetryResult::kSuccess);
  auto info = mojom::TelemetryInfo::New();
  info->sensor_result = mojom::SensorResult::NewSensorInfo({});
  SendTelemetryResult({mojom::ProbeCategoryEnum::kSensor}, info);
}

TEST_F(MetricsUtilsTest, SendMultipleTelemetryResult) {
  // The choice of categories is arbitrary.
  ExpectSendEnumToUMA(metrics_name::kTelemetryResultBattery,
                      CrosHealthdTelemetryResult::kSuccess);
  ExpectSendEnumToUMA(metrics_name::kTelemetryResultCpu,
                      CrosHealthdTelemetryResult::kSuccess);
  auto info = mojom::TelemetryInfo::New();
  info->battery_result = mojom::BatteryResult::NewBatteryInfo({});
  info->cpu_result = mojom::CpuResult::NewCpuInfo({});
  SendTelemetryResult(
      {
          mojom::ProbeCategoryEnum::kBattery,
          mojom::ProbeCategoryEnum::kCpu,
      },
      info);
}

TEST_F(MetricsUtilsTest, SendTelemetryErrorResult) {
  // The choice of category is arbitrary.
  ExpectSendEnumToUMA(metrics_name::kTelemetryResultBattery,
                      CrosHealthdTelemetryResult::kError);
  auto info = mojom::TelemetryInfo::New();
  info->battery_result = mojom::BatteryResult::NewError({});
  SendTelemetryResult({mojom::ProbeCategoryEnum::kBattery}, info);
}

TEST_F(MetricsUtilsTest, SendTelemetryResultWithANullField) {
  // The choice of category is arbitrary.
  ExpectSendEnumToUMA(metrics_name::kTelemetryResultBattery,
                      CrosHealthdTelemetryResult::kError);
  auto info = mojom::TelemetryInfo::New();
  SendTelemetryResult({mojom::ProbeCategoryEnum::kBattery}, info);
}

TEST_F(MetricsUtilsTest, SendDiagnosticPassedResult) {
  // The choice of routine is arbitrary.
  ExpectSendEnumToUMA(metrics_name::kDiagnosticResultBatteryCapacity,
                      CrosHealthdDiagnosticResult::kPassed);
  SendDiagnosticResult(mojom::DiagnosticRoutineEnum::kBatteryCapacity,
                       mojom::DiagnosticRoutineStatusEnum::kPassed);
}

TEST_F(MetricsUtilsTest, SendDiagnosticFailedResult) {
  // The choice of routine is arbitrary.
  ExpectSendEnumToUMA(metrics_name::kDiagnosticResultBatteryCapacity,
                      CrosHealthdDiagnosticResult::kFailed);
  SendDiagnosticResult(mojom::DiagnosticRoutineEnum::kBatteryCapacity,
                       mojom::DiagnosticRoutineStatusEnum::kFailed);
}

TEST_F(MetricsUtilsTest, SendDiagnosticErrorResult) {
  // The choice of routine is arbitrary.
  ExpectSendEnumToUMA(metrics_name::kDiagnosticResultBatteryCapacity,
                      CrosHealthdDiagnosticResult::kError);
  SendDiagnosticResult(mojom::DiagnosticRoutineEnum::kBatteryCapacity,
                       mojom::DiagnosticRoutineStatusEnum::kError);
}

TEST_F(MetricsUtilsTest, SendDiagnosticCancelledResult) {
  // The choice of routine is arbitrary.
  ExpectSendEnumToUMA(metrics_name::kDiagnosticResultBatteryCapacity,
                      CrosHealthdDiagnosticResult::kCancelled);
  SendDiagnosticResult(mojom::DiagnosticRoutineEnum::kBatteryCapacity,
                       mojom::DiagnosticRoutineStatusEnum::kCancelled);
}

TEST_F(MetricsUtilsTest, SendDiagnosticFailedToStartResult) {
  // The choice of routine is arbitrary.
  ExpectSendEnumToUMA(metrics_name::kDiagnosticResultBatteryCapacity,
                      CrosHealthdDiagnosticResult::kFailedToStart);
  SendDiagnosticResult(mojom::DiagnosticRoutineEnum::kBatteryCapacity,
                       mojom::DiagnosticRoutineStatusEnum::kFailedToStart);
}

TEST_F(MetricsUtilsTest, SendDiagnosticRemovedResult) {
  // The choice of routine is arbitrary.
  ExpectSendEnumToUMA(metrics_name::kDiagnosticResultBatteryCapacity,
                      CrosHealthdDiagnosticResult::kRemoved);
  SendDiagnosticResult(mojom::DiagnosticRoutineEnum::kBatteryCapacity,
                       mojom::DiagnosticRoutineStatusEnum::kRemoved);
}

TEST_F(MetricsUtilsTest, SendDiagnosticUnsupportedResult) {
  // The choice of routine is arbitrary.
  ExpectSendEnumToUMA(metrics_name::kDiagnosticResultBatteryCapacity,
                      CrosHealthdDiagnosticResult::kUnsupported);
  SendDiagnosticResult(mojom::DiagnosticRoutineEnum::kBatteryCapacity,
                       mojom::DiagnosticRoutineStatusEnum::kUnsupported);
}

TEST_F(MetricsUtilsTest, SendDiagnosticNotRunResult) {
  // The choice of routine is arbitrary.
  ExpectSendEnumToUMA(metrics_name::kDiagnosticResultBatteryCapacity,
                      CrosHealthdDiagnosticResult::kNotRun);
  SendDiagnosticResult(mojom::DiagnosticRoutineEnum::kBatteryCapacity,
                       mojom::DiagnosticRoutineStatusEnum::kNotRun);
}

}  // namespace
}  // namespace diagnostics
