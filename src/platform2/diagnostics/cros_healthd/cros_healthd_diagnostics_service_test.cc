// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <cstdint>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <base/test/task_environment.h>
#include <base/test/test_future.h>
#include <gtest/gtest.h>
#include <mojo/public/cpp/bindings/pending_receiver.h>

#include "diagnostics/cros_healthd/cros_healthd_diagnostics_service.h"
#include "diagnostics/cros_healthd/fake_cros_healthd_routine_factory.h"
#include "diagnostics/cros_healthd/routines/routine_service.h"
#include "diagnostics/cros_healthd/routines/routine_test_utils.h"
#include "diagnostics/cros_healthd/system/fake_mojo_service.h"
#include "diagnostics/cros_healthd/system/fake_system_config.h"
#include "diagnostics/cros_healthd/system/mock_context.h"
#include "diagnostics/mojom/public/cros_healthd_diagnostics.mojom.h"
#include "diagnostics/mojom/public/cros_healthd_routines.mojom.h"
#include "diagnostics/mojom/public/nullable_primitives.mojom.h"

namespace diagnostics {
namespace {

namespace mojom = ::ash::cros_healthd::mojom;

using base::test::TestFuture;

constexpr char kRoutineDoesNotExistStatusMessage[] =
    "Specified routine does not exist.";

// POD struct for DiagnosticsUpdateCommandTest.
struct DiagnosticsUpdateCommandTestParams {
  mojom::DiagnosticRoutineCommandEnum command;
  mojom::DiagnosticRoutineStatusEnum expected_status;
  int num_expected_start_calls;
  int num_expected_resume_calls;
  int num_expected_cancel_calls;
};

std::set<mojom::DiagnosticRoutineEnum> GetAllAvailableRoutines() {
  return std::set<mojom::DiagnosticRoutineEnum>{
      mojom::DiagnosticRoutineEnum::kUrandom,
      mojom::DiagnosticRoutineEnum::kBatteryCapacity,
      mojom::DiagnosticRoutineEnum::kBatteryCharge,
      mojom::DiagnosticRoutineEnum::kBatteryHealth,
      mojom::DiagnosticRoutineEnum::kSmartctlCheck,
      mojom::DiagnosticRoutineEnum::kSmartctlCheckWithPercentageUsed,
      mojom::DiagnosticRoutineEnum::kAcPower,
      mojom::DiagnosticRoutineEnum::kCpuCache,
      mojom::DiagnosticRoutineEnum::kCpuStress,
      mojom::DiagnosticRoutineEnum::kFloatingPointAccuracy,
      mojom::DiagnosticRoutineEnum::kNvmeWearLevel,
      mojom::DiagnosticRoutineEnum::kNvmeSelfTest,
      mojom::DiagnosticRoutineEnum::kDiskRead,
      mojom::DiagnosticRoutineEnum::kPrimeSearch,
      mojom::DiagnosticRoutineEnum::kBatteryDischarge,
      mojom::DiagnosticRoutineEnum::kMemory,
      mojom::DiagnosticRoutineEnum::kLanConnectivity,
      mojom::DiagnosticRoutineEnum::kSignalStrength,
      mojom::DiagnosticRoutineEnum::kGatewayCanBePinged,
      mojom::DiagnosticRoutineEnum::kHasSecureWiFiConnection,
      mojom::DiagnosticRoutineEnum::kDnsResolverPresent,
      mojom::DiagnosticRoutineEnum::kDnsLatency,
      mojom::DiagnosticRoutineEnum::kDnsResolution,
      mojom::DiagnosticRoutineEnum::kCaptivePortal,
      mojom::DiagnosticRoutineEnum::kHttpFirewall,
      mojom::DiagnosticRoutineEnum::kHttpsFirewall,
      mojom::DiagnosticRoutineEnum::kHttpsLatency,
      mojom::DiagnosticRoutineEnum::kVideoConferencing,
      mojom::DiagnosticRoutineEnum::kArcHttp,
      mojom::DiagnosticRoutineEnum::kArcPing,
      mojom::DiagnosticRoutineEnum::kArcDnsResolution,
      mojom::DiagnosticRoutineEnum::kSensitiveSensor,
      mojom::DiagnosticRoutineEnum::kFingerprint,
      mojom::DiagnosticRoutineEnum::kFingerprintAlive,
      mojom::DiagnosticRoutineEnum::kPrivacyScreen,
      mojom::DiagnosticRoutineEnum::kLedLitUp,
      mojom::DiagnosticRoutineEnum::kEmmcLifetime,
      mojom::DiagnosticRoutineEnum::kAudioSetVolume,
      mojom::DiagnosticRoutineEnum::kAudioSetGain,
      mojom::DiagnosticRoutineEnum::kBluetoothPower,
      mojom::DiagnosticRoutineEnum::kBluetoothDiscovery,
      mojom::DiagnosticRoutineEnum::kBluetoothScanning,
      mojom::DiagnosticRoutineEnum::kBluetoothPairing,
      mojom::DiagnosticRoutineEnum::kPowerButton,
      mojom::DiagnosticRoutineEnum::kAudioDriver,
  };
}

std::set<mojom::DiagnosticRoutineEnum> GetBatteryRoutines() {
  return std::set<mojom::DiagnosticRoutineEnum>{
      mojom::DiagnosticRoutineEnum::kBatteryCapacity,
      mojom::DiagnosticRoutineEnum::kBatteryCharge,
      mojom::DiagnosticRoutineEnum::kBatteryHealth,
      mojom::DiagnosticRoutineEnum::kBatteryDischarge};
}

std::set<mojom::DiagnosticRoutineEnum> GetNvmeRoutines() {
  return std::set<mojom::DiagnosticRoutineEnum>{
      mojom::DiagnosticRoutineEnum::kNvmeWearLevel,
      mojom::DiagnosticRoutineEnum::kNvmeSelfTest};
}

std::set<mojom::DiagnosticRoutineEnum> GetWilcoRoutines() {
  return std::set<mojom::DiagnosticRoutineEnum>{
      mojom::DiagnosticRoutineEnum::kNvmeWearLevel};
}

std::set<mojom::DiagnosticRoutineEnum> GetSmartCtlRoutines() {
  return std::set<mojom::DiagnosticRoutineEnum>{
      mojom::DiagnosticRoutineEnum::kSmartctlCheck,
      mojom::DiagnosticRoutineEnum::kSmartctlCheckWithPercentageUsed};
}

std::set<mojom::DiagnosticRoutineEnum> GetMmcRoutines() {
  return std::set<mojom::DiagnosticRoutineEnum>{
      mojom::DiagnosticRoutineEnum::kEmmcLifetime};
}

// Tests for the CrosHealthdDiagnosticsService class.
class CrosHealthdDiagnosticsServiceTest : public testing::Test {
 protected:
  void SetUp() override {
    mock_context_.fake_mojo_service()->InitializeFakeMojoService();
    mock_context_.fake_system_config()->SetHasBattery(true);
    mock_context_.fake_system_config()->SetHasPrivacyScreen(true);
    mock_context_.fake_system_config()->SetNvmeSupported(true);
    mock_context_.fake_system_config()->SetNvmeSupported(true);
    mock_context_.fake_system_config()->SetSmartCtrlSupported(true);
    mock_context_.fake_system_config()->SetIsWilcoDevice(true);
    mock_context_.fake_system_config()->SetMmcSupported(true);

    CreateService();
  }

  // The service needs to be recreated anytime the underlying conditions for
  // which tests are populated change.
  void CreateService() {
    service_ = std::make_unique<CrosHealthdDiagnosticsService>(
        &mock_context_, &routine_factory_, &routine_service_);
  }

  CrosHealthdDiagnosticsService* service() { return service_.get(); }

  FakeCrosHealthdRoutineFactory* routine_factory() { return &routine_factory_; }

  MockContext* mock_context() { return &mock_context_; }

  std::vector<mojom::DiagnosticRoutineEnum> ExecuteGetAvailableRoutines() {
    TestFuture<const std::vector<mojom::DiagnosticRoutineEnum>&> future;
    service()->GetAvailableRoutines(future.GetCallback());
    return future.Take();
  }

  mojom::RoutineUpdatePtr ExecuteGetRoutineUpdate(
      int32_t id,
      mojom::DiagnosticRoutineCommandEnum command,
      bool include_output) {
    TestFuture<mojom::RoutineUpdatePtr> future;
    service()->GetRoutineUpdate(id, command, include_output,
                                future.GetCallback());
    return future.Take();
  }

 private:
  base::test::TaskEnvironment task_environment_;
  FakeCrosHealthdRoutineFactory routine_factory_;
  MockContext mock_context_;
  RoutineService routine_service_{&mock_context_};
  std::unique_ptr<CrosHealthdDiagnosticsService> service_;
};

// Test that GetAvailableRoutines() returns the expected list of routines when
// all routines are supported.
TEST_F(CrosHealthdDiagnosticsServiceTest, GetAvailableRoutines) {
  auto reply = ExecuteGetAvailableRoutines();
  std::set<mojom::DiagnosticRoutineEnum> reply_set(reply.begin(), reply.end());
  EXPECT_EQ(reply_set, GetAllAvailableRoutines());
}

// Test that GetAvailableRoutines returns the expected list of routines when
// battery routines are not supported.
TEST_F(CrosHealthdDiagnosticsServiceTest, GetAvailableRoutinesNoBattery) {
  mock_context()->fake_system_config()->SetHasBattery(false);
  CreateService();
  auto reply = ExecuteGetAvailableRoutines();
  std::set<mojom::DiagnosticRoutineEnum> reply_set(reply.begin(), reply.end());
  auto expected_routines = GetAllAvailableRoutines();
  for (auto r : GetBatteryRoutines())
    expected_routines.erase(r);

  EXPECT_EQ(reply_set, expected_routines);
}

// Test that GetAvailableRoutines returns the expected list of routines when
// privacy screen routine is not supported.
TEST_F(CrosHealthdDiagnosticsServiceTest, GetAvailableRoutinesNoPrivacyScreen) {
  mock_context()->fake_system_config()->SetHasPrivacyScreen(false);
  CreateService();
  auto reply = ExecuteGetAvailableRoutines();
  std::set<mojom::DiagnosticRoutineEnum> reply_set(reply.begin(), reply.end());
  auto expected_routines = GetAllAvailableRoutines();
  expected_routines.erase(mojom::DiagnosticRoutineEnum::kPrivacyScreen);

  EXPECT_EQ(reply_set, expected_routines);
}

// Test that GetAvailableRoutines returns the expected list of routines when
// NVMe routines are not supported.
TEST_F(CrosHealthdDiagnosticsServiceTest, GetAvailableRoutinesNoNvme) {
  mock_context()->fake_system_config()->SetNvmeSupported(false);
  CreateService();
  auto reply = ExecuteGetAvailableRoutines();
  std::set<mojom::DiagnosticRoutineEnum> reply_set(reply.begin(), reply.end());

  auto expected_routines = GetAllAvailableRoutines();
  for (const auto r : GetNvmeRoutines())
    expected_routines.erase(r);

  EXPECT_EQ(reply_set, expected_routines);
}

// Test that GetAvailableRoutines returns the expected list of routines when
// NVMe self test is not supported.
TEST_F(CrosHealthdDiagnosticsServiceTest, GetAvailableRoutinesNoNvmeSelfTest) {
  mock_context()->fake_system_config()->SetNvmeSelfTestSupported(false);
  CreateService();
  auto reply = ExecuteGetAvailableRoutines();
  std::set<mojom::DiagnosticRoutineEnum> reply_set(reply.begin(), reply.end());

  auto expected_routines = GetAllAvailableRoutines();
  expected_routines.erase(mojom::DiagnosticRoutineEnum::kNvmeSelfTest);

  EXPECT_EQ(reply_set, expected_routines);
}

// Test that GetAvailableRoutines returns the expected list of routines when
// Smartctl routines are not supported.
TEST_F(CrosHealthdDiagnosticsServiceTest, GetAvailableRoutinesNoSmartctl) {
  mock_context()->fake_system_config()->SetSmartCtrlSupported(false);
  CreateService();
  auto reply = ExecuteGetAvailableRoutines();
  std::set<mojom::DiagnosticRoutineEnum> reply_set(reply.begin(), reply.end());

  auto expected_routines = GetAllAvailableRoutines();
  for (const auto r : GetSmartCtlRoutines())
    expected_routines.erase(r);

  EXPECT_EQ(reply_set, expected_routines);
}

// Test that GetAvailableRoutines returns the expected list of routines when
// mmc routines are not supported.
TEST_F(CrosHealthdDiagnosticsServiceTest, GetAvailableRoutinesNoMmc) {
  mock_context()->fake_system_config()->SetMmcSupported(false);
  CreateService();
  auto reply = ExecuteGetAvailableRoutines();
  std::set<mojom::DiagnosticRoutineEnum> reply_set(reply.begin(), reply.end());

  auto expected_routines = GetAllAvailableRoutines();
  for (const auto r : GetMmcRoutines())
    expected_routines.erase(r);

  EXPECT_EQ(reply_set, expected_routines);
}

// Test that GetAvailableRoutines returns the expected list of routines when
// wilco routines are not supported.
TEST_F(CrosHealthdDiagnosticsServiceTest, GetAvailableRoutinesNotWilcoDevice) {
  mock_context()->fake_system_config()->SetIsWilcoDevice(false);
  CreateService();
  auto reply = ExecuteGetAvailableRoutines();
  std::set<mojom::DiagnosticRoutineEnum> reply_set(reply.begin(), reply.end());

  auto expected_routines = GetAllAvailableRoutines();
  for (const auto r : GetWilcoRoutines())
    expected_routines.erase(r);

  EXPECT_EQ(reply_set, expected_routines);
}

// Test that getting the status of a routine that doesn't exist returns an
// error.
TEST_F(CrosHealthdDiagnosticsServiceTest, NonExistingStatus) {
  auto update = ExecuteGetRoutineUpdate(
      /*id=*/0, mojom::DiagnosticRoutineCommandEnum::kGetStatus,
      /*include_output=*/false);
  EXPECT_EQ(update->progress_percent, 0);
  VerifyNonInteractiveUpdate(update->routine_update_union,
                             mojom::DiagnosticRoutineStatusEnum::kError,
                             kRoutineDoesNotExistStatusMessage);
}

// Test that the battery capacity routine can be run.
TEST_F(CrosHealthdDiagnosticsServiceTest, RunBatteryCapacityRoutine) {
  constexpr mojom::DiagnosticRoutineStatusEnum kExpectedStatus =
      mojom::DiagnosticRoutineStatusEnum::kRunning;
  routine_factory()->SetNonInteractiveStatus(
      kExpectedStatus, /*status_message=*/"", /*progress_percent=*/50,
      /*output=*/"");

  TestFuture<mojom::RunRoutineResponsePtr> future;
  service()->RunBatteryCapacityRoutine(future.GetCallback());

  auto response = future.Take();
  EXPECT_EQ(response->id, 1);
  EXPECT_EQ(response->status, kExpectedStatus);
}

// Test that the battery health routine can be run.
TEST_F(CrosHealthdDiagnosticsServiceTest, RunBatteryHealthRoutine) {
  constexpr mojom::DiagnosticRoutineStatusEnum kExpectedStatus =
      mojom::DiagnosticRoutineStatusEnum::kRunning;
  routine_factory()->SetNonInteractiveStatus(
      kExpectedStatus, /*status_message=*/"", /*progress_percent=*/50,
      /*output=*/"");

  TestFuture<mojom::RunRoutineResponsePtr> future;
  service()->RunBatteryHealthRoutine(future.GetCallback());

  auto response = future.Take();
  EXPECT_EQ(response->id, 1);
  EXPECT_EQ(response->status, kExpectedStatus);
}

// Test that the urandom routine can be run.
TEST_F(CrosHealthdDiagnosticsServiceTest, RunUrandomRoutine) {
  constexpr mojom::DiagnosticRoutineStatusEnum kExpectedStatus =
      mojom::DiagnosticRoutineStatusEnum::kRunning;
  routine_factory()->SetNonInteractiveStatus(
      kExpectedStatus, /*status_message=*/"", /*progress_percent=*/50,
      /*output=*/"");

  TestFuture<mojom::RunRoutineResponsePtr> future;
  service()->RunUrandomRoutine(
      /*length_seconds=*/mojom::NullableUint32::New(120), future.GetCallback());

  auto response = future.Take();
  EXPECT_EQ(response->id, 1);
  EXPECT_EQ(response->status, kExpectedStatus);
}

// Test that the smartctl check routine can be run.
TEST_F(CrosHealthdDiagnosticsServiceTest, RunSmartctlCheckRoutineWithoutParam) {
  constexpr mojom::DiagnosticRoutineStatusEnum kExpectedStatus =
      mojom::DiagnosticRoutineStatusEnum::kRunning;
  routine_factory()->SetNonInteractiveStatus(
      kExpectedStatus, /*status_message=*/"", /*progress_percent=*/50,
      /*output=*/"");

  TestFuture<mojom::RunRoutineResponsePtr> future;
  // Pass the threshold as nullptr to test interface's backward compatibility.
  service()->RunSmartctlCheckRoutine(
      /*percentage_used_threshold=*/nullptr, future.GetCallback());

  auto response = future.Take();
  EXPECT_EQ(response->id, 1);
  EXPECT_EQ(response->status, kExpectedStatus);
}

// Test that the smartctl check routine can be run.
TEST_F(CrosHealthdDiagnosticsServiceTest, RunSmartctlCheckRoutineWithParam) {
  constexpr mojom::DiagnosticRoutineStatusEnum kExpectedStatus =
      mojom::DiagnosticRoutineStatusEnum::kRunning;
  routine_factory()->SetNonInteractiveStatus(
      kExpectedStatus, /*status_message=*/"", /*progress_percent=*/50,
      /*output=*/"");

  TestFuture<mojom::RunRoutineResponsePtr> future;
  service()->RunSmartctlCheckRoutine(
      /*percentage_used_threshold=*/mojom::NullableUint32::New(255),
      future.GetCallback());

  auto response = future.Take();
  EXPECT_EQ(response->id, 1);
  EXPECT_EQ(response->status, kExpectedStatus);
}

// Test that the eMMC lifetime routine can be run.
TEST_F(CrosHealthdDiagnosticsServiceTest, RunEmmcLifetimeRoutine) {
  constexpr mojom::DiagnosticRoutineStatusEnum kExpectedStatus =
      mojom::DiagnosticRoutineStatusEnum::kRunning;
  routine_factory()->SetNonInteractiveStatus(
      kExpectedStatus, /*status_message=*/"", /*progress_percent=*/50,
      /*output=*/"");

  TestFuture<mojom::RunRoutineResponsePtr> future;
  service()->RunEmmcLifetimeRoutine(future.GetCallback());

  auto response = future.Take();
  EXPECT_EQ(response->id, 1);
  EXPECT_EQ(response->status, kExpectedStatus);
}

// Test that the AC power routine can be run.
TEST_F(CrosHealthdDiagnosticsServiceTest, RunAcPowerRoutine) {
  constexpr mojom::DiagnosticRoutineStatusEnum kExpectedStatus =
      mojom::DiagnosticRoutineStatusEnum::kWaiting;
  routine_factory()->SetNonInteractiveStatus(
      kExpectedStatus, /*status_message=*/"", /*progress_percent=*/50,
      /*output=*/"");

  TestFuture<mojom::RunRoutineResponsePtr> future;
  service()->RunAcPowerRoutine(
      /*expected_status=*/mojom::AcPowerStatusEnum::kConnected,
      /*expected_power_type=*/std::optional<std::string>{"power_type"},
      future.GetCallback());

  auto response = future.Take();
  EXPECT_EQ(response->id, 1);
  EXPECT_EQ(response->status, kExpectedStatus);
}

// Test that the CPU cache routine can be run.
TEST_F(CrosHealthdDiagnosticsServiceTest, RunCpuCacheRoutine) {
  constexpr mojom::DiagnosticRoutineStatusEnum kExpectedStatus =
      mojom::DiagnosticRoutineStatusEnum::kRunning;

  TestFuture<mojom::RunRoutineResponsePtr> future;
  service()->RunCpuCacheRoutine(
      /*length_seconds=*/mojom::NullableUint32::New(120), future.GetCallback());

  auto response = future.Take();
  EXPECT_EQ(response->id, 1);
  EXPECT_EQ(response->status, kExpectedStatus);
}

// Test that the CPU stress routine can be run.
TEST_F(CrosHealthdDiagnosticsServiceTest, RunCpuStressRoutine) {
  constexpr mojom::DiagnosticRoutineStatusEnum kExpectedStatus =
      mojom::DiagnosticRoutineStatusEnum::kRunning;

  TestFuture<mojom::RunRoutineResponsePtr> future;
  service()->RunCpuStressRoutine(
      /*length_seconds=*/mojom::NullableUint32::New(120), future.GetCallback());

  auto response = future.Take();
  EXPECT_EQ(response->id, 1);
  EXPECT_EQ(response->status, kExpectedStatus);
}

// Test that the floating point accuracy routine can be run.
TEST_F(CrosHealthdDiagnosticsServiceTest, RunFloatingPointAccuracyRoutine) {
  constexpr mojom::DiagnosticRoutineStatusEnum kExpectedStatus =
      mojom::DiagnosticRoutineStatusEnum::kRunning;
  routine_factory()->SetNonInteractiveStatus(
      kExpectedStatus, /*status_message=*/"", /*progress_percent=*/50,
      /*output=*/"");

  TestFuture<mojom::RunRoutineResponsePtr> future;
  service()->RunFloatingPointAccuracyRoutine(
      /*length_seconds=*/mojom::NullableUint32::New(120), future.GetCallback());

  auto response = future.Take();
  EXPECT_EQ(response->id, 1);
  EXPECT_EQ(response->status, kExpectedStatus);
}

// Test that the NVMe wear level routine can be run.
TEST_F(CrosHealthdDiagnosticsServiceTest, RunNvmeWearLevelRoutine) {
  constexpr mojom::DiagnosticRoutineStatusEnum kExpectedStatus =
      mojom::DiagnosticRoutineStatusEnum::kRunning;
  routine_factory()->SetNonInteractiveStatus(
      kExpectedStatus, /*status_message=*/"", /*progress_percent=*/50,
      /*output=*/"");

  TestFuture<mojom::RunRoutineResponsePtr> future;
  service()->RunNvmeWearLevelRoutine(
      /*wear_level_threshold=*/mojom::NullableUint32::New(30),
      future.GetCallback());

  auto response = future.Take();
  EXPECT_EQ(response->id, 1);
  EXPECT_EQ(response->status, kExpectedStatus);
}

// Test that the NVMe self-test routine can be run.
TEST_F(CrosHealthdDiagnosticsServiceTest, RunNvmeSelfTestRoutine) {
  constexpr mojom::DiagnosticRoutineStatusEnum kExpectedStatus =
      mojom::DiagnosticRoutineStatusEnum::kRunning;
  routine_factory()->SetNonInteractiveStatus(
      kExpectedStatus, /*status_message=*/"", /*progress_percent=*/50,
      /*output=*/"");

  TestFuture<mojom::RunRoutineResponsePtr> future;
  service()->RunNvmeSelfTestRoutine(
      /*nvme_self_test_type=*/mojom::NvmeSelfTestTypeEnum::kShortSelfTest,
      future.GetCallback());

  auto response = future.Take();
  EXPECT_EQ(response->id, 1);
  EXPECT_EQ(response->status, kExpectedStatus);
}

// Test that the disk read routine can be run.
TEST_F(CrosHealthdDiagnosticsServiceTest, RunDiskReadRoutine) {
  constexpr mojom::DiagnosticRoutineStatusEnum kExpectedStatus =
      mojom::DiagnosticRoutineStatusEnum::kRunning;

  TestFuture<mojom::RunRoutineResponsePtr> future;
  service()->RunDiskReadRoutine(
      /*type*/ mojom::DiskReadRoutineTypeEnum::kLinearRead,
      /*length_seconds=*/10, /*file_size_mb=*/1024, future.GetCallback());

  auto response = future.Take();
  EXPECT_EQ(response->id, 1);
  EXPECT_EQ(response->status, kExpectedStatus);
}

// Test that the prime search routine can be run.
TEST_F(CrosHealthdDiagnosticsServiceTest, RunPrimeSearchRoutine) {
  constexpr mojom::DiagnosticRoutineStatusEnum kExpectedStatus =
      mojom::DiagnosticRoutineStatusEnum::kWaiting;
  routine_factory()->SetNonInteractiveStatus(
      kExpectedStatus, /*status_message=*/"", /*progress_percent=*/50,
      /*output=*/"");

  TestFuture<mojom::RunRoutineResponsePtr> future;
  service()->RunPrimeSearchRoutine(
      /*length_seconds=*/mojom::NullableUint32::New(120), future.GetCallback());

  auto response = future.Take();
  EXPECT_EQ(response->id, 1);
  EXPECT_EQ(response->status, kExpectedStatus);
}

// Test that the battery discharge routine can be run.
TEST_F(CrosHealthdDiagnosticsServiceTest, RunBatteryDischargeRoutine) {
  constexpr mojom::DiagnosticRoutineStatusEnum kExpectedStatus =
      mojom::DiagnosticRoutineStatusEnum::kWaiting;
  // TODO(crbug/1065463): Treat this as an interactive routine.
  routine_factory()->SetNonInteractiveStatus(
      kExpectedStatus, /*status_message=*/"", /*progress_percent=*/50,
      /*output=*/"");

  TestFuture<mojom::RunRoutineResponsePtr> future;
  service()->RunBatteryDischargeRoutine(
      /*length_seconds=*/23,
      /*maximum_discharge_percent_allowed=*/78, future.GetCallback());

  auto response = future.Take();
  EXPECT_EQ(response->id, 1);
  EXPECT_EQ(response->status, kExpectedStatus);
}

// Test that the battery charge routine can be run.
TEST_F(CrosHealthdDiagnosticsServiceTest, RunBatteryChargeRoutine) {
  constexpr mojom::DiagnosticRoutineStatusEnum kExpectedStatus =
      mojom::DiagnosticRoutineStatusEnum::kWaiting;
  // TODO(crbug/1065463): Treat this as an interactive routine.
  routine_factory()->SetNonInteractiveStatus(
      kExpectedStatus, /*status_message=*/"", /*progress_percent=*/50,
      /*output=*/"");

  TestFuture<mojom::RunRoutineResponsePtr> future;
  service()->RunBatteryChargeRoutine(
      /*length_seconds=*/54,
      /*minimum_charge_percent_required=*/56, future.GetCallback());

  auto response = future.Take();
  EXPECT_EQ(response->id, 1);
  EXPECT_EQ(response->status, kExpectedStatus);
}

// Test that the memory routine can be run.
TEST_F(CrosHealthdDiagnosticsServiceTest, RunMemoryRoutine) {
  constexpr mojom::DiagnosticRoutineStatusEnum kExpectedStatus =
      mojom::DiagnosticRoutineStatusEnum::kRunning;
  routine_factory()->SetNonInteractiveStatus(
      kExpectedStatus, /*status_message=*/"", /*progress_percent=*/50,
      /*output=*/"");

  TestFuture<mojom::RunRoutineResponsePtr> future;
  service()->RunMemoryRoutine(
      /*max_testing_mem_kib=*/std::nullopt, future.GetCallback());

  auto response = future.Take();
  EXPECT_EQ(response->id, 1);
  EXPECT_EQ(response->status, kExpectedStatus);
}

// Test that the LAN connectivity routine can be run.
TEST_F(CrosHealthdDiagnosticsServiceTest, RunLanConnectivityRoutine) {
  constexpr mojom::DiagnosticRoutineStatusEnum kExpectedStatus =
      mojom::DiagnosticRoutineStatusEnum::kRunning;
  routine_factory()->SetNonInteractiveStatus(
      kExpectedStatus, /*status_message=*/"", /*progress_percent=*/50,
      /*output=*/"");

  TestFuture<mojom::RunRoutineResponsePtr> future;
  service()->RunLanConnectivityRoutine(future.GetCallback());

  auto response = future.Take();
  EXPECT_EQ(response->id, 1);
  EXPECT_EQ(response->status, kExpectedStatus);
}

// Test that the signal strength routine can be run.
TEST_F(CrosHealthdDiagnosticsServiceTest, RunSignalStrengthRoutine) {
  constexpr mojom::DiagnosticRoutineStatusEnum kExpectedStatus =
      mojom::DiagnosticRoutineStatusEnum::kRunning;
  routine_factory()->SetNonInteractiveStatus(
      kExpectedStatus, /*status_message=*/"", /*progress_percent=*/50,
      /*output=*/"");

  TestFuture<mojom::RunRoutineResponsePtr> future;
  service()->RunSignalStrengthRoutine(future.GetCallback());

  auto response = future.Take();
  EXPECT_EQ(response->id, 1);
  EXPECT_EQ(response->status, kExpectedStatus);
}

// Test that the gateway can be pinged routine can be run.
TEST_F(CrosHealthdDiagnosticsServiceTest, RunGatewayCanBePingedRoutine) {
  constexpr mojom::DiagnosticRoutineStatusEnum kExpectedStatus =
      mojom::DiagnosticRoutineStatusEnum::kRunning;
  routine_factory()->SetNonInteractiveStatus(
      kExpectedStatus, /*status_message=*/"", /*progress_percent=*/50,
      /*output=*/"");

  TestFuture<mojom::RunRoutineResponsePtr> future;
  service()->RunGatewayCanBePingedRoutine(future.GetCallback());

  auto response = future.Take();
  EXPECT_EQ(response->id, 1);
  EXPECT_EQ(response->status, kExpectedStatus);
}

// Test that the has secure WiFi connection routine can be run.
TEST_F(CrosHealthdDiagnosticsServiceTest, RunHasSecureWiFiConnectionRoutine) {
  constexpr mojom::DiagnosticRoutineStatusEnum kExpectedStatus =
      mojom::DiagnosticRoutineStatusEnum::kRunning;
  routine_factory()->SetNonInteractiveStatus(
      kExpectedStatus, /*status_message=*/"", /*progress_percent=*/50,
      /*output=*/"");

  TestFuture<mojom::RunRoutineResponsePtr> future;
  service()->RunHasSecureWiFiConnectionRoutine(future.GetCallback());

  auto response = future.Take();
  EXPECT_EQ(response->id, 1);
  EXPECT_EQ(response->status, kExpectedStatus);
}

// Test that the DNS resolver present routine can be run.
TEST_F(CrosHealthdDiagnosticsServiceTest, RunDnsResolverPresentRoutine) {
  constexpr mojom::DiagnosticRoutineStatusEnum kExpectedStatus =
      mojom::DiagnosticRoutineStatusEnum::kRunning;
  routine_factory()->SetNonInteractiveStatus(
      kExpectedStatus, /*status_message=*/"", /*progress_percent=*/50,
      /*output=*/"");

  TestFuture<mojom::RunRoutineResponsePtr> future;
  service()->RunDnsResolverPresentRoutine(future.GetCallback());

  auto response = future.Take();
  EXPECT_EQ(response->id, 1);
  EXPECT_EQ(response->status, kExpectedStatus);
}

// Test that the DNS latency routine can be run.
TEST_F(CrosHealthdDiagnosticsServiceTest, RunDnsLatencyRoutine) {
  constexpr mojom::DiagnosticRoutineStatusEnum kExpectedStatus =
      mojom::DiagnosticRoutineStatusEnum::kRunning;
  routine_factory()->SetNonInteractiveStatus(
      kExpectedStatus, /*status_message=*/"", /*progress_percent=*/50,
      /*output=*/"");

  TestFuture<mojom::RunRoutineResponsePtr> future;
  service()->RunDnsLatencyRoutine(future.GetCallback());

  auto response = future.Take();
  EXPECT_EQ(response->id, 1);
  EXPECT_EQ(response->status, kExpectedStatus);
}

// Test that the DNS resolution routine can be run.
TEST_F(CrosHealthdDiagnosticsServiceTest, RunDnsResolutionRoutine) {
  constexpr mojom::DiagnosticRoutineStatusEnum kExpectedStatus =
      mojom::DiagnosticRoutineStatusEnum::kRunning;
  routine_factory()->SetNonInteractiveStatus(
      kExpectedStatus, /*status_message=*/"", /*progress_percent=*/50,
      /*output=*/"");

  TestFuture<mojom::RunRoutineResponsePtr> future;
  service()->RunDnsResolutionRoutine(future.GetCallback());

  auto response = future.Take();
  EXPECT_EQ(response->id, 1);
  EXPECT_EQ(response->status, kExpectedStatus);
}

// Test that the captive portal routine can be run.
TEST_F(CrosHealthdDiagnosticsServiceTest, RunCaptivePortalRoutine) {
  constexpr mojom::DiagnosticRoutineStatusEnum kExpectedStatus =
      mojom::DiagnosticRoutineStatusEnum::kRunning;
  routine_factory()->SetNonInteractiveStatus(
      kExpectedStatus, /*status_message=*/"", /*progress_percent=*/50,
      /*output=*/"");

  TestFuture<mojom::RunRoutineResponsePtr> future;
  service()->RunCaptivePortalRoutine(future.GetCallback());

  auto response = future.Take();
  EXPECT_EQ(response->id, 1);
  EXPECT_EQ(response->status, kExpectedStatus);
}

// Test that the HTTP firewall routine can be run.
TEST_F(CrosHealthdDiagnosticsServiceTest, RunHttpFirewallRoutine) {
  constexpr mojom::DiagnosticRoutineStatusEnum kExpectedStatus =
      mojom::DiagnosticRoutineStatusEnum::kRunning;
  routine_factory()->SetNonInteractiveStatus(
      kExpectedStatus, /*status_message=*/"", /*progress_percent=*/50,
      /*output=*/"");

  TestFuture<mojom::RunRoutineResponsePtr> future;
  service()->RunHttpFirewallRoutine(future.GetCallback());

  auto response = future.Take();
  EXPECT_EQ(response->id, 1);
  EXPECT_EQ(response->status, kExpectedStatus);
}

// Test that the HTTPS firewall routine can be run.
TEST_F(CrosHealthdDiagnosticsServiceTest, RunHttpsFirewallRoutine) {
  constexpr mojom::DiagnosticRoutineStatusEnum kExpectedStatus =
      mojom::DiagnosticRoutineStatusEnum::kRunning;
  routine_factory()->SetNonInteractiveStatus(
      kExpectedStatus, /*status_message=*/"", /*progress_percent=*/50,
      /*output=*/"");

  TestFuture<mojom::RunRoutineResponsePtr> future;
  service()->RunHttpsFirewallRoutine(future.GetCallback());

  auto response = future.Take();
  EXPECT_EQ(response->id, 1);
  EXPECT_EQ(response->status, kExpectedStatus);
}

// Test that the HTTPS latency routine can be run.
TEST_F(CrosHealthdDiagnosticsServiceTest, RunHttpsLatencyRoutine) {
  constexpr mojom::DiagnosticRoutineStatusEnum kExpectedStatus =
      mojom::DiagnosticRoutineStatusEnum::kRunning;
  routine_factory()->SetNonInteractiveStatus(
      kExpectedStatus, /*status_message=*/"", /*progress_percent=*/50,
      /*output=*/"");

  TestFuture<mojom::RunRoutineResponsePtr> future;
  service()->RunHttpsLatencyRoutine(future.GetCallback());

  auto response = future.Take();
  EXPECT_EQ(response->id, 1);
  EXPECT_EQ(response->status, kExpectedStatus);
}

// Test that the video conferencing routine can be run.
TEST_F(CrosHealthdDiagnosticsServiceTest, RunVideoConferencingRoutine) {
  constexpr mojom::DiagnosticRoutineStatusEnum kExpectedStatus =
      mojom::DiagnosticRoutineStatusEnum::kRunning;
  routine_factory()->SetNonInteractiveStatus(
      kExpectedStatus, /*status_message=*/"", /*progress_percent=*/50,
      /*output=*/"");

  TestFuture<mojom::RunRoutineResponsePtr> future;
  service()->RunVideoConferencingRoutine(
      /*stun_server_hostname=*/std::optional<
          std::string>{"http://www.stunserverhostname.com/path?k=v"},
      future.GetCallback());

  auto response = future.Take();
  EXPECT_EQ(response->id, 1);
  EXPECT_EQ(response->status, kExpectedStatus);
}

// Test that the ARC HTTP routine can be run.
TEST_F(CrosHealthdDiagnosticsServiceTest, RunArcHttpRoutine) {
  constexpr mojom::DiagnosticRoutineStatusEnum kExpectedStatus =
      mojom::DiagnosticRoutineStatusEnum::kRunning;
  routine_factory()->SetNonInteractiveStatus(
      kExpectedStatus, /*status_message=*/"", /*progress_percent=*/50,
      /*output=*/"");

  TestFuture<mojom::RunRoutineResponsePtr> future;
  service()->RunArcHttpRoutine(future.GetCallback());

  auto response = future.Take();
  EXPECT_EQ(response->id, 1);
  EXPECT_EQ(response->status, kExpectedStatus);
}

// Test that after a routine has been removed, we cannot access its data.
TEST_F(CrosHealthdDiagnosticsServiceTest, AccessStoppedRoutine) {
  routine_factory()->SetNonInteractiveStatus(
      mojom::DiagnosticRoutineStatusEnum::kRunning, /*status_message=*/"",
      /*progress_percent=*/50, /*output=*/"");

  TestFuture<mojom::RunRoutineResponsePtr> future;
  service()->RunSmartctlCheckRoutine(
      /*percentage_used_threshold=*/mojom::NullableUint32Ptr(),
      future.GetCallback());

  auto response = future.Take();
  ExecuteGetRoutineUpdate(response->id,
                          mojom::DiagnosticRoutineCommandEnum::kRemove,
                          /*include_output=*/false);

  auto update = ExecuteGetRoutineUpdate(
      response->id, mojom::DiagnosticRoutineCommandEnum::kGetStatus,
      /*include_output=*/true);

  EXPECT_EQ(update->progress_percent, 0);
  VerifyNonInteractiveUpdate(update->routine_update_union,
                             mojom::DiagnosticRoutineStatusEnum::kError,
                             kRoutineDoesNotExistStatusMessage);
}

// Test that an unsupported routine cannot be run.
TEST_F(CrosHealthdDiagnosticsServiceTest, RunUnsupportedRoutine) {
  mock_context()->fake_system_config()->SetSmartCtrlSupported(false);
  CreateService();
  routine_factory()->SetNonInteractiveStatus(
      mojom::DiagnosticRoutineStatusEnum::kUnsupported,
      /*status_message=*/"", /*progress_percent=*/0,
      /*output=*/"");

  TestFuture<mojom::RunRoutineResponsePtr> future;
  service()->RunSmartctlCheckRoutine(
      /*percentage_used_threshold=*/mojom::NullableUint32Ptr(),
      future.GetCallback());

  auto response = future.Take();
  EXPECT_EQ(response->id, mojom::kFailedToStartId);
  EXPECT_EQ(response->status, mojom::DiagnosticRoutineStatusEnum::kUnsupported);
}

// Tests for the GetRoutineUpdate() method of DiagnosticsService with different
// commands.
//
// This is a parameterized test with the following parameters (accessed
// through the POD DiagnosticsUpdateCommandTestParams POD struct):
// * |command| - mojom::DiagnosticRoutineCommandEnum sent to the routine
//               service.
// * |num_expected_start_calls| - number of times the underlying routine's
//                                Start() method is expected to be called.
// * |num_expected_resume_calls| - number of times the underlying routine's
//                                 Resume() method is expected to be called.
// * |num_expected_cancel_calls| - number of times the underlying routine's
//                                 Cancel() method is expected to be called.
class DiagnosticsUpdateCommandTest
    : public CrosHealthdDiagnosticsServiceTest,
      public testing::WithParamInterface<DiagnosticsUpdateCommandTestParams> {
 protected:
  // Accessors to the test parameters returned by gtest's GetParam():

  DiagnosticsUpdateCommandTestParams params() const { return GetParam(); }
};

// Test that we can send the given command.
TEST_P(DiagnosticsUpdateCommandTest, SendCommand) {
  constexpr mojom::DiagnosticRoutineStatusEnum kStatus =
      mojom::DiagnosticRoutineStatusEnum::kRunning;
  constexpr char kExpectedStatusMessage[] = "Expected status message.";
  constexpr uint32_t kExpectedProgressPercent = 19;
  constexpr char kExpectedOutput[] = "Expected output.";
  routine_factory()->SetRoutineExpectations(params().num_expected_start_calls,
                                            params().num_expected_resume_calls,
                                            params().num_expected_cancel_calls);
  routine_factory()->SetNonInteractiveStatus(kStatus, kExpectedStatusMessage,
                                             kExpectedProgressPercent,
                                             kExpectedOutput);

  TestFuture<mojom::RunRoutineResponsePtr> future;
  service()->RunSmartctlCheckRoutine(
      /*percentage_used_threshold=*/mojom::NullableUint32Ptr(),
      future.GetCallback());

  auto response = future.Take();
  auto update = ExecuteGetRoutineUpdate(response->id, params().command,
                                        /*include_output=*/true);

  EXPECT_EQ(update->progress_percent, kExpectedProgressPercent);
  std::string output =
      GetStringFromValidReadOnlySharedMemoryMapping(std::move(update->output));
  EXPECT_EQ(output, kExpectedOutput);
  VerifyNonInteractiveUpdate(update->routine_update_union,
                             params().expected_status, kExpectedStatusMessage);
}

INSTANTIATE_TEST_SUITE_P(
    ,
    DiagnosticsUpdateCommandTest,
    testing::Values(
        DiagnosticsUpdateCommandTestParams{
            mojom::DiagnosticRoutineCommandEnum::kCancel,
            mojom::DiagnosticRoutineStatusEnum::kRunning,
            /*num_expected_start_calls=*/1,
            /*num_expected_resume_calls=*/0,
            /*num_expected_cancel_calls=*/1},
        DiagnosticsUpdateCommandTestParams{
            mojom::DiagnosticRoutineCommandEnum::kContinue,
            mojom::DiagnosticRoutineStatusEnum::kRunning,
            /*num_expected_start_calls=*/1,
            /*num_expected_resume_calls=*/1,
            /*num_expected_cancel_calls=*/0},
        DiagnosticsUpdateCommandTestParams{
            mojom::DiagnosticRoutineCommandEnum::kGetStatus,
            mojom::DiagnosticRoutineStatusEnum::kRunning,
            /*num_expected_start_calls=*/1,
            /*num_expected_resume_calls=*/0,
            /*num_expected_cancel_calls=*/0},
        DiagnosticsUpdateCommandTestParams{
            mojom::DiagnosticRoutineCommandEnum::kRemove,
            mojom::DiagnosticRoutineStatusEnum::kRemoved,
            /*num_expected_start_calls=*/1,
            /*num_expected_resume_calls=*/0,
            /*num_expected_cancel_calls=*/0}));

}  // namespace
}  // namespace diagnostics
