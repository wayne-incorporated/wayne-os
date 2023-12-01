// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/fake/fake_diagnostics_service.h"

#include <optional>

#include <base/logging.h>
#include <base/notreached.h>

#include "diagnostics/mojom/public/nullable_primitives.mojom.h"

namespace diagnostics {

namespace mojom = ::ash::cros_healthd::mojom;

FakeDiagnosticsService::FakeDiagnosticsService() = default;
FakeDiagnosticsService::~FakeDiagnosticsService() = default;

void FakeDiagnosticsService::GetAvailableRoutines(
    GetAvailableRoutinesCallback callback) {
  NOTIMPLEMENTED();
}

void FakeDiagnosticsService::GetRoutineUpdate(
    int32_t id,
    mojom::DiagnosticRoutineCommandEnum command,
    bool include_output,
    GetRoutineUpdateCallback callback) {
  NOTIMPLEMENTED();
}

void FakeDiagnosticsService::RunUrandomRoutine(
    mojom::NullableUint32Ptr length_seconds,
    RunUrandomRoutineCallback callback) {
  NOTIMPLEMENTED();
}

void FakeDiagnosticsService::RunBatteryCapacityRoutine(
    RunBatteryCapacityRoutineCallback callback) {
  NOTIMPLEMENTED();
}

void FakeDiagnosticsService::RunBatteryHealthRoutine(
    RunBatteryHealthRoutineCallback callback) {
  NOTIMPLEMENTED();
}

void FakeDiagnosticsService::RunSmartctlCheckRoutine(
    mojom::NullableUint32Ptr percentage_used_threshold,
    RunSmartctlCheckRoutineCallback callback) {
  NOTIMPLEMENTED();
}

void FakeDiagnosticsService::RunAcPowerRoutine(
    mojom::AcPowerStatusEnum expected_status,
    const std::optional<std::string>& expected_power_type,
    RunAcPowerRoutineCallback callback) {
  NOTIMPLEMENTED();
}

void FakeDiagnosticsService::RunCpuCacheRoutine(
    mojom::NullableUint32Ptr length_seconds,
    RunCpuCacheRoutineCallback callback) {
  NOTIMPLEMENTED();
}

void FakeDiagnosticsService::RunCpuStressRoutine(
    mojom::NullableUint32Ptr length_seconds,
    RunCpuStressRoutineCallback callback) {
  NOTIMPLEMENTED();
}

void FakeDiagnosticsService::RunFloatingPointAccuracyRoutine(
    mojom::NullableUint32Ptr length_seconds,
    RunFloatingPointAccuracyRoutineCallback callback) {
  NOTIMPLEMENTED();
}

void FakeDiagnosticsService::DEPRECATED_RunNvmeWearLevelRoutine(
    uint32_t wear_level_threshold, RunNvmeWearLevelRoutineCallback callback) {
  NOTIMPLEMENTED();
}

void FakeDiagnosticsService::RunNvmeWearLevelRoutine(
    ash::cros_healthd::mojom::NullableUint32Ptr wear_level_threshold,
    RunNvmeWearLevelRoutineCallback callback) {
  NOTIMPLEMENTED();
}

void FakeDiagnosticsService::RunNvmeSelfTestRoutine(
    mojom::NvmeSelfTestTypeEnum nvme_self_test_type,
    RunNvmeSelfTestRoutineCallback callback) {
  NOTIMPLEMENTED();
}

void FakeDiagnosticsService::RunDiskReadRoutine(
    mojom::DiskReadRoutineTypeEnum type,
    uint32_t length_seconds,
    uint32_t file_size_mb,
    RunDiskReadRoutineCallback callback) {
  NOTIMPLEMENTED();
}

void FakeDiagnosticsService::RunPrimeSearchRoutine(
    mojom::NullableUint32Ptr length_seconds,
    RunPrimeSearchRoutineCallback callback) {
  NOTIMPLEMENTED();
}

void FakeDiagnosticsService::RunBatteryDischargeRoutine(
    uint32_t length_seconds,
    uint32_t maximum_discharge_percent_allowed,
    RunBatteryDischargeRoutineCallback callback) {
  NOTIMPLEMENTED();
}

void FakeDiagnosticsService::RunBatteryChargeRoutine(
    uint32_t length_seconds,
    uint32_t minimum_charge_percent_required,
    RunBatteryDischargeRoutineCallback callback) {
  NOTIMPLEMENTED();
}

void FakeDiagnosticsService::RunMemoryRoutine(
    std::optional<uint32_t> max_testing_mem_kib,
    RunMemoryRoutineCallback callback) {
  NOTIMPLEMENTED();
}

void FakeDiagnosticsService::RunLanConnectivityRoutine(
    RunLanConnectivityRoutineCallback callback) {
  NOTIMPLEMENTED();
}

void FakeDiagnosticsService::RunSignalStrengthRoutine(
    RunSignalStrengthRoutineCallback callback) {
  NOTIMPLEMENTED();
}

void FakeDiagnosticsService::RunGatewayCanBePingedRoutine(
    RunGatewayCanBePingedRoutineCallback callback) {
  NOTIMPLEMENTED();
}

void FakeDiagnosticsService::RunHasSecureWiFiConnectionRoutine(
    RunHasSecureWiFiConnectionRoutineCallback callback) {
  NOTIMPLEMENTED();
}

void FakeDiagnosticsService::RunDnsResolverPresentRoutine(
    RunDnsResolverPresentRoutineCallback callback) {
  NOTIMPLEMENTED();
}

void FakeDiagnosticsService::RunDnsLatencyRoutine(
    RunDnsLatencyRoutineCallback callback) {
  NOTIMPLEMENTED();
}

void FakeDiagnosticsService::RunDnsResolutionRoutine(
    RunDnsResolutionRoutineCallback callback) {
  NOTIMPLEMENTED();
}

void FakeDiagnosticsService::RunCaptivePortalRoutine(
    RunCaptivePortalRoutineCallback callback) {
  NOTIMPLEMENTED();
}

void FakeDiagnosticsService::RunHttpFirewallRoutine(
    RunHttpFirewallRoutineCallback callback) {
  NOTIMPLEMENTED();
}

void FakeDiagnosticsService::RunHttpsFirewallRoutine(
    RunHttpsFirewallRoutineCallback callback) {
  NOTIMPLEMENTED();
}

void FakeDiagnosticsService::RunHttpsLatencyRoutine(
    RunHttpsLatencyRoutineCallback callback) {
  NOTIMPLEMENTED();
}

void FakeDiagnosticsService::RunVideoConferencingRoutine(
    const std::optional<std::string>& stun_server_hostname,
    RunVideoConferencingRoutineCallback callback) {
  NOTIMPLEMENTED();
}

void FakeDiagnosticsService::RunArcHttpRoutine(
    RunArcHttpRoutineCallback callback) {
  NOTIMPLEMENTED();
}

void FakeDiagnosticsService::RunArcPingRoutine(
    RunArcPingRoutineCallback callback) {
  NOTIMPLEMENTED();
}

void FakeDiagnosticsService::RunArcDnsResolutionRoutine(
    RunArcDnsResolutionRoutineCallback callback) {
  NOTIMPLEMENTED();
}

void FakeDiagnosticsService::RunSensitiveSensorRoutine(
    RunSensitiveSensorRoutineCallback callback) {
  NOTIMPLEMENTED();
}

void FakeDiagnosticsService::RunFingerprintRoutine(
    RunFingerprintRoutineCallback callback) {
  NOTIMPLEMENTED();
}

void FakeDiagnosticsService::RunFingerprintAliveRoutine(
    RunFingerprintAliveRoutineCallback callback) {
  NOTIMPLEMENTED();
}

void FakeDiagnosticsService::RunPrivacyScreenRoutine(
    bool target_state, RunPrivacyScreenRoutineCallback callback) {
  NOTIMPLEMENTED();
}

void FakeDiagnosticsService::RunLedLitUpRoutine(
    mojom::LedName name,
    mojom::LedColor color,
    mojo::PendingRemote<mojom::LedLitUpRoutineReplier> replier,
    RunLedLitUpRoutineCallback callback) {
  NOTIMPLEMENTED();
}

void FakeDiagnosticsService::RunEmmcLifetimeRoutine(
    RunEmmcLifetimeRoutineCallback callback) {
  NOTIMPLEMENTED();
}

void FakeDiagnosticsService::RunAudioSetVolumeRoutine(
    uint64_t node_id,
    uint8_t volume,
    bool mute_on,
    RunAudioSetVolumeRoutineCallback callback) {
  NOTIMPLEMENTED();
}

void FakeDiagnosticsService::RunAudioSetGainRoutine(
    uint64_t node_id,
    uint8_t gain,
    bool deprecated_mute_on,
    RunAudioSetGainRoutineCallback callback) {
  NOTIMPLEMENTED();
}

void FakeDiagnosticsService::RunBluetoothPowerRoutine(
    RunBluetoothPowerRoutineCallback callback) {
  NOTIMPLEMENTED();
}

void FakeDiagnosticsService::RunBluetoothDiscoveryRoutine(
    RunBluetoothDiscoveryRoutineCallback callback) {
  NOTIMPLEMENTED();
}

void FakeDiagnosticsService::RunBluetoothScanningRoutine(
    mojom::NullableUint32Ptr length_seconds,
    RunBluetoothScanningRoutineCallback callback) {
  NOTIMPLEMENTED();
}

void FakeDiagnosticsService::RunBluetoothPairingRoutine(
    const std::string& peripheral_id,
    RunBluetoothPairingRoutineCallback callback) {
  NOTIMPLEMENTED();
}

void FakeDiagnosticsService::RunPowerButtonRoutine(
    uint32_t timeout_seconds, RunPowerButtonRoutineCallback callback) {
  NOTIMPLEMENTED();
}

void FakeDiagnosticsService::RunAudioDriverRoutine(
    RunAudioDriverRoutineCallback callback) {
  NOTIMPLEMENTED();
}

}  // namespace diagnostics
