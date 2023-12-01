// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/wilco_dtc_supportd/fake_diagnostics_service.h"

#include <cstdint>
#include <optional>
#include <utility>

#include "diagnostics/mojom/public/nullable_primitives.mojom.h"
#include "diagnostics/wilco_dtc_supportd/utils/mojo_utils.h"

namespace diagnostics {
namespace wilco {

namespace mojo_ipc = ::ash::cros_healthd::mojom;

FakeDiagnosticsService::FakeDiagnosticsService() = default;
FakeDiagnosticsService::~FakeDiagnosticsService() = default;

bool FakeDiagnosticsService::GetCrosHealthdDiagnosticsService(
    mojo::PendingReceiver<mojo_ipc::CrosHealthdDiagnosticsService> service) {
  // In situations where cros_healthd is unresponsive, the delegate wouldn't
  // know this, and would think that it had passed along the service request
  // and everything is fine. However, nothing would bind that request.
  if (!is_responsive_)
    return true;

  // In situations where wilco_dtc_supportd's mojo service hasn't been set up
  // yet, the delegate would realize this and report failure.
  if (!is_available_)
    return false;

  // When there are no errors with the request, it will be bound.
  service_receiver_.Bind(std::move(service));
  return true;
}

void FakeDiagnosticsService::GetAvailableRoutines(
    GetAvailableRoutinesCallback callback) {
  std::move(callback).Run(available_routines_);
}

void FakeDiagnosticsService::GetRoutineUpdate(
    int32_t id,
    mojo_ipc::DiagnosticRoutineCommandEnum command,
    bool include_output,
    GetRoutineUpdateCallback callback) {
  std::move(callback).Run(mojo_ipc::RoutineUpdate::New(
      routine_update_response_.progress_percent,
      std::move(routine_update_response_.output),
      std::move(routine_update_response_.routine_update_union)));
}

void FakeDiagnosticsService::RunUrandomRoutine(
    mojo_ipc::NullableUint32Ptr length_seconds,
    RunUrandomRoutineCallback callback) {
  std::move(callback).Run(run_routine_response_.Clone());
}

void FakeDiagnosticsService::RunBatteryCapacityRoutine(
    RunBatteryCapacityRoutineCallback callback) {
  std::move(callback).Run(run_routine_response_.Clone());
}

void FakeDiagnosticsService::RunBatteryHealthRoutine(
    RunBatteryHealthRoutineCallback callback) {
  std::move(callback).Run(run_routine_response_.Clone());
}

void FakeDiagnosticsService::RunSmartctlCheckRoutine(
    mojo_ipc::NullableUint32Ptr percentage_used_threshold,
    RunSmartctlCheckRoutineCallback callback) {
  std::move(callback).Run(run_routine_response_.Clone());
}

void FakeDiagnosticsService::RunAcPowerRoutine(
    mojo_ipc::AcPowerStatusEnum expected_status,
    const std::optional<std::string>& expected_power_type,
    RunAcPowerRoutineCallback callback) {
  std::move(callback).Run(run_routine_response_.Clone());
}

void FakeDiagnosticsService::RunCpuCacheRoutine(
    mojo_ipc::NullableUint32Ptr length_seconds,
    RunCpuCacheRoutineCallback callback) {
  std::move(callback).Run(run_routine_response_.Clone());
}

void FakeDiagnosticsService::RunCpuStressRoutine(
    mojo_ipc::NullableUint32Ptr length_seconds,
    RunCpuStressRoutineCallback callback) {
  std::move(callback).Run(run_routine_response_.Clone());
}

void FakeDiagnosticsService::RunFloatingPointAccuracyRoutine(
    mojo_ipc::NullableUint32Ptr length_seconds,
    RunFloatingPointAccuracyRoutineCallback callback) {
  std::move(callback).Run(run_routine_response_.Clone());
}

void FakeDiagnosticsService::DEPRECATED_RunNvmeWearLevelRoutine(
    uint32_t wear_level_threshold, RunNvmeWearLevelRoutineCallback callback) {
  std::move(callback).Run(run_routine_response_.Clone());
}

void FakeDiagnosticsService::RunNvmeWearLevelRoutine(
    ash::cros_healthd::mojom::NullableUint32Ptr wear_level_threshold,
    RunNvmeWearLevelRoutineCallback callback) {
  std::move(callback).Run(run_routine_response_.Clone());
}

void FakeDiagnosticsService::RunNvmeSelfTestRoutine(
    mojo_ipc::NvmeSelfTestTypeEnum nvme_self_test_type,
    RunNvmeSelfTestRoutineCallback callback) {
  std::move(callback).Run(run_routine_response_.Clone());
}

void FakeDiagnosticsService::RunDiskReadRoutine(
    mojo_ipc::DiskReadRoutineTypeEnum type,
    uint32_t length_seconds,
    uint32_t file_size_mb,
    RunDiskReadRoutineCallback callback) {
  std::move(callback).Run(run_routine_response_.Clone());
}

void FakeDiagnosticsService::RunPrimeSearchRoutine(
    mojo_ipc::NullableUint32Ptr length_seconds,
    RunPrimeSearchRoutineCallback callback) {
  std::move(callback).Run(run_routine_response_.Clone());
}

void FakeDiagnosticsService::RunBatteryDischargeRoutine(
    uint32_t length_seconds,
    uint32_t maximum_discharge_percent_allowed,
    RunBatteryDischargeRoutineCallback callback) {
  std::move(callback).Run(run_routine_response_.Clone());
}

void FakeDiagnosticsService::RunBatteryChargeRoutine(
    uint32_t length_seconds,
    uint32_t minimum_charge_percent_required,
    RunBatteryChargeRoutineCallback callback) {
  std::move(callback).Run(run_routine_response_.Clone());
}

void FakeDiagnosticsService::RunMemoryRoutine(
    std::optional<uint32_t> max_testing_mem_kib,
    RunMemoryRoutineCallback callback) {
  std::move(callback).Run(run_routine_response_.Clone());
}

void FakeDiagnosticsService::RunLanConnectivityRoutine(
    RunLanConnectivityRoutineCallback callback) {
  std::move(callback).Run(run_routine_response_.Clone());
}

void FakeDiagnosticsService::RunSignalStrengthRoutine(
    RunSignalStrengthRoutineCallback callback) {
  std::move(callback).Run(run_routine_response_.Clone());
}

void FakeDiagnosticsService::RunGatewayCanBePingedRoutine(
    RunGatewayCanBePingedRoutineCallback callback) {
  std::move(callback).Run(run_routine_response_.Clone());
}

void FakeDiagnosticsService::RunHasSecureWiFiConnectionRoutine(
    RunHasSecureWiFiConnectionRoutineCallback callback) {
  std::move(callback).Run(run_routine_response_.Clone());
}

void FakeDiagnosticsService::RunDnsResolverPresentRoutine(
    RunDnsResolverPresentRoutineCallback callback) {
  std::move(callback).Run(run_routine_response_.Clone());
}

void FakeDiagnosticsService::RunDnsLatencyRoutine(
    RunDnsLatencyRoutineCallback callback) {
  std::move(callback).Run(run_routine_response_.Clone());
}

void FakeDiagnosticsService::RunDnsResolutionRoutine(
    RunDnsResolutionRoutineCallback callback) {
  std::move(callback).Run(run_routine_response_.Clone());
}

void FakeDiagnosticsService::RunCaptivePortalRoutine(
    RunCaptivePortalRoutineCallback callback) {
  std::move(callback).Run(run_routine_response_.Clone());
}

void FakeDiagnosticsService::RunHttpFirewallRoutine(
    RunHttpFirewallRoutineCallback callback) {
  std::move(callback).Run(run_routine_response_.Clone());
}

void FakeDiagnosticsService::RunHttpsFirewallRoutine(
    RunHttpsFirewallRoutineCallback callback) {
  std::move(callback).Run(run_routine_response_.Clone());
}

void FakeDiagnosticsService::RunHttpsLatencyRoutine(
    RunHttpsLatencyRoutineCallback callback) {
  std::move(callback).Run(run_routine_response_.Clone());
}

void FakeDiagnosticsService::RunVideoConferencingRoutine(
    const std::optional<std::string>& stun_server_hostname,
    RunVideoConferencingRoutineCallback callback) {
  std::move(callback).Run(run_routine_response_.Clone());
}

void FakeDiagnosticsService::RunArcHttpRoutine(
    RunArcHttpRoutineCallback callback) {
  std::move(callback).Run(run_routine_response_.Clone());
}

void FakeDiagnosticsService::RunArcPingRoutine(
    RunArcPingRoutineCallback callback) {
  std::move(callback).Run(run_routine_response_.Clone());
}

void FakeDiagnosticsService::RunArcDnsResolutionRoutine(
    RunArcDnsResolutionRoutineCallback callback) {
  std::move(callback).Run(run_routine_response_.Clone());
}

void FakeDiagnosticsService::RunSensitiveSensorRoutine(
    RunSensitiveSensorRoutineCallback callback) {
  std::move(callback).Run(run_routine_response_.Clone());
}

void FakeDiagnosticsService::RunFingerprintRoutine(
    RunFingerprintRoutineCallback callback) {
  std::move(callback).Run(run_routine_response_.Clone());
}

void FakeDiagnosticsService::RunFingerprintAliveRoutine(
    RunFingerprintAliveRoutineCallback callback) {
  std::move(callback).Run(run_routine_response_.Clone());
}

void FakeDiagnosticsService::RunPrivacyScreenRoutine(
    bool target_state, RunPrivacyScreenRoutineCallback callback) {
  std::move(callback).Run(run_routine_response_.Clone());
}

void FakeDiagnosticsService::RunLedLitUpRoutine(
    mojo_ipc::LedName name,
    mojo_ipc::LedColor color,
    mojo::PendingRemote<mojo_ipc::LedLitUpRoutineReplier> replier,
    RunLedLitUpRoutineCallback callback) {
  std::move(callback).Run(run_routine_response_.Clone());
}

void FakeDiagnosticsService::RunEmmcLifetimeRoutine(
    RunEmmcLifetimeRoutineCallback callback) {
  std::move(callback).Run(run_routine_response_.Clone());
}

void FakeDiagnosticsService::RunAudioSetVolumeRoutine(
    uint64_t node_id,
    uint8_t volume,
    bool mute_on,
    RunAudioSetVolumeRoutineCallback callback) {
  std::move(callback).Run(run_routine_response_.Clone());
}

void FakeDiagnosticsService::RunAudioSetGainRoutine(
    uint64_t node_id,
    uint8_t gain,
    bool deprecated_mute_on,
    RunAudioSetGainRoutineCallback callback) {
  std::move(callback).Run(run_routine_response_.Clone());
}

void FakeDiagnosticsService::RunBluetoothPowerRoutine(
    RunBluetoothPowerRoutineCallback callback) {
  std::move(callback).Run(run_routine_response_.Clone());
}

void FakeDiagnosticsService::RunBluetoothDiscoveryRoutine(
    RunBluetoothDiscoveryRoutineCallback callback) {
  std::move(callback).Run(run_routine_response_.Clone());
}

void FakeDiagnosticsService::RunBluetoothScanningRoutine(
    mojo_ipc::NullableUint32Ptr length_seconds,
    RunBluetoothScanningRoutineCallback callback) {
  std::move(callback).Run(run_routine_response_.Clone());
}

void FakeDiagnosticsService::RunBluetoothPairingRoutine(
    const std::string& peripheral_id,
    RunBluetoothPairingRoutineCallback callback) {
  std::move(callback).Run(run_routine_response_.Clone());
}

void FakeDiagnosticsService::RunPowerButtonRoutine(
    uint32_t timeout_seconds, RunPowerButtonRoutineCallback callback) {
  std::move(callback).Run(run_routine_response_.Clone());
}

void FakeDiagnosticsService::RunAudioDriverRoutine(
    RunAudioDriverRoutineCallback callback) {
  std::move(callback).Run(run_routine_response_.Clone());
}

void FakeDiagnosticsService::SetMojoServiceIsAvailable(bool is_available) {
  is_available_ = is_available;
}

void FakeDiagnosticsService::SetMojoServiceIsResponsive(bool is_responsive) {
  is_responsive_ = is_responsive;
}

void FakeDiagnosticsService::ResetMojoConnection() {
  service_receiver_.reset();
}

void FakeDiagnosticsService::SetGetAvailableRoutinesResponse(
    const std::vector<mojo_ipc::DiagnosticRoutineEnum>& available_routines) {
  available_routines_ = available_routines;
}

void FakeDiagnosticsService::SetInteractiveUpdate(
    mojo_ipc::DiagnosticRoutineUserMessageEnum user_message,
    uint32_t progress_percent,
    const std::string& output) {
  routine_update_response_.progress_percent = progress_percent;
  routine_update_response_.output =
      CreateReadOnlySharedMemoryRegionMojoHandle(output);
  auto interactive_update = mojo_ipc::InteractiveRoutineUpdate::New();
  interactive_update->user_message = user_message;
  routine_update_response_.routine_update_union =
      mojo_ipc::RoutineUpdateUnion::NewInteractiveUpdate(
          std::move(interactive_update));
}

void FakeDiagnosticsService::SetNonInteractiveUpdate(
    mojo_ipc::DiagnosticRoutineStatusEnum status,
    const std::string& status_message,
    uint32_t progress_percent,
    const std::string& output) {
  routine_update_response_.progress_percent = progress_percent;
  routine_update_response_.output =
      CreateReadOnlySharedMemoryRegionMojoHandle(output);
  auto noninteractive_update = mojo_ipc::NonInteractiveRoutineUpdate::New();
  noninteractive_update->status = status;
  noninteractive_update->status_message = status_message;
  routine_update_response_.routine_update_union =
      mojo_ipc::RoutineUpdateUnion::NewNoninteractiveUpdate(
          std::move(noninteractive_update));
}

void FakeDiagnosticsService::SetRunSomeRoutineResponse(
    uint32_t id, mojo_ipc::DiagnosticRoutineStatusEnum status) {
  run_routine_response_.id = id;
  run_routine_response_.status = status;
}

}  // namespace wilco
}  // namespace diagnostics
