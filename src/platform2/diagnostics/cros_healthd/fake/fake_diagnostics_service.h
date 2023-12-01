// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_FAKE_FAKE_DIAGNOSTICS_SERVICE_H_
#define DIAGNOSTICS_CROS_HEALTHD_FAKE_FAKE_DIAGNOSTICS_SERVICE_H_

#include <cstdint>
#include <optional>
#include <string>

#include "diagnostics/mojom/public/cros_healthd.mojom.h"

namespace diagnostics {

// Fake implementation of the CrosHealthdDiagnosticsService interface.
class FakeDiagnosticsService final
    : public ash::cros_healthd::mojom::CrosHealthdDiagnosticsService {
 public:
  using DiagnosticRoutineStatusEnum =
      ::ash::cros_healthd::mojom::DiagnosticRoutineStatusEnum;
  using RunRoutineResponse = ::ash::cros_healthd::mojom::RunRoutineResponse;

  FakeDiagnosticsService();
  FakeDiagnosticsService(const FakeDiagnosticsService&) = delete;
  FakeDiagnosticsService& operator=(const FakeDiagnosticsService&) = delete;
  ~FakeDiagnosticsService() override;

  // ash::cros_healthd::mojom::CrosHealthdDiagnosticsService overrides:
  void GetAvailableRoutines(GetAvailableRoutinesCallback callback) override;
  void GetRoutineUpdate(
      int32_t id,
      ash::cros_healthd::mojom::DiagnosticRoutineCommandEnum command,
      bool include_output,
      GetRoutineUpdateCallback callback) override;
  void RunUrandomRoutine(
      ash::cros_healthd::mojom::NullableUint32Ptr length_seconds,
      RunUrandomRoutineCallback callback) override;
  void RunBatteryCapacityRoutine(
      RunBatteryCapacityRoutineCallback callback) override;
  void RunBatteryHealthRoutine(
      RunBatteryHealthRoutineCallback callback) override;
  void RunSmartctlCheckRoutine(
      ash::cros_healthd::mojom::NullableUint32Ptr percentage_used_threshold,
      RunSmartctlCheckRoutineCallback callback) override;
  void RunAcPowerRoutine(
      ash::cros_healthd::mojom::AcPowerStatusEnum expected_status,
      const std::optional<std::string>& expected_power_type,
      RunAcPowerRoutineCallback callback) override;
  void RunCpuCacheRoutine(
      ash::cros_healthd::mojom::NullableUint32Ptr length_seconds,
      RunCpuCacheRoutineCallback callback) override;
  void RunCpuStressRoutine(
      ash::cros_healthd::mojom::NullableUint32Ptr length_seconds,
      RunCpuStressRoutineCallback callback) override;
  void RunFloatingPointAccuracyRoutine(
      ash::cros_healthd::mojom::NullableUint32Ptr length_seconds,
      RunFloatingPointAccuracyRoutineCallback callback) override;
  void DEPRECATED_RunNvmeWearLevelRoutine(
      uint32_t wear_level_threshold,
      RunNvmeWearLevelRoutineCallback callback) override;
  void RunNvmeWearLevelRoutine(
      ash::cros_healthd::mojom::NullableUint32Ptr wear_level_threshold,
      RunNvmeWearLevelRoutineCallback callback) override;
  void RunNvmeSelfTestRoutine(
      ash::cros_healthd::mojom::NvmeSelfTestTypeEnum nvme_self_test_type,
      RunNvmeSelfTestRoutineCallback callback) override;
  void RunDiskReadRoutine(
      ash::cros_healthd::mojom::DiskReadRoutineTypeEnum type,
      uint32_t length_seconds,
      uint32_t file_size_mb,
      RunDiskReadRoutineCallback callback) override;
  void RunPrimeSearchRoutine(
      ash::cros_healthd::mojom::NullableUint32Ptr length_seconds,
      RunPrimeSearchRoutineCallback callback) override;
  void RunBatteryDischargeRoutine(
      uint32_t length_seconds,
      uint32_t maximum_discharge_percent_allowed,
      RunBatteryDischargeRoutineCallback callback) override;
  void RunBatteryChargeRoutine(
      uint32_t length_seconds,
      uint32_t minimum_charge_percent_required,
      RunBatteryChargeRoutineCallback callback) override;
  void RunMemoryRoutine(std::optional<uint32_t> max_testing_mem_kib,
                        RunMemoryRoutineCallback callback) override;
  void RunLanConnectivityRoutine(
      RunLanConnectivityRoutineCallback callback) override;
  void RunSignalStrengthRoutine(
      RunSignalStrengthRoutineCallback callback) override;
  void RunGatewayCanBePingedRoutine(
      RunGatewayCanBePingedRoutineCallback callback) override;
  void RunHasSecureWiFiConnectionRoutine(
      RunHasSecureWiFiConnectionRoutineCallback callback) override;
  void RunDnsResolverPresentRoutine(
      RunDnsResolverPresentRoutineCallback callback) override;
  void RunDnsLatencyRoutine(RunDnsLatencyRoutineCallback callback) override;
  void RunDnsResolutionRoutine(
      RunDnsResolutionRoutineCallback callback) override;
  void RunCaptivePortalRoutine(
      RunCaptivePortalRoutineCallback callback) override;
  void RunHttpFirewallRoutine(RunHttpFirewallRoutineCallback callback) override;
  void RunHttpsFirewallRoutine(
      RunHttpsFirewallRoutineCallback callback) override;
  void RunHttpsLatencyRoutine(RunHttpsLatencyRoutineCallback callback) override;
  void RunVideoConferencingRoutine(
      const std::optional<std::string>& stun_server_hostname,
      RunVideoConferencingRoutineCallback callback) override;
  void RunArcHttpRoutine(RunArcHttpRoutineCallback callback) override;
  void RunArcPingRoutine(RunArcPingRoutineCallback callback) override;
  void RunArcDnsResolutionRoutine(
      RunArcDnsResolutionRoutineCallback callback) override;
  void RunSensitiveSensorRoutine(
      RunSensitiveSensorRoutineCallback callback) override;
  void RunFingerprintRoutine(RunFingerprintRoutineCallback callback) override;
  void RunFingerprintAliveRoutine(
      RunFingerprintAliveRoutineCallback callback) override;
  void RunPrivacyScreenRoutine(
      bool target_state, RunPrivacyScreenRoutineCallback callback) override;
  void RunLedLitUpRoutine(
      ash::cros_healthd::mojom::LedName name,
      ash::cros_healthd::mojom::LedColor color,
      mojo::PendingRemote<ash::cros_healthd::mojom::LedLitUpRoutineReplier>
          replier,
      RunLedLitUpRoutineCallback callback) override;
  void RunEmmcLifetimeRoutine(RunEmmcLifetimeRoutineCallback callback) override;
  void RunAudioSetVolumeRoutine(
      uint64_t node_id,
      uint8_t volume,
      bool mute_on,
      RunAudioSetVolumeRoutineCallback callback) override;
  void RunAudioSetGainRoutine(uint64_t node_id,
                              uint8_t gain,
                              bool deprecated_mute_on,
                              RunAudioSetGainRoutineCallback callback) override;
  void RunBluetoothPowerRoutine(
      RunBluetoothPowerRoutineCallback callback) override;
  void RunBluetoothDiscoveryRoutine(
      RunBluetoothDiscoveryRoutineCallback callback) override;
  void RunBluetoothScanningRoutine(
      ash::cros_healthd::mojom::NullableUint32Ptr length_seconds,
      RunBluetoothScanningRoutineCallback callback) override;
  void RunBluetoothPairingRoutine(
      const std::string& peripheral_id,
      RunBluetoothPairingRoutineCallback callback) override;
  void RunPowerButtonRoutine(uint32_t timeout_seconds,
                             RunPowerButtonRoutineCallback callback) override;
  void RunAudioDriverRoutine(RunAudioDriverRoutineCallback callback) override;
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_FAKE_FAKE_DIAGNOSTICS_SERVICE_H_
