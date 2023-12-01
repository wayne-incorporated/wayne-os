// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_CROS_HEALTHD_DIAGNOSTICS_SERVICE_H_
#define DIAGNOSTICS_CROS_HEALTHD_CROS_HEALTHD_DIAGNOSTICS_SERVICE_H_

#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include <base/functional/callback.h>
#include <base/memory/weak_ptr.h>

#include "diagnostics/cros_healthd/cros_healthd_routine_factory.h"
#include "diagnostics/cros_healthd/routines/diag_routine.h"
#include "diagnostics/cros_healthd/system/context.h"
#include "diagnostics/cros_healthd/utils/mojo_service_provider.h"
#include "diagnostics/mojom/public/cros_healthd.mojom.h"
#include "diagnostics/mojom/public/cros_healthd_diagnostics.mojom.h"
#include "diagnostics/mojom/public/cros_healthd_routines.mojom.h"

namespace diagnostics {

// Production implementation of the CrosHealthdDiagnosticsService interface.
class CrosHealthdDiagnosticsService final
    : public ash::cros_healthd::mojom::CrosHealthdDiagnosticsService {
 public:
  CrosHealthdDiagnosticsService(
      Context* context,
      CrosHealthdRoutineFactory* routine_factory,
      ash::cros_healthd::mojom::CrosHealthdRoutinesService* routine_service);
  CrosHealthdDiagnosticsService(const CrosHealthdDiagnosticsService&) = delete;
  CrosHealthdDiagnosticsService& operator=(
      const CrosHealthdDiagnosticsService&) = delete;
  ~CrosHealthdDiagnosticsService() override;

  // ash::cros_healthd::mojom::CrosHealthdDiagnosticsService overrides:
  void GetAvailableRoutines(GetAvailableRoutinesCallback callback) override;
  void GetRoutineUpdate(
      int32_t id,
      ash::cros_healthd::mojom::DiagnosticRoutineCommandEnum command,
      bool include_output,
      GetRoutineUpdateCallback callback) override;
  void RunAcPowerRoutine(
      ash::cros_healthd::mojom::AcPowerStatusEnum expected_status,
      const std::optional<std::string>& expected_power_type,
      RunAcPowerRoutineCallback callback) override;
  void RunBatteryCapacityRoutine(
      RunBatteryCapacityRoutineCallback callback) override;
  void RunBatteryChargeRoutine(
      uint32_t length_seconds,
      uint32_t minimum_charge_percent_required,
      RunBatteryChargeRoutineCallback callback) override;
  void RunBatteryDischargeRoutine(
      uint32_t length_seconds,
      uint32_t maximum_discharge_percent_allowed,
      RunBatteryDischargeRoutineCallback callback) override;
  void RunBatteryHealthRoutine(
      RunBatteryHealthRoutineCallback callback) override;
  void RunCaptivePortalRoutine(
      RunCaptivePortalRoutineCallback callback) override;
  void RunCpuCacheRoutine(
      ash::cros_healthd::mojom::NullableUint32Ptr length_seconds,
      RunCpuCacheRoutineCallback callback) override;
  void RunCpuStressRoutine(
      ash::cros_healthd::mojom::NullableUint32Ptr length_seconds,
      RunCpuStressRoutineCallback callback) override;
  void RunDiskReadRoutine(
      ash::cros_healthd::mojom::DiskReadRoutineTypeEnum type,
      uint32_t length_seconds,
      uint32_t file_size_mb,
      RunDiskReadRoutineCallback callback) override;
  void RunDnsLatencyRoutine(RunDnsLatencyRoutineCallback callback) override;
  void RunDnsResolutionRoutine(
      RunDnsResolutionRoutineCallback callback) override;
  void RunDnsResolverPresentRoutine(
      RunDnsResolverPresentRoutineCallback callback) override;
  void RunFloatingPointAccuracyRoutine(
      ash::cros_healthd::mojom::NullableUint32Ptr length_seconds,
      RunFloatingPointAccuracyRoutineCallback callback) override;
  void RunGatewayCanBePingedRoutine(
      RunGatewayCanBePingedRoutineCallback callback) override;
  void RunHasSecureWiFiConnectionRoutine(
      RunHasSecureWiFiConnectionRoutineCallback callback) override;
  void RunHttpFirewallRoutine(RunHttpFirewallRoutineCallback callback) override;
  void RunHttpsFirewallRoutine(
      RunHttpsFirewallRoutineCallback callback) override;
  void RunHttpsLatencyRoutine(RunHttpsLatencyRoutineCallback callback) override;
  void RunLanConnectivityRoutine(
      RunLanConnectivityRoutineCallback callback) override;
  void RunMemoryRoutine(std::optional<uint32_t> max_testing_mem_kib,
                        RunMemoryRoutineCallback callback) override;
  void RunNvmeSelfTestRoutine(
      ash::cros_healthd::mojom::NvmeSelfTestTypeEnum nvme_self_test_type,
      RunNvmeSelfTestRoutineCallback callback) override;
  void DEPRECATED_RunNvmeWearLevelRoutine(
      uint32_t wear_level_threshold,
      RunNvmeWearLevelRoutineCallback callback) override;
  void RunNvmeWearLevelRoutine(
      ash::cros_healthd::mojom::NullableUint32Ptr wear_level_threshold,
      RunNvmeWearLevelRoutineCallback callback) override;
  void RunPrimeSearchRoutine(
      ash::cros_healthd::mojom::NullableUint32Ptr length_seconds,
      RunPrimeSearchRoutineCallback callback) override;
  void RunSignalStrengthRoutine(
      RunSignalStrengthRoutineCallback callback) override;
  void RunSmartctlCheckRoutine(
      ash::cros_healthd::mojom::NullableUint32Ptr percentage_used_threshold,
      RunSmartctlCheckRoutineCallback callback) override;
  void RunUrandomRoutine(
      ash::cros_healthd::mojom::NullableUint32Ptr length_seconds,
      RunUrandomRoutineCallback callback) override;
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

 private:
  void RunRoutine(
      std::unique_ptr<DiagnosticRoutine> routine,
      ash::cros_healthd::mojom::DiagnosticRoutineEnum routine_enum,
      base::OnceCallback<void(ash::cros_healthd::mojom::RunRoutineResponsePtr)>
          callback);

  // Callback for checking whether nvme-self-test is supported.
  void HandleNvmeSelfTestSupportedResponse(bool supported);

  // Called when this service is ready to handle CrosHealthdDiagnosticsService
  // method calls.
  void OnServiceReady();

  // Checks what routines are supported on the device and populates the member
  // available_routines_. Run |completion_callback| when all the checks are
  // done.
  void PopulateAvailableRoutines(base::OnceClosure completion_callback);

  // Map from IDs to instances of diagnostics routines that have
  // been started.
  std::map<int32_t, std::unique_ptr<DiagnosticRoutine>> active_routines_;
  // Generator for IDs - currently, when we need a new ID we just return
  // next_id_, then increment next_id_.
  int32_t next_id_ = 1;
  // Each of the supported diagnostic routines. Must be kept in sync with the
  // enums in diagnostics/mojo/cros_health_diagnostics.mojom.
  std::set<ash::cros_healthd::mojom::DiagnosticRoutineEnum> available_routines_;
  // Unowned pointer that should outlive this instance.
  Context* const context_ = nullptr;
  // Responsible for making the routines. Unowned pointer that should outlive
  // this instance.
  CrosHealthdRoutineFactory* const routine_factory_ = nullptr;
  // Mojo service provider to provide service to mojo service manager.
  MojoServiceProvider<ash::cros_healthd::mojom::CrosHealthdDiagnosticsService>
      provider_{this};

  [[maybe_unused]] ash::cros_healthd::mojom::CrosHealthdRoutinesService* const
      routine_service_;

  // Must be the last class member.
  base::WeakPtrFactory<CrosHealthdDiagnosticsService> weak_ptr_factory_{this};
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_CROS_HEALTHD_DIAGNOSTICS_SERVICE_H_
