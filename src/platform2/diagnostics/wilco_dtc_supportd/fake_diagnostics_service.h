// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_WILCO_DTC_SUPPORTD_FAKE_DIAGNOSTICS_SERVICE_H_
#define DIAGNOSTICS_WILCO_DTC_SUPPORTD_FAKE_DIAGNOSTICS_SERVICE_H_

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include <mojo/public/cpp/bindings/pending_receiver.h>
#include <mojo/public/cpp/bindings/receiver.h>
#include <mojo/public/cpp/system/handle.h>

#include "diagnostics/mojom/public/cros_healthd.mojom.h"
#include "diagnostics/mojom/public/cros_healthd_diagnostics.mojom.h"
#include "diagnostics/wilco_dtc_supportd/routine_service.h"

namespace diagnostics {
namespace wilco {

// Helper class that allows testing of the routine service.
class FakeDiagnosticsService final
    : public RoutineService::Delegate,
      public ash::cros_healthd::mojom::CrosHealthdDiagnosticsService {
 public:
  FakeDiagnosticsService();
  FakeDiagnosticsService(const FakeDiagnosticsService&) = delete;
  FakeDiagnosticsService& operator=(const FakeDiagnosticsService&) = delete;

  ~FakeDiagnosticsService();

  // RoutineService::Delegate overrides:
  bool GetCrosHealthdDiagnosticsService(
      mojo::PendingReceiver<
          ash::cros_healthd::mojom::CrosHealthdDiagnosticsService> service)
      override;

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
  void RunLanConnectivityRoutine(RunLanConnectivityRoutineCallback) override;
  void RunSignalStrengthRoutine(RunSignalStrengthRoutineCallback) override;
  void RunGatewayCanBePingedRoutine(
      RunGatewayCanBePingedRoutineCallback) override;
  void RunHasSecureWiFiConnectionRoutine(
      RunHasSecureWiFiConnectionRoutineCallback) override;
  void RunDnsResolverPresentRoutine(
      RunDnsResolverPresentRoutineCallback) override;
  void RunDnsLatencyRoutine(RunDnsLatencyRoutineCallback) override;
  void RunDnsResolutionRoutine(RunDnsResolutionRoutineCallback) override;
  void RunCaptivePortalRoutine(RunCaptivePortalRoutineCallback) override;
  void RunHttpFirewallRoutine(RunHttpFirewallRoutineCallback) override;
  void RunHttpsFirewallRoutine(RunHttpsFirewallRoutineCallback) override;
  void RunHttpsLatencyRoutine(RunHttpsLatencyRoutineCallback) override;
  void RunVideoConferencingRoutine(
      const std::optional<std::string>& stun_server_hostname,
      RunVideoConferencingRoutineCallback) override;
  void RunArcHttpRoutine(RunArcHttpRoutineCallback) override;
  void RunArcPingRoutine(RunArcPingRoutineCallback) override;
  void RunArcDnsResolutionRoutine(RunArcDnsResolutionRoutineCallback) override;
  void RunSensitiveSensorRoutine(RunSensitiveSensorRoutineCallback) override;
  void RunFingerprintRoutine(RunFingerprintRoutineCallback) override;
  void RunFingerprintAliveRoutine(RunFingerprintAliveRoutineCallback) override;
  void RunPrivacyScreenRoutine(bool target_state,
                               RunPrivacyScreenRoutineCallback) override;
  void RunLedLitUpRoutine(
      ash::cros_healthd::mojom::LedName name,
      ash::cros_healthd::mojom::LedColor color,
      mojo::PendingRemote<ash::cros_healthd::mojom::LedLitUpRoutineReplier>
          replier,
      RunLedLitUpRoutineCallback callback) override;
  void RunEmmcLifetimeRoutine(RunEmmcLifetimeRoutineCallback callback) override;
  void RunAudioSetVolumeRoutine(uint64_t node_id,
                                uint8_t volume,
                                bool mute_on,
                                RunAudioSetVolumeRoutineCallback) override;
  void RunAudioSetGainRoutine(uint64_t node_id,
                              uint8_t gain,
                              bool deprecated_mute_on,
                              RunAudioSetGainRoutineCallback) override;
  void RunBluetoothDiscoveryRoutine(
      RunBluetoothDiscoveryRoutineCallback callback) override;
  void RunBluetoothPowerRoutine(
      RunBluetoothPowerRoutineCallback callback) override;
  void RunBluetoothScanningRoutine(
      ash::cros_healthd::mojom::NullableUint32Ptr length_seconds,
      RunBluetoothScanningRoutineCallback callback) override;
  void RunBluetoothPairingRoutine(
      const std::string& peripheral_id,
      RunBluetoothPairingRoutineCallback callback) override;
  void RunPowerButtonRoutine(uint32_t timeout_seconds,
                             RunPowerButtonRoutineCallback callback) override;
  void RunAudioDriverRoutine(RunAudioDriverRoutineCallback callback) override;

  // Overrides the default behavior of GetCrosHealthdDiagnosticsService to test
  // situations where mojo methods were called prior to wilco_dtc_supportd's
  // mojo service being established.
  void SetMojoServiceIsAvailable(bool is_available);

  // Overrides the default behavior of GetCrosHealthdDiagnosticsService to test
  // situations where cros_healthd is unresponsive.
  void SetMojoServiceIsResponsive(bool is_responsive);

  // Resets the mojo connection.
  void ResetMojoConnection();

  // Sets the response to any GetAvailableRoutines IPCs received.
  void SetGetAvailableRoutinesResponse(
      const std::vector<ash::cros_healthd::mojom::DiagnosticRoutineEnum>&
          available_routines);

  // Sets an interactive response to any GetRoutineUpdate IPCs received.
  void SetInteractiveUpdate(
      ash::cros_healthd::mojom::DiagnosticRoutineUserMessageEnum user_message,
      uint32_t progress_percent,
      const std::string& output);

  // Sets a noninteractive response to any GetRoutineUpdate IPCs received.
  void SetNonInteractiveUpdate(
      ash::cros_healthd::mojom::DiagnosticRoutineStatusEnum status,
      const std::string& status_message,
      uint32_t progress_percent,
      const std::string& output);

  // Sets the response to any RunSomeRoutine IPCs received.
  void SetRunSomeRoutineResponse(
      uint32_t id,
      ash::cros_healthd::mojom::DiagnosticRoutineStatusEnum status);

 private:
  mojo::Receiver<ash::cros_healthd::mojom::CrosHealthdDiagnosticsService>
      service_receiver_{this /* impl */};

  // Used as the return value for any GetAvailableRoutines IPCs received.
  std::vector<ash::cros_healthd::mojom::DiagnosticRoutineEnum>
      available_routines_;
  // Used as the return value for any GetRoutineUpdate IPCs received.
  ash::cros_healthd::mojom::RoutineUpdate routine_update_response_{
      0, mojo::ScopedHandle(),
      ash::cros_healthd::mojom::RoutineUpdateUnionPtr()};
  // Used as the return value for any RunSomeRoutine IPCs received.
  ash::cros_healthd::mojom::RunRoutineResponse run_routine_response_;

  // Determines whether or not the service should present itself as available.
  bool is_available_ = true;
  // Determines whether or not the service should present itself as responsive.
  bool is_responsive_ = true;
};

}  // namespace wilco
}  // namespace diagnostics

#endif  // DIAGNOSTICS_WILCO_DTC_SUPPORTD_FAKE_DIAGNOSTICS_SERVICE_H_
