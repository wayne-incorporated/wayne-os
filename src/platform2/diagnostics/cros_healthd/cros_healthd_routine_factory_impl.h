// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_CROS_HEALTHD_ROUTINE_FACTORY_IMPL_H_
#define DIAGNOSTICS_CROS_HEALTHD_CROS_HEALTHD_ROUTINE_FACTORY_IMPL_H_

#include <cstdint>
#include <memory>
#include <optional>
#include <string>

#include "diagnostics/cros_healthd/cros_healthd_routine_factory.h"
#include "diagnostics/cros_healthd/routine_parameter_fetcher.h"
#include "diagnostics/cros_healthd/system/context.h"

namespace diagnostics {

// Production implementation of the CrosHealthdRoutineFactory interface.
class CrosHealthdRoutineFactoryImpl final : public CrosHealthdRoutineFactory {
 public:
  explicit CrosHealthdRoutineFactoryImpl(Context* context);
  CrosHealthdRoutineFactoryImpl(const CrosHealthdRoutineFactoryImpl&) = delete;
  CrosHealthdRoutineFactoryImpl& operator=(
      const CrosHealthdRoutineFactoryImpl&) = delete;
  ~CrosHealthdRoutineFactoryImpl() override;

  // CrosHealthdRoutineFactory overrides:
  std::unique_ptr<DiagnosticRoutine> MakeUrandomRoutine(
      ash::cros_healthd::mojom::NullableUint32Ptr length_seconds) override;
  std::unique_ptr<DiagnosticRoutine> MakeBatteryCapacityRoutine() override;
  std::unique_ptr<DiagnosticRoutine> MakeBatteryHealthRoutine() override;
  std::unique_ptr<DiagnosticRoutine> MakeSmartctlCheckRoutine(
      org::chromium::debugdProxyInterface* debugd_proxy,
      ash::cros_healthd::mojom::NullableUint32Ptr percentage_used_threshold)
      override;
  std::unique_ptr<DiagnosticRoutine> MakeAcPowerRoutine(
      ash::cros_healthd::mojom::AcPowerStatusEnum expected_status,
      const std::optional<std::string>& expected_power_type) override;
  std::unique_ptr<DiagnosticRoutine> MakeCpuCacheRoutine(
      const std::optional<base::TimeDelta>& exec_duration) override;
  std::unique_ptr<DiagnosticRoutine> MakeCpuStressRoutine(
      const std::optional<base::TimeDelta>& exec_duration) override;
  std::unique_ptr<DiagnosticRoutine> MakeFloatingPointAccuracyRoutine(
      const std::optional<base::TimeDelta>& exec_duration) override;
  std::unique_ptr<DiagnosticRoutine> MakeNvmeWearLevelRoutine(
      org::chromium::debugdProxyInterface* debugd_proxy,
      ash::cros_healthd::mojom::NullableUint32Ptr wear_level_threshold)
      override;
  std::unique_ptr<DiagnosticRoutine> MakeNvmeSelfTestRoutine(
      org::chromium::debugdProxyInterface* debugd_proxy,
      ash::cros_healthd::mojom::NvmeSelfTestTypeEnum nvme_self_test_type)
      override;
  std::unique_ptr<DiagnosticRoutine> MakePrimeSearchRoutine(
      const std::optional<base::TimeDelta>& exec_duration) override;
  std::unique_ptr<DiagnosticRoutine> MakeBatteryDischargeRoutine(
      base::TimeDelta exec_duration,
      uint32_t maximum_discharge_percent_allowed) override;
  std::unique_ptr<DiagnosticRoutine> MakeBatteryChargeRoutine(
      base::TimeDelta exec_duration,
      uint32_t minimum_charge_percent_required) override;
  std::unique_ptr<DiagnosticRoutine> MakeMemoryRoutine() override;
  std::unique_ptr<DiagnosticRoutine> MakeLanConnectivityRoutine() override;
  std::unique_ptr<DiagnosticRoutine> MakeSignalStrengthRoutine() override;
  std::unique_ptr<DiagnosticRoutine> MakeGatewayCanBePingedRoutine() override;
  std::unique_ptr<DiagnosticRoutine> MakeHasSecureWiFiConnectionRoutine()
      override;
  std::unique_ptr<DiagnosticRoutine> MakeDnsResolverPresentRoutine() override;
  std::unique_ptr<DiagnosticRoutine> MakeDnsLatencyRoutine() override;
  std::unique_ptr<DiagnosticRoutine> MakeDnsResolutionRoutine() override;
  std::unique_ptr<DiagnosticRoutine> MakeCaptivePortalRoutine() override;
  std::unique_ptr<DiagnosticRoutine> MakeHttpFirewallRoutine() override;
  std::unique_ptr<DiagnosticRoutine> MakeHttpsFirewallRoutine() override;
  std::unique_ptr<DiagnosticRoutine> MakeHttpsLatencyRoutine() override;
  std::unique_ptr<DiagnosticRoutine> MakeVideoConferencingRoutine(
      const std::optional<std::string>& stun_server_hostname) override;
  std::unique_ptr<DiagnosticRoutine> MakeArcHttpRoutine() override;
  std::unique_ptr<DiagnosticRoutine> MakeArcPingRoutine() override;
  std::unique_ptr<DiagnosticRoutine> MakeArcDnsResolutionRoutine() override;
  std::unique_ptr<DiagnosticRoutine> MakeSensitiveSensorRoutine() override;
  std::unique_ptr<DiagnosticRoutine> MakeFingerprintRoutine() override;
  std::unique_ptr<DiagnosticRoutine> MakeFingerprintAliveRoutine() override;
  std::unique_ptr<DiagnosticRoutine> MakePrivacyScreenRoutine(
      bool target_state) override;
  std::unique_ptr<DiagnosticRoutine> MakeLedLitUpRoutine(
      ash::cros_healthd::mojom::LedName name,
      ash::cros_healthd::mojom::LedColor color,
      mojo::PendingRemote<ash::cros_healthd::mojom::LedLitUpRoutineReplier>
          replier) override;
  std::unique_ptr<DiagnosticRoutine> MakeEmmcLifetimeRoutine(
      org::chromium::debugdProxyInterface* debugd_proxy) override;
  std::unique_ptr<DiagnosticRoutine> MakeAudioSetVolumeRoutine(
      uint64_t node_id, uint8_t volume, bool mute_on) override;
  std::unique_ptr<DiagnosticRoutine> MakeAudioSetGainRoutine(
      uint64_t node_id, uint8_t gain) override;
  std::unique_ptr<DiagnosticRoutine> MakeBluetoothPowerRoutine() override;
  std::unique_ptr<DiagnosticRoutine> MakeBluetoothDiscoveryRoutine() override;
  std::unique_ptr<DiagnosticRoutine> MakeBluetoothScanningRoutine(
      const std::optional<base::TimeDelta>& exec_duration) override;
  std::unique_ptr<DiagnosticRoutine> MakeBluetoothPairingRoutine(
      const std::string& peripheral_id) override;
  std::unique_ptr<DiagnosticRoutine> MakePowerButtonRoutine(
      uint32_t timeout_seconds) override;

 private:
  // Unowned pointer that should outlive this instance.
  Context* const context_ = nullptr;

  // Used to fetch default parameters for routines.
  std::unique_ptr<RoutineParameterFetcher> parameter_fetcher_;
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_CROS_HEALTHD_ROUTINE_FACTORY_IMPL_H_
