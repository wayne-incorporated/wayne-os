// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_FAKE_CROS_HEALTHD_ROUTINE_FACTORY_H_
#define DIAGNOSTICS_CROS_HEALTHD_FAKE_CROS_HEALTHD_ROUTINE_FACTORY_H_

#include <cstdint>
#include <memory>
#include <optional>
#include <string>

#include "diagnostics/cros_healthd/cros_healthd_routine_factory.h"
#include "diagnostics/cros_healthd/routines/diag_routine.h"
#include "diagnostics/mojom/public/cros_healthd_diagnostics.mojom.h"

namespace diagnostics {

// Implementation of CrosHealthdRoutineFactory that should only be used for
// testing.
class FakeCrosHealthdRoutineFactory final : public CrosHealthdRoutineFactory {
 public:
  FakeCrosHealthdRoutineFactory();
  FakeCrosHealthdRoutineFactory(const FakeCrosHealthdRoutineFactory&) = delete;
  FakeCrosHealthdRoutineFactory& operator=(
      const FakeCrosHealthdRoutineFactory&) = delete;
  ~FakeCrosHealthdRoutineFactory() override;

  // Sets the number of times that Start(), Resume(), and Cancel() are expected
  // to be called on the next routine to be created. If this function isn't
  // called before calling MakeSomeRoutine, then the created routine will not
  // count the expected function calls. Any future calls to this function will
  // override the settings from a previous call. Must be called before
  // SetNonInteractiveStatus.
  void SetRoutineExpectations(int num_expected_start_calls,
                              int num_expected_resume_calls,
                              int num_expected_cancel_calls);

  // Makes the next routine returned by MakeSomeRoutine report a noninteractive
  // status with the specified status, status_message, progress_percent and
  // output. Any future calls to this function will override the settings from a
  // previous call.
  void SetNonInteractiveStatus(
      ash::cros_healthd::mojom::DiagnosticRoutineStatusEnum status,
      const std::string& status_message,
      uint32_t progress_percent,
      const std::string& output);

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
  // The routine that will be returned by any calls to MakeSomeRoutine.
  std::unique_ptr<DiagnosticRoutine> next_routine_;
  // Number of times that any created routines expect their Start() method to be
  // called.
  int num_expected_start_calls_;
  // Number of times that any created routines expect their Resume() method to
  // be called.
  int num_expected_resume_calls_;
  // Number of times that any created routines expect their Cancel() method to
  // be called.
  int num_expected_cancel_calls_;
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_FAKE_CROS_HEALTHD_ROUTINE_FACTORY_H_
