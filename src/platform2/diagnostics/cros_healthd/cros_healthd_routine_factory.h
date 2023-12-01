// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_CROS_HEALTHD_ROUTINE_FACTORY_H_
#define DIAGNOSTICS_CROS_HEALTHD_CROS_HEALTHD_ROUTINE_FACTORY_H_

#include <cstdint>
#include <memory>
#include <optional>
#include <string>

#include <base/time/time.h>

#include "diagnostics/cros_healthd/routines/diag_routine.h"
#include "diagnostics/mojom/public/cros_healthd.mojom.h"

namespace org {
namespace chromium {
class debugdProxyInterface;
}  // namespace chromium
}  // namespace org

namespace diagnostics {

// Interface for constructing DiagnosticRoutines.
class CrosHealthdRoutineFactory {
 public:
  virtual ~CrosHealthdRoutineFactory() = default;

  // Constructs a new instance of the urandom routine. See
  // diagnostics/routines/memory_and_cpu for details on the routine itself.
  virtual std::unique_ptr<DiagnosticRoutine> MakeUrandomRoutine(
      ash::cros_healthd::mojom::NullableUint32Ptr length_seconds) = 0;
  // Constructs a new instance of the battery capacity routine. See
  // diagnostics/routines/battery for details on the routine itself.
  virtual std::unique_ptr<DiagnosticRoutine> MakeBatteryCapacityRoutine() = 0;
  // Constructs a new instance of the battery health routine. See
  // diagnostics/routines/battery_sysfs for details on the routine itself.
  virtual std::unique_ptr<DiagnosticRoutine> MakeBatteryHealthRoutine() = 0;
  // Constructs a new instance of the smartctl check routine. See
  // diagnostics/routines/smartctl_check for details on the routine itself.
  virtual std::unique_ptr<DiagnosticRoutine> MakeSmartctlCheckRoutine(
      org::chromium::debugdProxyInterface* debugd_proxy,
      ash::cros_healthd::mojom::NullableUint32Ptr
          percentage_used_threshold) = 0;
  // Constructs a new instance of the AC power routine. See
  // diagnostics/routines/battery_sysfs for details on the routine itself.
  virtual std::unique_ptr<DiagnosticRoutine> MakeAcPowerRoutine(
      ash::cros_healthd::mojom::AcPowerStatusEnum expected_status,
      const std::optional<std::string>& expected_power_type) = 0;
  // Constructs a new instance of the CPU cache routine. See
  // diagnostics/routines/memory_and_cpu for details on the routine itself.
  virtual std::unique_ptr<DiagnosticRoutine> MakeCpuCacheRoutine(
      const std::optional<base::TimeDelta>& exec_duration) = 0;
  // Constructs a new instance of the CPU stress routine. See
  // diagnostics/routines/memory_and_cpu for details on the routine itself.
  virtual std::unique_ptr<DiagnosticRoutine> MakeCpuStressRoutine(
      const std::optional<base::TimeDelta>& exec_duration) = 0;
  // Constructs a new instance of the floating point accuracy routine. See
  // diagnostics/routines/memory_and_cpu for details on the routine itself.
  virtual std::unique_ptr<DiagnosticRoutine> MakeFloatingPointAccuracyRoutine(
      const std::optional<base::TimeDelta>& exec_duration) = 0;
  // Constructs a new instance of the nvme_wear_level routine. See
  // diagnostics/routines/nvme_wear_level for details on the routine itself.
  virtual std::unique_ptr<DiagnosticRoutine> MakeNvmeWearLevelRoutine(
      org::chromium::debugdProxyInterface* debugd_proxy,
      ash::cros_healthd::mojom::NullableUint32Ptr wear_level_threshold) = 0;
  // Constructs a new instance of the NvmeSelfTest routine. See
  // diagnostics/routines/nvme_self_test for details on the routine itself.
  virtual std::unique_ptr<DiagnosticRoutine> MakeNvmeSelfTestRoutine(
      org::chromium::debugdProxyInterface* debugd_proxy,
      ash::cros_healthd::mojom::NvmeSelfTestTypeEnum nvme_self_test_type) = 0;
  // Constructs a new instance of the prime search routine. See
  // diagnostics/routines/memory_and_cpu for details on the routine itself.
  virtual std::unique_ptr<DiagnosticRoutine> MakePrimeSearchRoutine(
      const std::optional<base::TimeDelta>& exec_duration) = 0;
  // Constructs a new instance of the battery discharge routine. See
  // diagnostics/routines/battery_discharge for details on the routine itself.
  virtual std::unique_ptr<DiagnosticRoutine> MakeBatteryDischargeRoutine(
      base::TimeDelta exec_duration,
      uint32_t maximum_discharge_percent_allowed) = 0;
  // Constructs a new instance of the battery charge routine. See
  // diagnostics/routines/battery_charge for details on the routine itself.
  virtual std::unique_ptr<DiagnosticRoutine> MakeBatteryChargeRoutine(
      base::TimeDelta exec_duration,
      uint32_t minimum_charge_percent_required) = 0;
  // Constructs a new instance of the memory routine. See
  // diagnostics/routines/memory_and_cpu for details on the routine itself.
  virtual std::unique_ptr<DiagnosticRoutine> MakeMemoryRoutine() = 0;
  // Constructs a new instance of the LAN connectivity routine. See
  // diagnostics/routines/lan_connectivity for details on the routine itself.
  virtual std::unique_ptr<DiagnosticRoutine> MakeLanConnectivityRoutine() = 0;
  // Constructs a new instance of the signal strength routine. See
  // diagnostics/routines/signal_strength for details on the routine itself.
  virtual std::unique_ptr<DiagnosticRoutine> MakeSignalStrengthRoutine() = 0;
  // Constructs a new instance of the gateway can be pinged routine. See
  // diagnostics/routines/gateway_can_be_pinged for details on the routine
  // itself.
  virtual std::unique_ptr<DiagnosticRoutine>
  MakeGatewayCanBePingedRoutine() = 0;
  // Constructs a new instance of the has secure wifi connection routine. See
  // diagnostics/routines/has_secure_wifi_connection for details on the routine
  // itself.
  virtual std::unique_ptr<DiagnosticRoutine>
  MakeHasSecureWiFiConnectionRoutine() = 0;
  // Constructs a new instance of the DNS resolver present routine. See
  // diagnostics/routines/dns_resolver_present for details on the routine
  // itself.
  virtual std::unique_ptr<DiagnosticRoutine>
  MakeDnsResolverPresentRoutine() = 0;
  // Constructs a new instance of the DNS latency routine. See
  // diagnostics/routines/dns_latency for details on the routine itself.
  virtual std::unique_ptr<DiagnosticRoutine> MakeDnsLatencyRoutine() = 0;
  // Constructs a new instance of the DNS resolution routine. See
  // diagnostics/routines/dns_resolution for details on the routine itself.
  virtual std::unique_ptr<DiagnosticRoutine> MakeDnsResolutionRoutine() = 0;
  // Constructs a new instance of the captive portal routine. See
  // diagnostics/routines/captive_portal for details on the routine itself.
  virtual std::unique_ptr<DiagnosticRoutine> MakeCaptivePortalRoutine() = 0;
  // Constructs a new instance of the HTTP firewall routine. See
  // diagnostics/routines/http_firewall for details on the routine itself.
  virtual std::unique_ptr<DiagnosticRoutine> MakeHttpFirewallRoutine() = 0;
  // Constructs a new instance of the HTTPS firewall routine. See
  // diagnostics/routines/https_firewall for details on the routine itself.
  virtual std::unique_ptr<DiagnosticRoutine> MakeHttpsFirewallRoutine() = 0;
  // Constructs a new instance of the HTTPS latency routine. See
  // diagnostics/routines/https_latency for details on the routine itself.
  virtual std::unique_ptr<DiagnosticRoutine> MakeHttpsLatencyRoutine() = 0;
  // Constructs a new instance of the video conferencing routine. See
  // diagnostics/routines/video_conferencing for details on the routine itself.
  virtual std::unique_ptr<DiagnosticRoutine> MakeVideoConferencingRoutine(
      const std::optional<std::string>& stun_server_hostname) = 0;
  // Constructs a new instance of the ARC HTTP routine. See
  // diagnostics/routines/arc_http for details on the routine itself.
  virtual std::unique_ptr<DiagnosticRoutine> MakeArcHttpRoutine() = 0;
  // Constructs a new instance of the ARC Ping routine. See
  // diagnostics/routines/arc_ping for details on the routine itself.
  virtual std::unique_ptr<DiagnosticRoutine> MakeArcPingRoutine() = 0;
  // Constructs a new instance of the ARC DNS Resolution routine. See
  // diagnostics/routines/arc_dns_resolution for details on the routine itself.
  virtual std::unique_ptr<DiagnosticRoutine> MakeArcDnsResolutionRoutine() = 0;
  // Constructs a new instance of the sensor routine. See
  // diagnostics/routines/sensor for details on the routine itself.
  virtual std::unique_ptr<DiagnosticRoutine> MakeSensitiveSensorRoutine() = 0;
  // Constructs a new instance of the fingerprint routine. See
  // diagnostics/routines/fingerprint for details on the routine itself.
  virtual std::unique_ptr<DiagnosticRoutine> MakeFingerprintRoutine() = 0;
  // Constructs a new instance of the fingerprint alive routine. See
  // diagnostics/routines/fingerprint_alive for details on the routine itself.
  virtual std::unique_ptr<DiagnosticRoutine> MakeFingerprintAliveRoutine() = 0;
  // Constructs a new instance of the privacy screen routine. See
  // diagnostics/routines/privacy_screen for details on the routine itself.
  virtual std::unique_ptr<DiagnosticRoutine> MakePrivacyScreenRoutine(
      bool target_state) = 0;
  // Constructs a new instance of the LED lit up routine. See
  // diagnostics/routines/led_lit_up for details on the routine itself.
  virtual std::unique_ptr<DiagnosticRoutine> MakeLedLitUpRoutine(
      ash::cros_healthd::mojom::LedName name,
      ash::cros_healthd::mojom::LedColor color,
      mojo::PendingRemote<ash::cros_healthd::mojom::LedLitUpRoutineReplier>
          replier) = 0;
  // Constructs a new instance of the eMMC lifetime routine. See
  // diagnostics/routines/emmc_lifetime for details on the routine itself.
  virtual std::unique_ptr<DiagnosticRoutine> MakeEmmcLifetimeRoutine(
      org::chromium::debugdProxyInterface* debugd_proxy) = 0;
  // Constructs a new instance of the audio set volume routine. See
  // diagnostics/routines/audio/audio_set_volume.cc for details on the routine
  // itself.
  virtual std::unique_ptr<DiagnosticRoutine> MakeAudioSetVolumeRoutine(
      uint64_t node_id, uint8_t volume, bool mute_on) = 0;
  // Constructs a new instance of the audio set gain routine. See
  // diagnostics/routines/audio/audio_set_gain.cc for details on the routine
  // itself.
  virtual std::unique_ptr<DiagnosticRoutine> MakeAudioSetGainRoutine(
      uint64_t node_id, uint8_t gain) = 0;
  // Constructs a new instance of the Bluetooth power routine. See
  // diagnostics/routines/bluetooth/bluetooth_power for details on the routine
  // itself.
  virtual std::unique_ptr<DiagnosticRoutine> MakeBluetoothPowerRoutine() = 0;
  // Constructs a new instance of the Bluetooth discovery routine. See
  // diagnostics/routines/bluetooth/bluetooth_discovery for details on the
  // routine itself.
  virtual std::unique_ptr<DiagnosticRoutine>
  MakeBluetoothDiscoveryRoutine() = 0;
  // Constructs a new instance of the Bluetooth scanning routine. See
  // diagnostics/routines/bluetooth/bluetooth_scanning for details on the
  // routine itself.
  virtual std::unique_ptr<DiagnosticRoutine> MakeBluetoothScanningRoutine(
      const std::optional<base::TimeDelta>& exec_duration) = 0;
  // Constructs a new instance of the Bluetooth pairing routine. See
  // diagnostics/routines/bluetooth/bluetooth_pairing for details on the
  // routine itself.
  virtual std::unique_ptr<DiagnosticRoutine> MakeBluetoothPairingRoutine(
      const std::string& peripheral_id) = 0;
  // Constructs a new instance of the power button routine. See
  // diagnostics/routines/power_button/power_button for details on the routine
  // itself.
  virtual std::unique_ptr<DiagnosticRoutine> MakePowerButtonRoutine(
      uint32_t timeout_seconds) = 0;
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_CROS_HEALTHD_ROUTINE_FACTORY_H_
