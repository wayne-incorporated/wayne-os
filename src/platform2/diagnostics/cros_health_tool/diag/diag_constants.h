// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTH_TOOL_DIAG_DIAG_CONSTANTS_H_
#define DIAGNOSTICS_CROS_HEALTH_TOOL_DIAG_DIAG_CONSTANTS_H_

#include "diagnostics/mojom/public/cros_healthd_diagnostics.mojom.h"

namespace diagnostics {

// Used for printing and parsing routine names.
constexpr struct {
  const char* switch_name;
  ash::cros_healthd::mojom::DiagnosticRoutineEnum routine;
} kDiagnosticRoutineSwitches[] = {
    {"battery_capacity",
     ash::cros_healthd::mojom::DiagnosticRoutineEnum::kBatteryCapacity},
    {"battery_health",
     ash::cros_healthd::mojom::DiagnosticRoutineEnum::kBatteryHealth},
    {"urandom", ash::cros_healthd::mojom::DiagnosticRoutineEnum::kUrandom},
    {"smartctl_check",
     ash::cros_healthd::mojom::DiagnosticRoutineEnum::kSmartctlCheck},
    {"smartctl_check_with_percentage_used",
     ash::cros_healthd::mojom::DiagnosticRoutineEnum::
         kSmartctlCheckWithPercentageUsed},
    {"ac_power", ash::cros_healthd::mojom::DiagnosticRoutineEnum::kAcPower},
    {"cpu_cache", ash::cros_healthd::mojom::DiagnosticRoutineEnum::kCpuCache},
    {"cpu_stress", ash::cros_healthd::mojom::DiagnosticRoutineEnum::kCpuStress},
    {"floating_point_accuracy",
     ash::cros_healthd::mojom::DiagnosticRoutineEnum::kFloatingPointAccuracy},
    {"nvme_wear_level",
     ash::cros_healthd::mojom::DiagnosticRoutineEnum::kNvmeWearLevel},
    {"nvme_self_test",
     ash::cros_healthd::mojom::DiagnosticRoutineEnum::kNvmeSelfTest},
    {"disk_read", ash::cros_healthd::mojom::DiagnosticRoutineEnum::kDiskRead},
    {"prime_search",
     ash::cros_healthd::mojom::DiagnosticRoutineEnum::kPrimeSearch},
    {"battery_discharge",
     ash::cros_healthd::mojom::DiagnosticRoutineEnum::kBatteryDischarge},
    {"battery_charge",
     ash::cros_healthd::mojom::DiagnosticRoutineEnum::kBatteryCharge},
    {"memory", ash::cros_healthd::mojom::DiagnosticRoutineEnum::kMemory},
    {"lan_connectivity",
     ash::cros_healthd::mojom::DiagnosticRoutineEnum::kLanConnectivity},
    {"signal_strength",
     ash::cros_healthd::mojom::DiagnosticRoutineEnum::kSignalStrength},
    {"gateway_can_be_pinged",
     ash::cros_healthd::mojom::DiagnosticRoutineEnum::kGatewayCanBePinged},
    {"has_secure_wifi_connection",
     ash::cros_healthd::mojom::DiagnosticRoutineEnum::kHasSecureWiFiConnection},
    {"dns_resolver_present",
     ash::cros_healthd::mojom::DiagnosticRoutineEnum::kDnsResolverPresent},
    {"dns_latency",
     ash::cros_healthd::mojom::DiagnosticRoutineEnum::kDnsLatency},
    {"dns_resolution",
     ash::cros_healthd::mojom::DiagnosticRoutineEnum::kDnsResolution},
    {"captive_portal",
     ash::cros_healthd::mojom::DiagnosticRoutineEnum::kCaptivePortal},
    {"http_firewall",
     ash::cros_healthd::mojom::DiagnosticRoutineEnum::kHttpFirewall},
    {"https_firewall",
     ash::cros_healthd::mojom::DiagnosticRoutineEnum::kHttpsFirewall},
    {"https_latency",
     ash::cros_healthd::mojom::DiagnosticRoutineEnum::kHttpsLatency},
    {"video_conferencing",
     ash::cros_healthd::mojom::DiagnosticRoutineEnum::kVideoConferencing},
    {"arc_http", ash::cros_healthd::mojom::DiagnosticRoutineEnum::kArcHttp},
    {"arc_ping", ash::cros_healthd::mojom::DiagnosticRoutineEnum::kArcPing},
    {"arc_dns_resolution",
     ash::cros_healthd::mojom::DiagnosticRoutineEnum::kArcDnsResolution},
    {"sensitive_sensor",
     ash::cros_healthd::mojom::DiagnosticRoutineEnum::kSensitiveSensor},
    {"fingerprint",
     ash::cros_healthd::mojom::DiagnosticRoutineEnum::kFingerprint},
    {"fingerprint_alive",
     ash::cros_healthd::mojom::DiagnosticRoutineEnum::kFingerprintAlive},
    {"privacy_screen",
     ash::cros_healthd::mojom::DiagnosticRoutineEnum::kPrivacyScreen},
    {"led_lit_up", ash::cros_healthd::mojom::DiagnosticRoutineEnum::kLedLitUp},
    {"emmc_lifetime",
     ash::cros_healthd::mojom::DiagnosticRoutineEnum::kEmmcLifetime},
    {"audio_set_volume",
     ash::cros_healthd::mojom::DiagnosticRoutineEnum::kAudioSetVolume},
    {"audio_set_gain",
     ash::cros_healthd::mojom::DiagnosticRoutineEnum::kAudioSetGain},
    {"bluetooth_power",
     ash::cros_healthd::mojom::DiagnosticRoutineEnum::kBluetoothPower},
    {"bluetooth_discovery",
     ash::cros_healthd::mojom::DiagnosticRoutineEnum::kBluetoothDiscovery},
    {"bluetooth_scanning",
     ash::cros_healthd::mojom::DiagnosticRoutineEnum::kBluetoothScanning},
    {"bluetooth_pairing",
     ash::cros_healthd::mojom::DiagnosticRoutineEnum::kBluetoothPairing},
    {"power_button",
     ash::cros_healthd::mojom::DiagnosticRoutineEnum::kPowerButton},
    {"audio_driver",
     ash::cros_healthd::mojom::DiagnosticRoutineEnum::kAudioDriver},
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTH_TOOL_DIAG_DIAG_CONSTANTS_H_
