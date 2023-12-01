// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/utils/metrics_utils.h"

#include <optional>
#include <set>
#include <string>

#include <base/logging.h>
#include <mojo/public/cpp/bindings/struct_ptr.h>

#include "diagnostics/cros_healthd/utils/metrics_utils_constants.h"

namespace diagnostics {

namespace {

namespace mojom = ::ash::cros_healthd::mojom;

std::optional<std::string> GetMetricName(mojom::ProbeCategoryEnum category) {
  switch (category) {
    case mojom::ProbeCategoryEnum::kUnknown:
      // No metric name for the unknown category.
      return std::nullopt;
    case mojom::ProbeCategoryEnum::kBattery:
      return metrics_name::kTelemetryResultBattery;
    case mojom::ProbeCategoryEnum::kCpu:
      return metrics_name::kTelemetryResultCpu;
    case mojom::ProbeCategoryEnum::kNonRemovableBlockDevices:
      return metrics_name::kTelemetryResultBlockDevice;
    case mojom::ProbeCategoryEnum::kTimezone:
      return metrics_name::kTelemetryResultTimezone;
    case mojom::ProbeCategoryEnum::kMemory:
      return metrics_name::kTelemetryResultMemory;
    case mojom::ProbeCategoryEnum::kBacklight:
      return metrics_name::kTelemetryResultBacklight;
    case mojom::ProbeCategoryEnum::kFan:
      return metrics_name::kTelemetryResultFan;
    case mojom::ProbeCategoryEnum::kStatefulPartition:
      return metrics_name::kTelemetryResultStatefulPartition;
    case mojom::ProbeCategoryEnum::kBluetooth:
      return metrics_name::kTelemetryResultBluetooth;
    case mojom::ProbeCategoryEnum::kSystem:
      return metrics_name::kTelemetryResultSystem;
    case mojom::ProbeCategoryEnum::kNetwork:
      return metrics_name::kTelemetryResultNetwork;
    case mojom::ProbeCategoryEnum::kAudio:
      return metrics_name::kTelemetryResultAudio;
    case mojom::ProbeCategoryEnum::kBootPerformance:
      return metrics_name::kTelemetryResultBootPerformance;
    case mojom::ProbeCategoryEnum::kBus:
      return metrics_name::kTelemetryResultBus;
    case mojom::ProbeCategoryEnum::kTpm:
      return metrics_name::kTelemetryResultTpm;
    case mojom::ProbeCategoryEnum::kNetworkInterface:
      return metrics_name::kTelemetryResultNetworkInterface;
    case mojom::ProbeCategoryEnum::kGraphics:
      return metrics_name::kTelemetryResultGraphics;
    case mojom::ProbeCategoryEnum::kDisplay:
      return metrics_name::kTelemetryResultDisplay;
    case mojom::ProbeCategoryEnum::kInput:
      return metrics_name::kTelemetryResultInput;
    case mojom::ProbeCategoryEnum::kAudioHardware:
      return metrics_name::kTelemetryResultAudioHardware;
    case mojom::ProbeCategoryEnum::kSensor:
      return metrics_name::kTelemetryResultSensor;
  }
}

std::optional<std::string> GetMetricName(mojom::DiagnosticRoutineEnum routine) {
  switch (routine) {
    case mojom::DiagnosticRoutineEnum::kUnknown:
      // No metric name for the unknown routine.
      return std::nullopt;
    case mojom::DiagnosticRoutineEnum::kBatteryCapacity:
      return metrics_name::kDiagnosticResultBatteryCapacity;
    case mojom::DiagnosticRoutineEnum::kBatteryHealth:
      return metrics_name::kDiagnosticResultBatteryHealth;
    case mojom::DiagnosticRoutineEnum::kUrandom:
      return metrics_name::kDiagnosticResultUrandom;
    case mojom::DiagnosticRoutineEnum::kSmartctlCheck:
      return metrics_name::kDiagnosticResultSmartctlCheck;
    case mojom::DiagnosticRoutineEnum::kAcPower:
      return metrics_name::kDiagnosticResultAcPower;
    case mojom::DiagnosticRoutineEnum::kCpuCache:
      return metrics_name::kDiagnosticResultCpuCache;
    case mojom::DiagnosticRoutineEnum::kCpuStress:
      return metrics_name::kDiagnosticResultCpuStress;
    case mojom::DiagnosticRoutineEnum::kFloatingPointAccuracy:
      return metrics_name::kDiagnosticResultFloatingPointAccuracy;
    case mojom::DiagnosticRoutineEnum::kNvmeWearLevel:
      return metrics_name::kDiagnosticResultNvmeWearLevel;
    case mojom::DiagnosticRoutineEnum::kNvmeSelfTest:
      return metrics_name::kDiagnosticResultNvmeSelfTest;
    case mojom::DiagnosticRoutineEnum::kDiskRead:
      return metrics_name::kDiagnosticResultDiskRead;
    case mojom::DiagnosticRoutineEnum::kPrimeSearch:
      return metrics_name::kDiagnosticResultPrimeSearch;
    case mojom::DiagnosticRoutineEnum::kBatteryDischarge:
      return metrics_name::kDiagnosticResultBatteryDischarge;
    case mojom::DiagnosticRoutineEnum::kBatteryCharge:
      return metrics_name::kDiagnosticResultBatteryCharge;
    case mojom::DiagnosticRoutineEnum::kMemory:
      return metrics_name::kDiagnosticResultMemory;
    case mojom::DiagnosticRoutineEnum::kLanConnectivity:
      return metrics_name::kDiagnosticResultLanConnectivity;
    case mojom::DiagnosticRoutineEnum::kSignalStrength:
      return metrics_name::kDiagnosticResultSignalStrength;
    case mojom::DiagnosticRoutineEnum::kGatewayCanBePinged:
      return metrics_name::kDiagnosticResultGatewayCanBePinged;
    case mojom::DiagnosticRoutineEnum::kHasSecureWiFiConnection:
      return metrics_name::kDiagnosticResultHasSecureWiFiConnection;
    case mojom::DiagnosticRoutineEnum::kDnsResolverPresent:
      return metrics_name::kDiagnosticResultDnsResolverPresent;
    case mojom::DiagnosticRoutineEnum::kDnsLatency:
      return metrics_name::kDiagnosticResultDnsLatency;
    case mojom::DiagnosticRoutineEnum::kDnsResolution:
      return metrics_name::kDiagnosticResultDnsResolution;
    case mojom::DiagnosticRoutineEnum::kCaptivePortal:
      return metrics_name::kDiagnosticResultCaptivePortal;
    case mojom::DiagnosticRoutineEnum::kHttpFirewall:
      return metrics_name::kDiagnosticResultHttpFirewall;
    case mojom::DiagnosticRoutineEnum::kHttpsFirewall:
      return metrics_name::kDiagnosticResultHttpsFirewall;
    case mojom::DiagnosticRoutineEnum::kHttpsLatency:
      return metrics_name::kDiagnosticResultHttpsLatency;
    case mojom::DiagnosticRoutineEnum::kVideoConferencing:
      return metrics_name::kDiagnosticResultVideoConferencing;
    case mojom::DiagnosticRoutineEnum::kArcHttp:
      return metrics_name::kDiagnosticResultArcHttp;
    case mojom::DiagnosticRoutineEnum::kArcPing:
      return metrics_name::kDiagnosticResultArcPing;
    case mojom::DiagnosticRoutineEnum::kArcDnsResolution:
      return metrics_name::kDiagnosticResultArcDnsResolution;
    case mojom::DiagnosticRoutineEnum::kSensitiveSensor:
      return metrics_name::kDiagnosticResultSensitiveSensor;
    case mojom::DiagnosticRoutineEnum::kFingerprint:
      return metrics_name::kDiagnosticResultFingerprint;
    case mojom::DiagnosticRoutineEnum::kFingerprintAlive:
      return metrics_name::kDiagnosticResultFingerprintAlive;
    case mojom::DiagnosticRoutineEnum::kPrivacyScreen:
      return metrics_name::kDiagnosticResultPrivacyScreen;
    case mojom::DiagnosticRoutineEnum::kLedLitUp:
      return metrics_name::kDiagnosticResultLedLitUp;
    case mojom::DiagnosticRoutineEnum::kSmartctlCheckWithPercentageUsed:
      return metrics_name::kDiagnosticResultSmartctlCheckWithPercentageUsed;
    case mojom::DiagnosticRoutineEnum::kEmmcLifetime:
      return metrics_name::kDiagnosticResultEmmcLifetime;
    case mojom::DiagnosticRoutineEnum::kAudioSetVolume:
      return metrics_name::kDiagnosticResultAudioSetVolume;
    case mojom::DiagnosticRoutineEnum::kAudioSetGain:
      return metrics_name::kDiagnosticResultAudioSetGain;
    case mojom::DiagnosticRoutineEnum::kBluetoothPower:
      return metrics_name::kDiagnosticResultBluetoothPower;
    case mojom::DiagnosticRoutineEnum::kBluetoothDiscovery:
      return metrics_name::kDiagnosticResultBluetoothDiscovery;
    case mojom::DiagnosticRoutineEnum::kBluetoothScanning:
      return metrics_name::kDiagnosticResultBluetoothScanning;
    case mojom::DiagnosticRoutineEnum::kBluetoothPairing:
      return metrics_name::kDiagnosticResultBluetoothPairing;
    case mojom::DiagnosticRoutineEnum::kPowerButton:
      return metrics_name::kDiagnosticResultPowerButton;
    case mojom::DiagnosticRoutineEnum::kAudioDriver:
      return metrics_name::kDiagnosticResultAudioDriver;
  }
}

std::optional<CrosHealthdDiagnosticResult> ConvertDiagnosticStatusToUMAEnum(
    mojom::DiagnosticRoutineStatusEnum status) {
  switch (status) {
    case mojom::DiagnosticRoutineStatusEnum::kPassed:
      return CrosHealthdDiagnosticResult::kPassed;
    case mojom::DiagnosticRoutineStatusEnum::kFailed:
      return CrosHealthdDiagnosticResult::kFailed;
    case mojom::DiagnosticRoutineStatusEnum::kError:
      return CrosHealthdDiagnosticResult::kError;
    case mojom::DiagnosticRoutineStatusEnum::kCancelled:
      return CrosHealthdDiagnosticResult::kCancelled;
    case mojom::DiagnosticRoutineStatusEnum::kFailedToStart:
      return CrosHealthdDiagnosticResult::kFailedToStart;
    case mojom::DiagnosticRoutineStatusEnum::kRemoved:
      return CrosHealthdDiagnosticResult::kRemoved;
    case mojom::DiagnosticRoutineStatusEnum::kUnsupported:
      return CrosHealthdDiagnosticResult::kUnsupported;
    case mojom::DiagnosticRoutineStatusEnum::kNotRun:
      return CrosHealthdDiagnosticResult::kNotRun;
    // Non-terminal status.
    case mojom::DiagnosticRoutineStatusEnum::kUnknown:
    case mojom::DiagnosticRoutineStatusEnum::kReady:
    case mojom::DiagnosticRoutineStatusEnum::kRunning:
    case mojom::DiagnosticRoutineStatusEnum::kWaiting:
    case mojom::DiagnosticRoutineStatusEnum::kCancelling:
      return std::nullopt;
  }
}

template <typename S>
void SendOneTelemetryResultToUMA(MetricsLibraryInterface* metrics,
                                 mojom::ProbeCategoryEnum category,
                                 const mojo::StructPtr<S>& struct_ptr) {
  std::optional<std::string> metrics_name = GetMetricName(category);
  if (!metrics_name.has_value()) {
    return;
  }

  CrosHealthdTelemetryResult enum_sample;
  if (struct_ptr.is_null() || struct_ptr->is_error()) {
    enum_sample = CrosHealthdTelemetryResult::kError;
  } else {
    enum_sample = CrosHealthdTelemetryResult::kSuccess;
  }

  bool result = metrics->SendEnumToUMA(metrics_name.value(), enum_sample);
  if (!result) {
    LOG(ERROR) << "Failed to send telemetry result of " << category
               << " to UMA.";
  }
}

}  // namespace

void SendTelemetryResultToUMA(
    MetricsLibraryInterface* metrics,
    const std::set<mojom::ProbeCategoryEnum>& requested_categories,
    const mojom::TelemetryInfoPtr& info) {
  if (info.is_null()) {
    LOG(WARNING) << "Cannot send a null telemetry result to UMA.";
    return;
  }

  for (const auto category : requested_categories) {
    switch (category) {
      case mojom::ProbeCategoryEnum::kUnknown: {
        // No result to send for an unknown category. Skip it.
        break;
      }
      case mojom::ProbeCategoryEnum::kBattery: {
        SendOneTelemetryResultToUMA(metrics, category, info->battery_result);
        break;
      }
      case mojom::ProbeCategoryEnum::kCpu: {
        SendOneTelemetryResultToUMA(metrics, category, info->cpu_result);
        break;
      }
      case mojom::ProbeCategoryEnum::kNonRemovableBlockDevices: {
        SendOneTelemetryResultToUMA(metrics, category,
                                    info->block_device_result);
        break;
      }
      case mojom::ProbeCategoryEnum::kTimezone: {
        SendOneTelemetryResultToUMA(metrics, category, info->timezone_result);
        break;
      }
      case mojom::ProbeCategoryEnum::kMemory: {
        SendOneTelemetryResultToUMA(metrics, category, info->memory_result);
        break;
      }
      case mojom::ProbeCategoryEnum::kBacklight: {
        SendOneTelemetryResultToUMA(metrics, category, info->backlight_result);
        break;
      }
      case mojom::ProbeCategoryEnum::kFan: {
        SendOneTelemetryResultToUMA(metrics, category, info->fan_result);
        break;
      }
      case mojom::ProbeCategoryEnum::kStatefulPartition: {
        SendOneTelemetryResultToUMA(metrics, category,
                                    info->stateful_partition_result);
        break;
      }
      case mojom::ProbeCategoryEnum::kBluetooth: {
        SendOneTelemetryResultToUMA(metrics, category, info->bluetooth_result);
        break;
      }
      case mojom::ProbeCategoryEnum::kSystem: {
        SendOneTelemetryResultToUMA(metrics, category, info->system_result);
        break;
      }
      case mojom::ProbeCategoryEnum::kNetwork: {
        SendOneTelemetryResultToUMA(metrics, category, info->network_result);
        break;
      }
      case mojom::ProbeCategoryEnum::kAudio: {
        SendOneTelemetryResultToUMA(metrics, category, info->audio_result);
        break;
      }
      case mojom::ProbeCategoryEnum::kBootPerformance: {
        SendOneTelemetryResultToUMA(metrics, category,
                                    info->boot_performance_result);
        break;
      }
      case mojom::ProbeCategoryEnum::kBus: {
        SendOneTelemetryResultToUMA(metrics, category, info->bus_result);
        break;
      }
      case mojom::ProbeCategoryEnum::kTpm: {
        SendOneTelemetryResultToUMA(metrics, category, info->tpm_result);
        break;
      }
      case mojom::ProbeCategoryEnum::kNetworkInterface: {
        SendOneTelemetryResultToUMA(metrics, category,
                                    info->network_interface_result);
        break;
      }
      case mojom::ProbeCategoryEnum::kGraphics: {
        SendOneTelemetryResultToUMA(metrics, category, info->graphics_result);
        break;
      }
      case mojom::ProbeCategoryEnum::kDisplay: {
        SendOneTelemetryResultToUMA(metrics, category, info->display_result);
        break;
      }
      case mojom::ProbeCategoryEnum::kInput: {
        SendOneTelemetryResultToUMA(metrics, category, info->input_result);
        break;
      }
      case mojom::ProbeCategoryEnum::kAudioHardware: {
        SendOneTelemetryResultToUMA(metrics, category,
                                    info->audio_hardware_result);
        break;
      }
      case mojom::ProbeCategoryEnum::kSensor: {
        SendOneTelemetryResultToUMA(metrics, category, info->sensor_result);
        break;
      }
    }
  }
}

void SendDiagnosticResultToUMA(MetricsLibraryInterface* metrics,
                               mojom::DiagnosticRoutineEnum routine,
                               mojom::DiagnosticRoutineStatusEnum status) {
  std::optional<std::string> metrics_name = GetMetricName(routine);
  if (!metrics_name.has_value()) {
    return;
  }

  std::optional<CrosHealthdDiagnosticResult> result_enum =
      ConvertDiagnosticStatusToUMAEnum(status);
  if (!result_enum.has_value()) {
    LOG(ERROR) << "Unable to send non-terminal status " << status << " of "
               << routine << " to UMA.";
    return;
  }

  bool result =
      metrics->SendEnumToUMA(metrics_name.value(), result_enum.value());
  if (!result) {
    LOG(ERROR) << "Failed to send diagnostic result of " << routine << " ("
               << status << ") to UMA.";
  }
}

}  // namespace diagnostics
