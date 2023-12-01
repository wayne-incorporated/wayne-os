// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTH_TOOL_DIAG_DIAG_ACTIONS_H_
#define DIAGNOSTICS_CROS_HEALTH_TOOL_DIAG_DIAG_ACTIONS_H_

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <base/time/default_tick_clock.h>
#include <base/time/tick_clock.h>
#include <mojo/public/cpp/bindings/remote.h>

#include "diagnostics/cros_health_tool/diag/repliers/led_lit_up_routine_replier.h"
#include "diagnostics/mojom/public/cros_healthd.mojom.h"

namespace diagnostics {

// This class is responsible for providing the actions corresponding to the
// command-line arguments for the diag tool. Only capable of running a single
// routine at a time.
class DiagActions final {
 public:
  DiagActions();
  DiagActions(const DiagActions&) = delete;
  DiagActions& operator=(const DiagActions&) = delete;
  ~DiagActions();

  // Print a list of routines available on the platform. Returns true iff all
  // available routines were successfully converted to human-readable strings
  // and printed.
  bool ActionGetRoutines();
  // Run a particular diagnostic routine. See mojo/cros_healthd.mojom for
  // details on the individual routines. Returns true iff the routine completed.
  // Note that this does not mean the routine succeeded, only that it started,
  // ran, and was removed.
  bool ActionRunAcPowerRoutine(
      ash::cros_healthd::mojom::AcPowerStatusEnum expected_status,
      const std::optional<std::string>& expected_power_type);
  bool ActionRunBatteryCapacityRoutine();
  bool ActionRunBatteryChargeRoutine(uint32_t length_seconds,
                                     uint32_t minimum_charge_percent_required);
  bool ActionRunBatteryDischargeRoutine(
      uint32_t length_seconds, uint32_t maximum_discharge_percent_allowed);
  bool ActionRunBatteryHealthRoutine();
  bool ActionRunCaptivePortalRoutine();
  bool ActionRunCpuCacheRoutine(const std::optional<uint32_t>& length_seconds);
  bool ActionRunCpuStressRoutine(const std::optional<uint32_t>& length_seconds);
  bool ActionRunDiskReadRoutine(
      ash::cros_healthd::mojom::DiskReadRoutineTypeEnum type,
      uint32_t length_seconds,
      uint32_t file_size_mb);
  bool ActionRunDnsLatencyRoutine();
  bool ActionRunDnsResolutionRoutine();
  bool ActionRunDnsResolverPresentRoutine();
  bool ActionRunFloatingPointAccuracyRoutine(
      const std::optional<uint32_t>& length_seconds);
  bool ActionRunGatewayCanBePingedRoutine();
  bool ActionRunHasSecureWiFiConnectionRoutine();
  bool ActionRunHttpFirewallRoutine();
  bool ActionRunHttpsFirewallRoutine();
  bool ActionRunHttpsLatencyRoutine();
  bool ActionRunLanConnectivityRoutine();
  bool ActionRunMemoryRoutine(std::optional<uint32_t> max_testing_mem_kib);
  bool ActionRunNvmeSelfTestRoutine(
      ash::cros_healthd::mojom::NvmeSelfTestTypeEnum nvme_self_test_type);
  bool ActionRunNvmeWearLevelRoutine(
      const std::optional<uint32_t>& wear_level_threshold);
  bool ActionRunPrimeSearchRoutine(
      const std::optional<uint32_t>& length_seconds);
  bool ActionRunSignalStrengthRoutine();
  bool ActionRunSmartctlCheckRoutine(
      const std::optional<uint32_t>& percentage_used_threshold);
  bool ActionRunUrandomRoutine(const std::optional<uint32_t>& length_seconds);
  bool ActionRunVideoConferencingRoutine(
      const std::optional<std::string>& stun_server_hostname);
  bool ActionRunArcHttpRoutine();
  bool ActionRunArcPingRoutine();
  bool ActionRunArcDnsResolutionRoutine();
  bool ActionRunSensitiveSensorRoutine();
  bool ActionRunFingerprintRoutine();
  bool ActionRunFingerprintAliveRoutine();
  bool ActionRunPrivacyScreenRoutine(bool target_state);
  bool ActionRunLedRoutine(ash::cros_healthd::mojom::LedName name,
                           ash::cros_healthd::mojom::LedColor color);
  bool ActionRunEmmcLifetimeRoutine();
  bool ActionRunAudioSetVolumeRoutine(uint64_t node_id,
                                      uint8_t volume,
                                      bool mute_on);
  bool ActionRunAudioSetGainRoutine(uint64_t node_id, uint8_t volume);
  bool ActionRunBluetoothPowerRoutine();
  bool ActionRunBluetoothDiscoveryRoutine();
  bool ActionRunBluetoothScanningRoutine(
      const std::optional<uint32_t>& length_seconds);
  bool ActionRunBluetoothPairingRoutine(const std::string& peripheral_id);
  bool ActionRunPowerButtonRoutine(uint32_t timeout_seconds);
  bool ActionRunAudioDriverRoutine();

  // Cancels the next routine run, when that routine reports a progress percent
  // greater than or equal to |percent|. Should be called before running the
  // routine to be cancelled.
  void ForceCancelAtPercent(uint32_t percent);

 private:
  // Helper function that checks the response initially returned when starting
  // the routine and then polls for the routine's result. Returns true if the
  // routine was invoked without error, or false otherwise.
  bool ProcessRoutineResponse(
      const ash::cros_healthd::mojom::RunRoutineResponsePtr& response);
  // Helper function to determine when a routine has finished. Also does any
  // necessary cleanup.
  bool PollRoutineAndProcessResult();
  // Displays the user message from |interactive_result|, then blocks for user
  // input. After receiving input, resets the polling time and continues to
  // poll.
  bool ProcessInteractiveResultAndContinue(
      ash::cros_healthd::mojom::InteractiveRoutineUpdatePtr interactive_result);
  // Displays information from a noninteractive routine update and removes the
  // routine corresponding to |id_|.
  bool ProcessNonInteractiveResultAndEnd(
      ash::cros_healthd::mojom::NonInteractiveRoutineUpdatePtr
          noninteractive_result);
  // Attempts to remove the routine corresponding to |id_|.
  void RemoveRoutine();
  // Helper function to print a routine |status| to stdout. Returns true if
  // |status| is known and false otherwise.
  bool PrintStatus(
      ash::cros_healthd::mojom::DiagnosticRoutineStatusEnum status);
  // Gets an update for the specified routine.
  ash::cros_healthd::mojom::RoutineUpdatePtr GetRoutineUpdate(
      int32_t id,
      ash::cros_healthd::mojom::DiagnosticRoutineCommandEnum command,
      bool include_output);
  // Returns which routines are available on the platform.
  // TODO(b/237508808): Determine whether this function should be changed.
  std::optional<std::vector<ash::cros_healthd::mojom::DiagnosticRoutineEnum>>
  GetAvailableRoutines();

  // Diagnostics Service used to run routines from diag tool.
  mojo::Remote<ash::cros_healthd::mojom::CrosHealthdDiagnosticsService>
      cros_healthd_diagnostics_service_;

  // ID of the routine being run.
  int32_t id_ = ash::cros_healthd::mojom::kFailedToStartId;

  // If |force_cancel_| is true, the next routine run will be cancelled when its
  // progress is greater than or equal to |cancellation_percent_|.
  bool force_cancel_ = false;
  uint32_t cancellation_percent_ = 0;

  // Tracks the passage of time.
  std::unique_ptr<base::DefaultTickClock> default_tick_clock_;
  // Unowned pointer which should outlive this instance. Allows the default tick
  // clock to be overridden for testing.
  const base::TickClock* tick_clock_;

  // Used in the LED lit up routine.
  std::unique_ptr<LedLitUpRoutineReplier> led_lit_up_routine_replier_;
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTH_TOOL_DIAG_DIAG_ACTIONS_H_
