// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_health_tool/diag/diag_actions.h"

#include <cstdint>
#include <iostream>
#include <iterator>
#include <map>
#include <optional>
#include <string>
#include <utility>

#include <base/check.h>
#include <base/check_op.h>
#include <base/json/json_reader.h>
#include <base/json/json_writer.h>
#include <base/logging.h>
#include <base/no_destructor.h>
#include <base/run_loop.h>
#include <base/task/single_thread_task_runner.h>
#include <base/time/time.h>
#include <mojo/service_constants.h>

#include "diagnostics/base/mojo_utils.h"
#include "diagnostics/cros_health_tool/diag/diag_constants.h"
#include "diagnostics/cros_health_tool/mojo_util.h"
#include "diagnostics/mojom/public/cros_healthd_diagnostics.mojom.h"
#include "diagnostics/mojom/public/nullable_primitives.mojom.h"

namespace diagnostics {

namespace {

namespace mojom = ash::cros_healthd::mojom;

// Poll interval while waiting for a routine to finish.
constexpr base::TimeDelta kRoutinePollInterval = base::Milliseconds(100);
// Maximum time we're willing to wait for a routine to finish.
constexpr base::TimeDelta kMaximumRoutineExecution = base::Hours(1);

const struct {
  const char* readable_status;
  mojom::DiagnosticRoutineStatusEnum status;
} kDiagnosticRoutineReadableStatuses[] = {
    {"Ready", mojom::DiagnosticRoutineStatusEnum::kReady},
    {"Running", mojom::DiagnosticRoutineStatusEnum::kRunning},
    {"Waiting", mojom::DiagnosticRoutineStatusEnum::kWaiting},
    {"Passed", mojom::DiagnosticRoutineStatusEnum::kPassed},
    {"Failed", mojom::DiagnosticRoutineStatusEnum::kFailed},
    {"Error", mojom::DiagnosticRoutineStatusEnum::kError},
    {"Cancelled", mojom::DiagnosticRoutineStatusEnum::kCancelled},
    {"Failed to start", mojom::DiagnosticRoutineStatusEnum::kFailedToStart},
    {"Removed", mojom::DiagnosticRoutineStatusEnum::kRemoved},
    {"Cancelling", mojom::DiagnosticRoutineStatusEnum::kCancelling},
    {"Unsupported", mojom::DiagnosticRoutineStatusEnum::kUnsupported},
    {"Not run", mojom::DiagnosticRoutineStatusEnum::kNotRun}};

std::string GetSwitchFromRoutine(mojom::DiagnosticRoutineEnum routine) {
  static base::NoDestructor<std::map<mojom::DiagnosticRoutineEnum, std::string>>
      diagnostic_routine_to_switch;

  if (diagnostic_routine_to_switch->empty()) {
    for (const auto& item : kDiagnosticRoutineSwitches) {
      diagnostic_routine_to_switch->insert(
          std::make_pair(item.routine, item.switch_name));
    }
  }

  auto routine_itr = diagnostic_routine_to_switch->find(routine);
  LOG_IF(FATAL, routine_itr == diagnostic_routine_to_switch->end())
      << "Invalid routine to switch lookup with routine: " << routine;

  return routine_itr->second;
}

void WaitUntilEnterPressed() {
  std::cout << "Press ENTER to continue." << std::endl;
  std::string dummy;
  std::getline(std::cin, dummy);
}

void HandleGetLedColorMatchedInvocation(
    mojom::LedLitUpRoutineReplier::GetColorMatchedCallback callback) {
  // Print a newline so we don't overwrite the progress percent.
  std::cout << '\n';

  std::optional<bool> answer;
  do {
    std::cout << "Is the LED lit up in the specified color? "
                 "Input y/n then press ENTER to continue."
              << std::endl;
    std::string input;
    std::getline(std::cin, input);

    if (!input.empty() && input[0] == 'y') {
      answer = true;
    } else if (!input.empty() && input[0] == 'n') {
      answer = false;
    }
  } while (!answer.has_value());

  DCHECK(answer.has_value());
  std::move(callback).Run(answer.value());
}

// Saves |response| to |response_destination|.
// TODO(b/262814572): Migrate this to MojoResponseWaiter.
template <class T>
void OnMojoResponseReceived(T* response_destination,
                            base::OnceClosure quit_closure,
                            T response) {
  *response_destination = std::move(response);
  std::move(quit_closure).Run();
}

void PrintStatusMessage(const std::string& status_message) {
  std::cout << "Status message: " << status_message << std::endl;
}

}  // namespace

DiagActions::DiagActions() {
  // Bind the Diagnostics Service.
  RequestMojoServiceWithDisconnectHandler(
      chromeos::mojo_services::kCrosHealthdDiagnostics,
      cros_healthd_diagnostics_service_);

  default_tick_clock_ = std::make_unique<base::DefaultTickClock>();
  tick_clock_ = default_tick_clock_.get();
  DCHECK(tick_clock_);
}

DiagActions::~DiagActions() = default;

mojom::RoutineUpdatePtr DiagActions::GetRoutineUpdate(
    int32_t id,
    mojom::DiagnosticRoutineCommandEnum command,
    bool include_output) {
  MojoResponseWaiter<mojom::RoutineUpdatePtr> waiter;
  cros_healthd_diagnostics_service_->GetRoutineUpdate(
      id, command, include_output, waiter.CreateCallback());
  return waiter.WaitForResponse();
}

std::optional<std::vector<mojom::DiagnosticRoutineEnum>>
DiagActions::GetAvailableRoutines() {
  std::vector<mojom::DiagnosticRoutineEnum> response;
  base::RunLoop run_loop;
  cros_healthd_diagnostics_service_->GetAvailableRoutines(base::BindOnce(
      [](std::vector<mojom::DiagnosticRoutineEnum>* out,
         base::OnceClosure quit_closure,
         const std::vector<mojom::DiagnosticRoutineEnum>& routines) {
        *out = routines;
        std::move(quit_closure).Run();
      },
      &response, run_loop.QuitClosure()));
  run_loop.Run();
  return response;
}

bool DiagActions::ActionGetRoutines() {
  auto reply = GetAvailableRoutines();
  if (!reply.has_value()) {
    std::cout << "Unable to get available routines from cros_healthd"
              << std::endl;
    return false;
  }

  for (auto routine : reply.value()) {
    std::cout << "Available routine: " << GetSwitchFromRoutine(routine)
              << std::endl;
  }

  return true;
}

bool DiagActions::ActionRunAcPowerRoutine(
    mojom::AcPowerStatusEnum expected_status,
    const std::optional<std::string>& expected_power_type) {
  MojoResponseWaiter<mojom::RunRoutineResponsePtr> waiter;
  cros_healthd_diagnostics_service_->RunAcPowerRoutine(
      expected_status, expected_power_type, waiter.CreateCallback());
  return ProcessRoutineResponse(waiter.WaitForResponse());
}

bool DiagActions::ActionRunBatteryCapacityRoutine() {
  MojoResponseWaiter<mojom::RunRoutineResponsePtr> waiter;
  cros_healthd_diagnostics_service_->RunBatteryCapacityRoutine(
      waiter.CreateCallback());
  return ProcessRoutineResponse(waiter.WaitForResponse());
}

bool DiagActions::ActionRunBatteryChargeRoutine(
    uint32_t length_seconds, uint32_t minimum_charge_percent_required) {
  MojoResponseWaiter<mojom::RunRoutineResponsePtr> waiter;
  cros_healthd_diagnostics_service_->RunBatteryChargeRoutine(
      length_seconds, minimum_charge_percent_required, waiter.CreateCallback());
  return ProcessRoutineResponse(waiter.WaitForResponse());
}

bool DiagActions::ActionRunBatteryDischargeRoutine(
    uint32_t length_seconds, uint32_t maximum_discharge_percent_allowed) {
  MojoResponseWaiter<mojom::RunRoutineResponsePtr> waiter;
  cros_healthd_diagnostics_service_->RunBatteryDischargeRoutine(
      length_seconds, maximum_discharge_percent_allowed,
      waiter.CreateCallback());
  return ProcessRoutineResponse(waiter.WaitForResponse());
}

bool DiagActions::ActionRunBatteryHealthRoutine() {
  MojoResponseWaiter<mojom::RunRoutineResponsePtr> waiter;
  cros_healthd_diagnostics_service_->RunBatteryHealthRoutine(
      waiter.CreateCallback());
  return ProcessRoutineResponse(waiter.WaitForResponse());
}

bool DiagActions::ActionRunCaptivePortalRoutine() {
  MojoResponseWaiter<mojom::RunRoutineResponsePtr> waiter;
  cros_healthd_diagnostics_service_->RunCaptivePortalRoutine(
      waiter.CreateCallback());
  return ProcessRoutineResponse(waiter.WaitForResponse());
}

bool DiagActions::ActionRunCpuCacheRoutine(
    const std::optional<uint32_t>& length_seconds) {
  MojoResponseWaiter<mojom::RunRoutineResponsePtr> waiter;
  mojom::NullableUint32Ptr length_seconds_parameter;
  if (length_seconds.has_value()) {
    length_seconds_parameter =
        mojom::NullableUint32::New(length_seconds.value());
  }
  cros_healthd_diagnostics_service_->RunCpuCacheRoutine(
      std::move(length_seconds_parameter), waiter.CreateCallback());
  return ProcessRoutineResponse(waiter.WaitForResponse());
}

bool DiagActions::ActionRunCpuStressRoutine(
    const std::optional<uint32_t>& length_seconds) {
  MojoResponseWaiter<mojom::RunRoutineResponsePtr> waiter;
  mojom::NullableUint32Ptr length_seconds_parameter;
  if (length_seconds.has_value()) {
    length_seconds_parameter =
        mojom::NullableUint32::New(length_seconds.value());
  }
  cros_healthd_diagnostics_service_->RunCpuStressRoutine(
      std::move(length_seconds_parameter), waiter.CreateCallback());
  return ProcessRoutineResponse(waiter.WaitForResponse());
}

bool DiagActions::ActionRunDiskReadRoutine(mojom::DiskReadRoutineTypeEnum type,
                                           uint32_t length_seconds,
                                           uint32_t file_size_mb) {
  MojoResponseWaiter<mojom::RunRoutineResponsePtr> waiter;
  cros_healthd_diagnostics_service_->RunDiskReadRoutine(
      type, length_seconds, file_size_mb, waiter.CreateCallback());
  return ProcessRoutineResponse(waiter.WaitForResponse());
}

bool DiagActions::ActionRunDnsLatencyRoutine() {
  MojoResponseWaiter<mojom::RunRoutineResponsePtr> waiter;
  cros_healthd_diagnostics_service_->RunDnsLatencyRoutine(
      waiter.CreateCallback());
  return ProcessRoutineResponse(waiter.WaitForResponse());
}

bool DiagActions::ActionRunDnsResolutionRoutine() {
  MojoResponseWaiter<mojom::RunRoutineResponsePtr> waiter;
  cros_healthd_diagnostics_service_->RunDnsResolutionRoutine(
      waiter.CreateCallback());
  return ProcessRoutineResponse(waiter.WaitForResponse());
}

bool DiagActions::ActionRunDnsResolverPresentRoutine() {
  MojoResponseWaiter<mojom::RunRoutineResponsePtr> waiter;
  cros_healthd_diagnostics_service_->RunDnsResolverPresentRoutine(
      waiter.CreateCallback());
  return ProcessRoutineResponse(waiter.WaitForResponse());
}

bool DiagActions::ActionRunFloatingPointAccuracyRoutine(
    const std::optional<uint32_t>& length_seconds) {
  MojoResponseWaiter<mojom::RunRoutineResponsePtr> waiter;
  mojom::NullableUint32Ptr length_seconds_parameter;
  if (length_seconds.has_value()) {
    length_seconds_parameter =
        mojom::NullableUint32::New(length_seconds.value());
  }
  cros_healthd_diagnostics_service_->RunFloatingPointAccuracyRoutine(
      std::move(length_seconds_parameter), waiter.CreateCallback());
  return ProcessRoutineResponse(waiter.WaitForResponse());
}

bool DiagActions::ActionRunGatewayCanBePingedRoutine() {
  MojoResponseWaiter<mojom::RunRoutineResponsePtr> waiter;
  cros_healthd_diagnostics_service_->RunGatewayCanBePingedRoutine(
      waiter.CreateCallback());
  return ProcessRoutineResponse(waiter.WaitForResponse());
}

bool DiagActions::ActionRunHasSecureWiFiConnectionRoutine() {
  MojoResponseWaiter<mojom::RunRoutineResponsePtr> waiter;
  cros_healthd_diagnostics_service_->RunHasSecureWiFiConnectionRoutine(
      waiter.CreateCallback());
  return ProcessRoutineResponse(waiter.WaitForResponse());
}

bool DiagActions::ActionRunHttpFirewallRoutine() {
  MojoResponseWaiter<mojom::RunRoutineResponsePtr> waiter;
  cros_healthd_diagnostics_service_->RunHttpFirewallRoutine(
      waiter.CreateCallback());
  return ProcessRoutineResponse(waiter.WaitForResponse());
}

bool DiagActions::ActionRunHttpsFirewallRoutine() {
  MojoResponseWaiter<mojom::RunRoutineResponsePtr> waiter;
  cros_healthd_diagnostics_service_->RunHttpsFirewallRoutine(
      waiter.CreateCallback());
  return ProcessRoutineResponse(waiter.WaitForResponse());
}

bool DiagActions::ActionRunHttpsLatencyRoutine() {
  MojoResponseWaiter<mojom::RunRoutineResponsePtr> waiter;
  cros_healthd_diagnostics_service_->RunHttpsLatencyRoutine(
      waiter.CreateCallback());
  return ProcessRoutineResponse(waiter.WaitForResponse());
}

bool DiagActions::ActionRunLanConnectivityRoutine() {
  MojoResponseWaiter<mojom::RunRoutineResponsePtr> waiter;
  cros_healthd_diagnostics_service_->RunLanConnectivityRoutine(
      waiter.CreateCallback());
  return ProcessRoutineResponse(waiter.WaitForResponse());
}

bool DiagActions::ActionRunMemoryRoutine(
    std::optional<uint32_t> max_testing_mem_kib) {
  MojoResponseWaiter<mojom::RunRoutineResponsePtr> waiter;
  cros_healthd_diagnostics_service_->RunMemoryRoutine(max_testing_mem_kib,
                                                      waiter.CreateCallback());
  return ProcessRoutineResponse(waiter.WaitForResponse());
}

bool DiagActions::ActionRunNvmeSelfTestRoutine(
    mojom::NvmeSelfTestTypeEnum nvme_self_test_type) {
  MojoResponseWaiter<mojom::RunRoutineResponsePtr> waiter;
  cros_healthd_diagnostics_service_->RunNvmeSelfTestRoutine(
      nvme_self_test_type, waiter.CreateCallback());
  return ProcessRoutineResponse(waiter.WaitForResponse());
}

bool DiagActions::ActionRunNvmeWearLevelRoutine(
    const std::optional<uint32_t>& wear_level_threshold) {
  MojoResponseWaiter<mojom::RunRoutineResponsePtr> waiter;
  mojom::NullableUint32Ptr wear_level_threshold_parameter;
  if (wear_level_threshold.has_value()) {
    wear_level_threshold_parameter =
        mojom::NullableUint32::New(wear_level_threshold.value());
  }
  cros_healthd_diagnostics_service_->RunNvmeWearLevelRoutine(
      std::move(wear_level_threshold_parameter), waiter.CreateCallback());
  return ProcessRoutineResponse(waiter.WaitForResponse());
}

bool DiagActions::ActionRunPrimeSearchRoutine(
    const std::optional<uint32_t>& length_seconds) {
  MojoResponseWaiter<mojom::RunRoutineResponsePtr> waiter;
  mojom::NullableUint32Ptr length_seconds_parameter;
  if (length_seconds.has_value()) {
    length_seconds_parameter =
        mojom::NullableUint32::New(length_seconds.value());
  }
  cros_healthd_diagnostics_service_->RunPrimeSearchRoutine(
      std::move(length_seconds_parameter), waiter.CreateCallback());
  return ProcessRoutineResponse(waiter.WaitForResponse());
}

bool DiagActions::ActionRunSignalStrengthRoutine() {
  MojoResponseWaiter<mojom::RunRoutineResponsePtr> waiter;
  cros_healthd_diagnostics_service_->RunSignalStrengthRoutine(
      waiter.CreateCallback());
  return ProcessRoutineResponse(waiter.WaitForResponse());
}

bool DiagActions::ActionRunSmartctlCheckRoutine(
    const std::optional<uint32_t>& percentage_used_threshold) {
  MojoResponseWaiter<mojom::RunRoutineResponsePtr> waiter;
  ash::cros_healthd::mojom::NullableUint32Ptr
      percentage_used_threshold_parameter;
  if (percentage_used_threshold.has_value()) {
    percentage_used_threshold_parameter =
        ash::cros_healthd::mojom::NullableUint32::New(
            percentage_used_threshold.value());
  }
  cros_healthd_diagnostics_service_->RunSmartctlCheckRoutine(
      std::move(percentage_used_threshold_parameter), waiter.CreateCallback());
  return ProcessRoutineResponse(waiter.WaitForResponse());
}

bool DiagActions::ActionRunUrandomRoutine(
    const std::optional<uint32_t>& length_seconds) {
  MojoResponseWaiter<mojom::RunRoutineResponsePtr> waiter;
  mojom::NullableUint32Ptr length_seconds_parameter;
  if (length_seconds.has_value()) {
    length_seconds_parameter =
        mojom::NullableUint32::New(length_seconds.value());
  }
  cros_healthd_diagnostics_service_->RunUrandomRoutine(
      std::move(length_seconds_parameter), waiter.CreateCallback());
  return ProcessRoutineResponse(waiter.WaitForResponse());
}

bool DiagActions::ActionRunVideoConferencingRoutine(
    const std::optional<std::string>& stun_server_hostname) {
  MojoResponseWaiter<mojom::RunRoutineResponsePtr> waiter;
  cros_healthd_diagnostics_service_->RunVideoConferencingRoutine(
      stun_server_hostname, waiter.CreateCallback());
  return ProcessRoutineResponse(waiter.WaitForResponse());
}

bool DiagActions::ActionRunArcHttpRoutine() {
  MojoResponseWaiter<mojom::RunRoutineResponsePtr> waiter;
  cros_healthd_diagnostics_service_->RunArcHttpRoutine(waiter.CreateCallback());
  return ProcessRoutineResponse(waiter.WaitForResponse());
}

bool DiagActions::ActionRunArcPingRoutine() {
  MojoResponseWaiter<mojom::RunRoutineResponsePtr> waiter;
  cros_healthd_diagnostics_service_->RunArcPingRoutine(waiter.CreateCallback());
  return ProcessRoutineResponse(waiter.WaitForResponse());
}

bool DiagActions::ActionRunArcDnsResolutionRoutine() {
  MojoResponseWaiter<mojom::RunRoutineResponsePtr> waiter;
  cros_healthd_diagnostics_service_->RunArcDnsResolutionRoutine(
      waiter.CreateCallback());
  return ProcessRoutineResponse(waiter.WaitForResponse());
}

bool DiagActions::ActionRunSensitiveSensorRoutine() {
  MojoResponseWaiter<mojom::RunRoutineResponsePtr> waiter;
  cros_healthd_diagnostics_service_->RunSensitiveSensorRoutine(
      waiter.CreateCallback());
  return ProcessRoutineResponse(waiter.WaitForResponse());
}

bool DiagActions::ActionRunFingerprintRoutine() {
  MojoResponseWaiter<mojom::RunRoutineResponsePtr> waiter;
  cros_healthd_diagnostics_service_->RunFingerprintRoutine(
      waiter.CreateCallback());
  return ProcessRoutineResponse(waiter.WaitForResponse());
}

bool DiagActions::ActionRunFingerprintAliveRoutine() {
  MojoResponseWaiter<mojom::RunRoutineResponsePtr> waiter;
  cros_healthd_diagnostics_service_->RunFingerprintAliveRoutine(
      waiter.CreateCallback());
  return ProcessRoutineResponse(waiter.WaitForResponse());
}

bool DiagActions::ActionRunPrivacyScreenRoutine(bool target_state) {
  MojoResponseWaiter<mojom::RunRoutineResponsePtr> waiter;
  cros_healthd_diagnostics_service_->RunPrivacyScreenRoutine(
      target_state, waiter.CreateCallback());
  return ProcessRoutineResponse(waiter.WaitForResponse());
}

bool DiagActions::ActionRunLedRoutine(mojom::LedName name,
                                      mojom::LedColor color) {
  mojo::PendingReceiver<mojom::LedLitUpRoutineReplier> replier_receiver;
  mojo::PendingRemote<mojom::LedLitUpRoutineReplier> replier_remote(
      replier_receiver.InitWithNewPipeAndPassRemote());
  led_lit_up_routine_replier_ =
      std::make_unique<LedLitUpRoutineReplier>(std::move(replier_receiver));
  led_lit_up_routine_replier_->SetGetColorMatchedHandler(
      base::BindRepeating(&HandleGetLedColorMatchedInvocation));
  MojoResponseWaiter<mojom::RunRoutineResponsePtr> waiter;
  cros_healthd_diagnostics_service_->RunLedLitUpRoutine(
      name, color, std::move(replier_remote), waiter.CreateCallback());
  return ProcessRoutineResponse(waiter.WaitForResponse());
}

bool DiagActions::ActionRunEmmcLifetimeRoutine() {
  MojoResponseWaiter<mojom::RunRoutineResponsePtr> waiter;
  cros_healthd_diagnostics_service_->RunEmmcLifetimeRoutine(
      waiter.CreateCallback());
  return ProcessRoutineResponse(waiter.WaitForResponse());
}

bool DiagActions::ActionRunAudioSetVolumeRoutine(uint64_t node_id,
                                                 uint8_t volume,
                                                 bool mute_on) {
  MojoResponseWaiter<mojom::RunRoutineResponsePtr> waiter;
  cros_healthd_diagnostics_service_->RunAudioSetVolumeRoutine(
      node_id, volume, mute_on, waiter.CreateCallback());
  return ProcessRoutineResponse(waiter.WaitForResponse());
}

bool DiagActions::ActionRunAudioSetGainRoutine(uint64_t node_id, uint8_t gain) {
  MojoResponseWaiter<mojom::RunRoutineResponsePtr> waiter;
  cros_healthd_diagnostics_service_->RunAudioSetGainRoutine(
      node_id, gain, /*deprecated_mute_on=*/false, waiter.CreateCallback());
  return ProcessRoutineResponse(waiter.WaitForResponse());
}

bool DiagActions::ActionRunBluetoothPowerRoutine() {
  MojoResponseWaiter<mojom::RunRoutineResponsePtr> waiter;
  cros_healthd_diagnostics_service_->RunBluetoothPowerRoutine(
      waiter.CreateCallback());
  return ProcessRoutineResponse(waiter.WaitForResponse());
}

bool DiagActions::ActionRunBluetoothDiscoveryRoutine() {
  MojoResponseWaiter<mojom::RunRoutineResponsePtr> waiter;
  cros_healthd_diagnostics_service_->RunBluetoothDiscoveryRoutine(
      waiter.CreateCallback());
  return ProcessRoutineResponse(waiter.WaitForResponse());
}

bool DiagActions::ActionRunBluetoothScanningRoutine(
    const std::optional<uint32_t>& length_seconds) {
  MojoResponseWaiter<mojom::RunRoutineResponsePtr> waiter;
  mojom::NullableUint32Ptr length_seconds_parameter;
  if (length_seconds.has_value()) {
    length_seconds_parameter =
        mojom::NullableUint32::New(length_seconds.value());
  }
  cros_healthd_diagnostics_service_->RunBluetoothScanningRoutine(
      std::move(length_seconds_parameter), waiter.CreateCallback());
  return ProcessRoutineResponse(waiter.WaitForResponse());
}

bool DiagActions::ActionRunBluetoothPairingRoutine(
    const std::string& peripheral_id) {
  MojoResponseWaiter<mojom::RunRoutineResponsePtr> waiter;
  cros_healthd_diagnostics_service_->RunBluetoothPairingRoutine(
      peripheral_id, waiter.CreateCallback());
  return ProcessRoutineResponse(waiter.WaitForResponse());
}

bool DiagActions::ActionRunPowerButtonRoutine(uint32_t timeout_seconds) {
  MojoResponseWaiter<mojom::RunRoutineResponsePtr> waiter;
  cros_healthd_diagnostics_service_->RunPowerButtonRoutine(
      timeout_seconds, waiter.CreateCallback());
  return ProcessRoutineResponse(waiter.WaitForResponse());
}

bool DiagActions::ActionRunAudioDriverRoutine() {
  MojoResponseWaiter<mojom::RunRoutineResponsePtr> waiter;
  cros_healthd_diagnostics_service_->RunAudioDriverRoutine(
      waiter.CreateCallback());
  return ProcessRoutineResponse(waiter.WaitForResponse());
}

void DiagActions::ForceCancelAtPercent(uint32_t percent) {
  CHECK_LE(percent, 100) << "Percent must be <= 100.";
  force_cancel_ = true;
  cancellation_percent_ = percent;
}

bool DiagActions::ProcessRoutineResponse(
    const mojom::RunRoutineResponsePtr& response) {
  if (!response) {
    std::cout << "Unable to run routine. Routine response empty" << std::endl;
    return false;
  }

  id_ = response->id;
  if (id_ == mojom::kFailedToStartId) {
    PrintStatus(response->status);
    auto status_msg = "";
    switch (response->status) {
      case mojom::DiagnosticRoutineStatusEnum::kUnsupported:
        status_msg = "The routine is not supported by the device";
        break;
      case mojom::DiagnosticRoutineStatusEnum::kNotRun:
        status_msg = "The routine is not applicable to the device at this time";
        break;
      default:
        status_msg = "Failed to start routine";
    }
    PrintStatusMessage(status_msg);
    return true;
  }

  return PollRoutineAndProcessResult();
}

bool DiagActions::PollRoutineAndProcessResult() {
  mojom::RoutineUpdatePtr response;
  const base::TimeTicks start_time = tick_clock_->NowTicks();

  do {
    // Poll the routine until it's either interactive and requires user input,
    // or it's noninteractive but no longer running.
    response =
        GetRoutineUpdate(id_, mojom::DiagnosticRoutineCommandEnum::kGetStatus,
                         true /* include_output */);
    std::cout << '\r' << "Progress: " << response->progress_percent
              << std::flush;

    if (force_cancel_ && !response.is_null() &&
        response->progress_percent >= cancellation_percent_) {
      response =
          GetRoutineUpdate(id_, mojom::DiagnosticRoutineCommandEnum::kCancel,
                           true /* include_output */);
      force_cancel_ = false;
    }

    base::RunLoop run_loop;
    base::SingleThreadTaskRunner::GetCurrentDefault()->PostDelayedTask(
        FROM_HERE, run_loop.QuitClosure(), kRoutinePollInterval);
    run_loop.Run();
  } while (
      !response.is_null() &&
      response->routine_update_union->is_noninteractive_update() &&
      response->routine_update_union->get_noninteractive_update()->status ==
          mojom::DiagnosticRoutineStatusEnum::kRunning &&
      tick_clock_->NowTicks() < start_time + kMaximumRoutineExecution);

  if (response.is_null()) {
    std::cout << '\n' << "No GetRoutineUpdateResponse received." << std::endl;
    return false;
  }

  if (response->routine_update_union->is_interactive_update()) {
    return ProcessInteractiveResultAndContinue(
        std::move(response->routine_update_union->get_interactive_update()));
  }

  // Noninteractive routines without a status of kRunning must have terminated
  // in some form. Print the update to the console to let the user know.
  std::cout << '\r' << "Progress: " << response->progress_percent << std::endl;
  if (response->output.is_valid()) {
    auto shm_mapping =
        diagnostics::GetReadOnlySharedMemoryMappingFromMojoHandle(
            std::move(response->output));
    if (!shm_mapping.IsValid()) {
      LOG(ERROR) << "Failed to read output.";
      return false;
    }

    auto output = base::JSONReader::Read(std::string(
        shm_mapping.GetMemoryAs<const char>(), shm_mapping.mapped_size()));
    if (!output.has_value()) {
      LOG(ERROR) << "Failed to parse output.";
      return false;
    }

    std::string json;
    base::JSONWriter::WriteWithOptions(
        output.value(), base::JSONWriter::Options::OPTIONS_PRETTY_PRINT, &json);
    std::cout << "Output: " << json << std::endl;
  }

  return ProcessNonInteractiveResultAndEnd(
      std::move(response->routine_update_union->get_noninteractive_update()));
}

bool DiagActions::ProcessInteractiveResultAndContinue(
    mojom::InteractiveRoutineUpdatePtr interactive_result) {
  // Print a newline so we don't overwrite the progress percent.
  std::cout << '\n';
  // Interactive updates require us to print out instructions to the user on the
  // console. Once the user responds by pressing the ENTER key, we need to send
  // a continue command to the routine and restart waiting for results.
  //
  // kCheckLedColor is an exception, which use a pending_remote to communicate
  // with the routine. It should be migrated to the new routine API in the
  // future.
  bool skip_sending_continue_command = false;
  switch (interactive_result->user_message) {
    case mojom::DiagnosticRoutineUserMessageEnum::kUnplugACPower:
      std::cout << "Unplug the AC adapter." << std::endl;
      WaitUntilEnterPressed();
      break;
    case mojom::DiagnosticRoutineUserMessageEnum::kPlugInACPower:
      std::cout << "Plug in the AC adapter." << std::endl;
      WaitUntilEnterPressed();
      break;
    case mojom::DiagnosticRoutineUserMessageEnum::kCheckLedColor:
      // Don't send the continue command because it communicates with the
      // routine through |HandleGetLedColorMatchedInvocation|.
      skip_sending_continue_command = true;
      break;
    case mojom::DiagnosticRoutineUserMessageEnum::kUnknown:
      LOG(ERROR) << "Unknown routine user message enum";
      RemoveRoutine();
      return false;
  }

  if (!skip_sending_continue_command) {
    auto response =
        GetRoutineUpdate(id_, mojom::DiagnosticRoutineCommandEnum::kContinue,
                         false /* include_output */);
  }
  return PollRoutineAndProcessResult();
}

bool DiagActions::ProcessNonInteractiveResultAndEnd(
    mojom::NonInteractiveRoutineUpdatePtr noninteractive_result) {
  mojom::DiagnosticRoutineStatusEnum status = noninteractive_result->status;

  // Clean up the routine if necessary - if the routine never started, then we
  // don't need to remove it.
  if (status != mojom::DiagnosticRoutineStatusEnum::kFailedToStart)
    RemoveRoutine();

  if (!PrintStatus(status))
    return false;

  PrintStatusMessage(noninteractive_result->status_message);

  return true;
}

void DiagActions::RemoveRoutine() {
  auto response =
      GetRoutineUpdate(id_, mojom::DiagnosticRoutineCommandEnum::kRemove,
                       false /* include_output */);

  // Reset |id_|, because it's no longer valid after the routine has been
  // removed.
  id_ = mojom::kFailedToStartId;

  if (response.is_null() ||
      !response->routine_update_union->is_noninteractive_update() ||
      response->routine_update_union->get_noninteractive_update()->status !=
          mojom::DiagnosticRoutineStatusEnum::kRemoved) {
    LOG(ERROR) << "Failed to remove routine: " << id_;
  }
}

bool DiagActions::PrintStatus(mojom::DiagnosticRoutineStatusEnum status) {
  bool status_found = false;
  for (const auto& item : kDiagnosticRoutineReadableStatuses) {
    if (item.status == status) {
      status_found = true;
      std::cout << "Status: " << item.readable_status << std::endl;
      break;
    }
  }

  if (!status_found) {
    LOG(ERROR) << "No human-readable string for status: "
               << static_cast<int>(status);
    return false;
  }

  return true;
}

}  // namespace diagnostics
