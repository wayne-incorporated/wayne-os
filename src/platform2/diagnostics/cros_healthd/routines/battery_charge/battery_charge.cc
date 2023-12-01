// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/routines/battery_charge/battery_charge.h"

#include <inttypes.h>

#include <cstdint>
#include <optional>
#include <string>
#include <utility>

#include <base/check.h>
#include <base/check_op.h>
#include <base/json/json_writer.h>
#include <base/logging.h>
#include <base/task/single_thread_task_runner.h>
#include <power_manager/proto_bindings/power_supply_properties.pb.h>

#include "diagnostics/base/mojo_utils.h"
#include "diagnostics/cros_healthd/routines/battery_charge/battery_charge_constants.h"
#include "diagnostics/mojom/public/cros_healthd_diagnostics.mojom.h"

namespace diagnostics {

namespace mojom = ::ash::cros_healthd::mojom;

BatteryChargeRoutine::BatteryChargeRoutine(
    Context* const context,
    base::TimeDelta exec_duration,
    uint32_t minimum_charge_percent_required,
    const base::TickClock* tick_clock)
    : context_(context),
      exec_duration_(exec_duration),
      minimum_charge_percent_required_(minimum_charge_percent_required) {
  if (tick_clock) {
    tick_clock_ = tick_clock;
  } else {
    default_tick_clock_ = std::make_unique<base::DefaultTickClock>();
    tick_clock_ = default_tick_clock_.get();
  }
  DCHECK(context_);
  DCHECK(tick_clock_);
}

BatteryChargeRoutine::~BatteryChargeRoutine() = default;

void BatteryChargeRoutine::Start() {
  DCHECK_EQ(GetStatus(), mojom::DiagnosticRoutineStatusEnum::kReady);
  // Transition to waiting so the user can plug in the charger if necessary.
  UpdateStatus(mojom::DiagnosticRoutineStatusEnum::kWaiting, "");
  CalculateProgressPercent();
}

void BatteryChargeRoutine::Resume() {
  DCHECK_EQ(GetStatus(), mojom::DiagnosticRoutineStatusEnum::kWaiting);
  RunBatteryChargeRoutine();
  if (GetStatus() != mojom::DiagnosticRoutineStatusEnum::kRunning)
    LOG(ERROR) << "Routine failed: " << GetStatusMessage();
}

void BatteryChargeRoutine::Cancel() {
  auto status = GetStatus();
  // Cancel the routine if it hasn't already finished.
  if (status == mojom::DiagnosticRoutineStatusEnum::kPassed ||
      status == mojom::DiagnosticRoutineStatusEnum::kFailed ||
      status == mojom::DiagnosticRoutineStatusEnum::kError) {
    return;
  }

  CalculateProgressPercent();

  callback_.Cancel();
  UpdateStatus(mojom::DiagnosticRoutineStatusEnum::kCancelled,
               kBatteryChargeRoutineCancelledMessage);
}

void BatteryChargeRoutine::PopulateStatusUpdate(mojom::RoutineUpdate* response,
                                                bool include_output) {
  auto status = GetStatus();
  if (status == mojom::DiagnosticRoutineStatusEnum::kWaiting) {
    auto interactive_update = mojom::InteractiveRoutineUpdate::New();
    interactive_update->user_message =
        mojom::DiagnosticRoutineUserMessageEnum::kPlugInACPower;
    response->routine_update_union =
        mojom::RoutineUpdateUnion::NewInteractiveUpdate(
            std::move(interactive_update));
  } else {
    auto noninteractive_update = mojom::NonInteractiveRoutineUpdate::New();
    noninteractive_update->status = status;
    noninteractive_update->status_message = GetStatusMessage();

    response->routine_update_union =
        mojom::RoutineUpdateUnion::NewNoninteractiveUpdate(
            std::move(noninteractive_update));
  }

  CalculateProgressPercent();
  response->progress_percent = progress_percent_;
  if (include_output && !output_.empty()) {
    std::string json;
    base::JSONWriter::Write(output_, &json);
    response->output =
        CreateReadOnlySharedMemoryRegionMojoHandle(base::StringPiece(json));
  }
}

void BatteryChargeRoutine::CalculateProgressPercent() {
  auto status = GetStatus();
  if (status == mojom::DiagnosticRoutineStatusEnum::kPassed ||
      status == mojom::DiagnosticRoutineStatusEnum::kFailed) {
    // The routine has finished, so report 100.
    progress_percent_ = 100;
  } else if (status != mojom::DiagnosticRoutineStatusEnum::kError &&
             status != mojom::DiagnosticRoutineStatusEnum::kCancelled &&
             start_ticks_.has_value()) {
    progress_percent_ =
        100 * (tick_clock_->NowTicks() - start_ticks_.value()) / exec_duration_;
  }
}

void BatteryChargeRoutine::RunBatteryChargeRoutine() {
  std::optional<power_manager::PowerSupplyProperties> response =
      context_->powerd_adapter()->GetPowerSupplyProperties();
  if (!response.has_value()) {
    UpdateStatus(mojom::DiagnosticRoutineStatusEnum::kError,
                 kPowerdPowerSupplyPropertiesFailedMessage);
    return;
  }
  auto power_supply_proto = response.value();

  if (power_supply_proto.battery_state() !=
      power_manager::PowerSupplyProperties_BatteryState_CHARGING) {
    UpdateStatus(mojom::DiagnosticRoutineStatusEnum::kError,
                 kBatteryChargeRoutineNotChargingMessage);
    return;
  }

  double beginning_charge_percent = power_supply_proto.battery_percent();

  if (beginning_charge_percent + minimum_charge_percent_required_ > 100) {
    base::Value::Dict error_dict;
    error_dict.Set("startingBatteryChargePercent", beginning_charge_percent);
    error_dict.Set("chargePercentRequested",
                   static_cast<int>(minimum_charge_percent_required_));
    output_.Set("errorDetails", std::move(error_dict));
    UpdateStatus(mojom::DiagnosticRoutineStatusEnum::kError,
                 kBatteryChargeRoutineInvalidParametersMessage);
    return;
  }

  start_ticks_ = tick_clock_->NowTicks();

  callback_.Reset(base::BindOnce(&BatteryChargeRoutine::DetermineRoutineResult,
                                 weak_ptr_factory_.GetWeakPtr(),
                                 beginning_charge_percent));
  base::SingleThreadTaskRunner::GetCurrentDefault()->PostDelayedTask(
      FROM_HERE, callback_.callback(), exec_duration_);

  UpdateStatus(mojom::DiagnosticRoutineStatusEnum::kRunning,
               kBatteryChargeRoutineRunningMessage);
}

void BatteryChargeRoutine::DetermineRoutineResult(
    double beginning_charge_percent) {
  std::optional<power_manager::PowerSupplyProperties> response =
      context_->powerd_adapter()->GetPowerSupplyProperties();
  if (!response.has_value()) {
    UpdateStatus(mojom::DiagnosticRoutineStatusEnum::kError,
                 kPowerdPowerSupplyPropertiesFailedMessage);
    LOG(ERROR) << kPowerdPowerSupplyPropertiesFailedMessage;
    return;
  }
  auto power_supply_proto = response.value();
  double ending_charge_percent = power_supply_proto.battery_percent();

  if (ending_charge_percent < beginning_charge_percent) {
    UpdateStatus(mojom::DiagnosticRoutineStatusEnum::kError,
                 kBatteryChargeRoutineNotChargingMessage);
    LOG(ERROR) << kBatteryChargeRoutineNotChargingMessage;
    return;
  }

  double charge_percent = ending_charge_percent - beginning_charge_percent;
  base::Value::Dict result_dict;
  result_dict.Set("chargePercent", charge_percent);
  output_.Set("resultDetails", std::move(result_dict));
  if (charge_percent < minimum_charge_percent_required_) {
    UpdateStatus(mojom::DiagnosticRoutineStatusEnum::kFailed,
                 kBatteryChargeRoutineFailedInsufficientChargeMessage);
    return;
  }

  UpdateStatus(mojom::DiagnosticRoutineStatusEnum::kPassed,
               kBatteryChargeRoutineSucceededMessage);
}

}  // namespace diagnostics
