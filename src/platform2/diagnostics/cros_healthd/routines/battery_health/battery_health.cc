// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/routines/battery_health/battery_health.h"

#include <cstdint>
#include <optional>
#include <string>
#include <utility>

#include <base/check.h>
#include <base/logging.h>
#include <base/values.h>
#include <power_manager/proto_bindings/power_supply_properties.pb.h>

#include "diagnostics/cros_healthd/routines/simple_routine.h"
#include "diagnostics/mojom/public/cros_healthd_diagnostics.mojom.h"

namespace diagnostics {

namespace {

namespace mojom = ::ash::cros_healthd::mojom;

bool TestWearPercentage(
    const power_manager::PowerSupplyProperties& power_supply_proto,
    uint8_t percent_battery_wear_allowed,
    mojom::DiagnosticRoutineStatusEnum* status,
    std::string* status_message,
    base::Value::Dict* result_dict) {
  DCHECK(status);
  DCHECK(status_message);
  DCHECK(result_dict);

  double capacity = power_supply_proto.battery_charge_full();
  double design_capacity = power_supply_proto.battery_charge_full_design();

  if (percent_battery_wear_allowed > 100) {
    *status_message = kBatteryHealthInvalidParametersMessage;
    *status = mojom::DiagnosticRoutineStatusEnum::kError;
    return false;
  }

  if (!power_supply_proto.has_battery_charge_full() ||
      !power_supply_proto.has_battery_charge_full_design()) {
    *status_message = kBatteryHealthFailedCalculatingWearPercentageMessage;
    *status = mojom::DiagnosticRoutineStatusEnum::kError;
    return false;
  }

  // Cap the wear percentage at 0. There are cases where the capacity can be
  // higher than the design capacity, due to variance in batteries or vendors
  // setting conservative design capacities.
  uint32_t wear_percentage =
      capacity > design_capacity ? 0 : 100 - capacity * 100 / design_capacity;

  result_dict->Set("wearPercentage", static_cast<int>(wear_percentage));
  if (wear_percentage > percent_battery_wear_allowed) {
    *status_message = kBatteryHealthExcessiveWearMessage;
    *status = mojom::DiagnosticRoutineStatusEnum::kFailed;
    return false;
  }

  return true;
}

bool TestCycleCount(
    const power_manager::PowerSupplyProperties& power_supply_proto,
    uint32_t maximum_cycle_count,
    mojom::DiagnosticRoutineStatusEnum* status,
    std::string* status_message,
    base::Value::Dict* result_dict) {
  DCHECK(status);
  DCHECK(status_message);
  DCHECK(result_dict);

  google::protobuf::int64 cycle_count =
      power_supply_proto.battery_cycle_count();
  if (!power_supply_proto.has_battery_cycle_count()) {
    *status_message = kBatteryHealthFailedReadingCycleCountMessage;
    *status = mojom::DiagnosticRoutineStatusEnum::kError;
    return false;
  }

  result_dict->Set("cycleCount", static_cast<int>(cycle_count));
  if (cycle_count > maximum_cycle_count) {
    *status_message = kBatteryHealthExcessiveCycleCountMessage;
    *status = mojom::DiagnosticRoutineStatusEnum::kFailed;
    return false;
  }

  return true;
}

SimpleRoutine::RoutineResult GetBatteryHealthResult(
    Context* const context,
    uint32_t maximum_cycle_count,
    uint8_t percent_battery_wear_allowed) {
  DCHECK(context);

  std::optional<power_manager::PowerSupplyProperties> response =
      context->powerd_adapter()->GetPowerSupplyProperties();
  if (!response.has_value()) {
    LOG(ERROR) << kPowerdPowerSupplyPropertiesFailedMessage;
    return {
        .status = mojom::DiagnosticRoutineStatusEnum::kError,
        .status_message = kPowerdPowerSupplyPropertiesFailedMessage,
    };
  }

  mojom::DiagnosticRoutineStatusEnum status;
  std::string status_message;
  base::Value::Dict output_dict;

  base::Value::Dict result_dict;

  auto power_supply_proto = response.value();
  auto present =
      power_supply_proto.battery_state() ==
              power_manager::PowerSupplyProperties_BatteryState_NOT_PRESENT
          ? 0
          : 1;
  result_dict.Set("present", present);
  result_dict.Set("manufacturer", power_supply_proto.battery_vendor());
  result_dict.Set("currentNowA", power_supply_proto.battery_current());
  result_dict.Set("status", power_supply_proto.battery_status());
  result_dict.Set("voltageNowV", power_supply_proto.battery_voltage());
  result_dict.Set("chargeFullAh", power_supply_proto.battery_charge_full());
  result_dict.Set("chargeFullDesignAh",
                  power_supply_proto.battery_charge_full_design());
  result_dict.Set("chargeNowAh", power_supply_proto.battery_charge());

  if (TestWearPercentage(power_supply_proto, percent_battery_wear_allowed,
                         &status, &status_message, &result_dict) &&
      TestCycleCount(power_supply_proto, maximum_cycle_count, &status,
                     &status_message, &result_dict)) {
    status_message = kBatteryHealthRoutinePassedMessage;
    status = mojom::DiagnosticRoutineStatusEnum::kPassed;
  }

  if (!result_dict.empty()) {
    output_dict.Set("resultDetails", std::move(result_dict));
  }

  return {
      .status = status,
      .status_message = status_message,
      .output_dict = std::move(output_dict),
  };
}

void RunBatteryHealthRoutine(Context* const context,
                             uint32_t maximum_cycle_count,
                             uint8_t percent_battery_wear_allowed,
                             SimpleRoutine::RoutineResultCallback callback) {
  std::move(callback).Run(GetBatteryHealthResult(context, maximum_cycle_count,
                                                 percent_battery_wear_allowed));
}

}  // namespace

const char kBatteryHealthInvalidParametersMessage[] =
    "Invalid battery health routine parameters.";
const char kBatteryHealthFailedCalculatingWearPercentageMessage[] =
    "Could not get wear percentage.";
const char kBatteryHealthExcessiveWearMessage[] = "Battery is over-worn.";
const char kBatteryHealthFailedReadingCycleCountMessage[] =
    "Could not get cycle count.";
const char kBatteryHealthExcessiveCycleCountMessage[] =
    "Battery cycle count is too high.";
const char kBatteryHealthRoutinePassedMessage[] = "Routine passed.";

const uint32_t kBatteryHealthDefaultMaximumCycleCount = 1000;
const uint8_t kBatteryHealthDefaultPercentBatteryWearAllowed = 50;

std::unique_ptr<DiagnosticRoutine> CreateBatteryHealthRoutine(
    Context* const context,
    const std::optional<uint32_t>& maximum_cycle_count,
    const std::optional<uint8_t>& percent_battery_wear_allowed) {
  return std::make_unique<SimpleRoutine>(base::BindOnce(
      &RunBatteryHealthRoutine, context,
      maximum_cycle_count.value_or(kBatteryHealthDefaultMaximumCycleCount),
      percent_battery_wear_allowed.value_or(
          kBatteryHealthDefaultPercentBatteryWearAllowed)));
}

}  // namespace diagnostics
