// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/routines/battery_capacity/battery_capacity.h"

#include <cstdint>
#include <optional>
#include <string>
#include <utility>

#include <base/check.h>
#include <base/functional/callback.h>
#include <base/logging.h>
#include <power_manager/proto_bindings/power_supply_properties.pb.h>

#include "diagnostics/cros_healthd/routines/simple_routine.h"
#include "diagnostics/mojom/public/cros_healthd_diagnostics.mojom.h"

namespace diagnostics {

namespace {

namespace mojom = ::ash::cros_healthd::mojom;

// Conversion factor from Ah to mAh.
constexpr uint32_t kAhTomAhMultiplier = 1000;

SimpleRoutine::RoutineResult GetBatteryCapacityResult(Context* const context,
                                                      uint32_t low_mah,
                                                      uint32_t high_mah) {
  DCHECK(context);

  if (low_mah > high_mah) {
    return {
        .status = mojom::DiagnosticRoutineStatusEnum::kError,
        .status_message = kBatteryCapacityRoutineParametersInvalidMessage,
    };
  }

  std::optional<power_manager::PowerSupplyProperties> response =
      context->powerd_adapter()->GetPowerSupplyProperties();
  if (!response.has_value()) {
    return {
        .status = mojom::DiagnosticRoutineStatusEnum::kError,
        .status_message = kPowerdPowerSupplyPropertiesFailedMessage,
    };
  }

  auto power_supply_proto = response.value();
  double charge_full_design_ah =
      power_supply_proto.battery_charge_full_design();

  // Conversion is necessary because the inputs are given in mAh, whereas the
  // design capacity is reported in Ah.
  uint32_t charge_full_design_mah = charge_full_design_ah * kAhTomAhMultiplier;
  if (!(charge_full_design_mah >= low_mah) ||
      !(charge_full_design_mah <= high_mah)) {
    return {
        .status = mojom::DiagnosticRoutineStatusEnum::kFailed,
        .status_message = kBatteryCapacityRoutineFailedMessage,
    };
  }

  return {
      .status = mojom::DiagnosticRoutineStatusEnum::kPassed,
      .status_message = kBatteryCapacityRoutineSucceededMessage,
  };
}

void RunBatteryCapacityRoutine(Context* const context,
                               uint32_t low_mah,
                               uint32_t high_mah,
                               SimpleRoutine::RoutineResultCallback callback) {
  std::move(callback).Run(GetBatteryCapacityResult(context, low_mah, high_mah));
}

}  // namespace

const char kBatteryCapacityRoutineParametersInvalidMessage[] =
    "Invalid BatteryCapacityRoutineParameters.";
const char kBatteryCapacityRoutineSucceededMessage[] =
    "Battery design capacity within given limits.";
const char kBatteryCapacityRoutineFailedMessage[] =
    "Battery design capacity not within given limits.";

const uint32_t kBatteryCapacityDefaultLowMah = 1000;
const uint32_t kBatteryCapacityDefaultHighMah = 10000;

std::unique_ptr<DiagnosticRoutine> CreateBatteryCapacityRoutine(
    Context* const context,
    const std::optional<uint32_t>& low_mah,
    const std::optional<uint32_t>& high_mah) {
  return std::make_unique<SimpleRoutine>(
      base::BindOnce(&RunBatteryCapacityRoutine, context,
                     low_mah.value_or(kBatteryCapacityDefaultLowMah),
                     high_mah.value_or(kBatteryCapacityDefaultHighMah)));
}

}  // namespace diagnostics
