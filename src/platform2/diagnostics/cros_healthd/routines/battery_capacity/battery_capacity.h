// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_ROUTINES_BATTERY_CAPACITY_BATTERY_CAPACITY_H_
#define DIAGNOSTICS_CROS_HEALTHD_ROUTINES_BATTERY_CAPACITY_BATTERY_CAPACITY_H_

#include <cstdint>
#include <memory>
#include <optional>

#include "diagnostics/cros_healthd/routines/diag_routine.h"
#include "diagnostics/cros_healthd/system/context.h"

namespace diagnostics {

// Output messages for the battery capacity routine when in various states.
extern const char kBatteryCapacityRoutineParametersInvalidMessage[];
extern const char kBatteryCapacityRoutineSucceededMessage[];
extern const char kBatteryCapacityRoutineFailedMessage[];

// Fleet-wide default values for the battery capacity routine's parameters.
// These values were taken from the corresponding factory test's defaults.
extern const uint32_t kBatteryCapacityDefaultLowMah;
extern const uint32_t kBatteryCapacityDefaultHighMah;

// The battery capacity routine checks whether or not the battery's design
// capacity is within the given limits. If |low_mah| and/or |high_mah| aren't
// specified, the routine will default to kBatteryCapacityDefaultLowMah and/or
// kBatteryCapacityDefaultHighMah.
std::unique_ptr<DiagnosticRoutine> CreateBatteryCapacityRoutine(
    Context* const context,
    const std::optional<uint32_t>& low_mah,
    const std::optional<uint32_t>& high_mah);

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_ROUTINES_BATTERY_CAPACITY_BATTERY_CAPACITY_H_
