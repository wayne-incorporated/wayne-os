// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_ROUTINES_BATTERY_HEALTH_BATTERY_HEALTH_H_
#define DIAGNOSTICS_CROS_HEALTHD_ROUTINES_BATTERY_HEALTH_BATTERY_HEALTH_H_

#include <cstdint>
#include <memory>
#include <optional>

#include <base/files/file_path.h>

#include "diagnostics/cros_healthd/routines/diag_routine.h"
#include "diagnostics/cros_healthd/system/context.h"

namespace diagnostics {

// Status messages for the BatteryHealth routine when in various states.
extern const char kBatteryHealthInvalidParametersMessage[];
extern const char kBatteryHealthFailedCalculatingWearPercentageMessage[];
extern const char kBatteryHealthExcessiveWearMessage[];
extern const char kBatteryHealthFailedReadingCycleCountMessage[];
extern const char kBatteryHealthExcessiveCycleCountMessage[];
extern const char kBatteryHealthRoutinePassedMessage[];

// Fleet-wide default values for the battery health routine's parameters. These
// values were suggested by the ChromeOS power team.
extern const uint32_t kBatteryHealthDefaultMaximumCycleCount;
extern const uint8_t kBatteryHealthDefaultPercentBatteryWearAllowed;

// The battery health routine checks whether or not the battery's design
// capacity is within the given limits. If |maximum_cycle_count| and/or
// |percent_battery_wear_allowed| aren't specified, the routine will default to
// kBatteryHealthDefaultMaximumCycleCount and/or
// kBatteryHealthDefaultPercentBatteryWearAllowed.
std::unique_ptr<DiagnosticRoutine> CreateBatteryHealthRoutine(
    Context* const context,
    const std::optional<uint32_t>& maximum_cycle_count,
    const std::optional<uint8_t>& percent_battery_wear_allowed);

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_ROUTINES_BATTERY_HEALTH_BATTERY_HEALTH_H_
