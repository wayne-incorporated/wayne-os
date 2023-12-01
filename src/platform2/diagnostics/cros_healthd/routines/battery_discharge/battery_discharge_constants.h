// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_ROUTINES_BATTERY_DISCHARGE_BATTERY_DISCHARGE_CONSTANTS_H_
#define DIAGNOSTICS_CROS_HEALTHD_ROUTINES_BATTERY_DISCHARGE_BATTERY_DISCHARGE_CONSTANTS_H_

namespace diagnostics {

// Status messages reported by the battery discharge routine.
inline constexpr char kBatteryDischargeRoutineSucceededMessage[] =
    "Battery discharge routine passed.";
inline constexpr char kBatteryDischargeRoutineNotDischargingMessage[] =
    "Battery is not discharging.";
inline constexpr char
    kBatteryDischargeRoutineFailedExcessiveDischargeMessage[] =
        "Battery discharge rate greater than maximum allowed discharge rate.";
inline constexpr char
    kBatteryDischargeRoutineFailedReadingBatteryAttributesMessage[] =
        "Failed to read battery attributes from sysfs.";
inline constexpr char kBatteryDischargeRoutineInvalidParametersMessage[] =
    "Maximum allowed discharge percent must be less than or equal to 100.";
inline constexpr char kBatteryDischargeRoutineCancelledMessage[] =
    "Battery discharge routine cancelled.";
inline constexpr char kBatteryDischargeRoutineRunningMessage[] =
    "Battery discharge routine running.";

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_ROUTINES_BATTERY_DISCHARGE_BATTERY_DISCHARGE_CONSTANTS_H_
