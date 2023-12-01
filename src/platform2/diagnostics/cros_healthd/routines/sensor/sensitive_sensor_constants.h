// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_ROUTINES_SENSOR_SENSITIVE_SENSOR_CONSTANTS_H_
#define DIAGNOSTICS_CROS_HEALTHD_ROUTINES_SENSOR_SENSITIVE_SENSOR_CONSTANTS_H_

namespace diagnostics {

// Status messages of the sensitive sensor routine.
inline constexpr char kSensitiveSensorRoutineRunningMessage[] =
    "Sensitive sensor routine running.";
inline constexpr char kSensitiveSensorRoutinePassedMessage[] =
    "Sensitive sensor routine passed.";
inline constexpr char kSensitiveSensorRoutineFailedUnexpectedlyMessage[] =
    "Sensitive sensor routine failed unexpectedly.";
inline constexpr char kSensitiveSensorRoutineFailedMessage[] =
    "Sensitive sensor routine failed to pass all sensors.";
inline constexpr char kSensitiveSensorRoutineFailedCheckConfigMessage[] =
    "Sensitive sensor routine failed to pass configuration check.";

// Supported sensor types
inline constexpr char kSensitiveSensorRoutineTypeAccel[] = "Accel";
inline constexpr char kSensitiveSensorRoutineTypeGyro[] = "Gyro";
inline constexpr char kSensitiveSensorRoutineTypeGravity[] = "Gravity";
inline constexpr char kSensitiveSensorRoutineTypeMagn[] = "Magn";

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_ROUTINES_SENSOR_SENSITIVE_SENSOR_CONSTANTS_H_
