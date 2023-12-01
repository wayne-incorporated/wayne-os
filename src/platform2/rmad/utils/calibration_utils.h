// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RMAD_UTILS_CALIBRATION_UTILS_H_
#define RMAD_UTILS_CALIBRATION_UTILS_H_

#include <array>
#include <map>
#include <utility>

#include <base/memory/scoped_refptr.h>

#include "rmad/constants.h"
#include "rmad/utils/json_store.h"

namespace rmad {

inline constexpr std::
    array<std::pair<RmadComponent, CalibrationSetupInstruction>, 4>
        kCalibrationSetupInstruction = {
            {{RMAD_COMPONENT_BASE_ACCELEROMETER,
              RMAD_CALIBRATION_INSTRUCTION_PLACE_BASE_ON_FLAT_SURFACE},
             {RMAD_COMPONENT_LID_ACCELEROMETER,
              RMAD_CALIBRATION_INSTRUCTION_PLACE_LID_ON_FLAT_SURFACE},
             {RMAD_COMPONENT_BASE_GYROSCOPE,
              RMAD_CALIBRATION_INSTRUCTION_PLACE_BASE_ON_FLAT_SURFACE},
             {RMAD_COMPONENT_LID_GYROSCOPE,
              RMAD_CALIBRATION_INSTRUCTION_PLACE_LID_ON_FLAT_SURFACE}}};

// Check if the component can be calibrated.
bool IsValidCalibrationComponent(RmadComponent component);

// Get the setup instruction for calibration according to the given component.
CalibrationSetupInstruction GetCalibrationSetupInstruction(
    RmadComponent component);

// Check whether calibration is required according to the calibration status.
bool IsWaitingForCalibration(
    CalibrationComponentStatus::CalibrationStatus status);

// Check whether calibration is complete (complete or skipped by user) or not.
bool IsCompleteStatus(CalibrationComponentStatus::CalibrationStatus status);

// Check whether calibration is failed or not.
bool IsFailedStatus(CalibrationComponentStatus::CalibrationStatus status);

// Check whether the status is in progress or not.
bool IsInProgressStatus(CalibrationComponentStatus::CalibrationStatus status);

// Check whether the status is pending write or not.
bool IsPendingWriteStatus(CalibrationComponentStatus::CalibrationStatus status);

// Check whether the status is unknown or not.
bool IsUnknownStatus(CalibrationComponentStatus::CalibrationStatus status);

using InstructionCalibrationStatusMap = std::map<
    CalibrationSetupInstruction,
    std::map<RmadComponent, CalibrationComponentStatus::CalibrationStatus>>;

// Get the current calibration status and setup instructions of each sensor from
// the given json storage.
bool GetCalibrationMap(scoped_refptr<JsonStore> json_store,
                       InstructionCalibrationStatusMap* calibration_map);

// Set the current calibration status and setup instructions of each sensor to
// the given json storage.
bool SetCalibrationMap(scoped_refptr<JsonStore> json_store,
                       const InstructionCalibrationStatusMap& calibration_map);

// Get current setup instructions by providing calibration status of all
// sensors.
CalibrationSetupInstruction GetCurrentSetupInstruction(
    const InstructionCalibrationStatusMap& calibration_map);

}  // namespace rmad

#endif  // RMAD_UTILS_CALIBRATION_UTILS_H_
