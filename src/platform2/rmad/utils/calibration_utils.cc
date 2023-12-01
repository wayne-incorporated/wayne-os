// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "rmad/utils/calibration_utils.h"

#include <string>

#include <base/logging.h>

namespace rmad {

bool IsValidCalibrationComponent(RmadComponent component) {
  for (auto [grouped_component, instruction] : kCalibrationSetupInstruction) {
    if (component == grouped_component) {
      return true;
    }
  }
  return false;
}

CalibrationSetupInstruction GetCalibrationSetupInstruction(
    RmadComponent component) {
  CalibrationSetupInstruction setup_instruction =
      RMAD_CALIBRATION_INSTRUCTION_UNKNOWN;
  for (auto [grouped_component, instruction] : kCalibrationSetupInstruction) {
    if (grouped_component == component) {
      setup_instruction = instruction;
      break;
    }
  }

  if (setup_instruction == RMAD_CALIBRATION_INSTRUCTION_UNKNOWN) {
    LOG(ERROR) << "Unknown setup instruction for the device "
               << RmadComponent_Name(component);
  }

  return setup_instruction;
}

bool IsWaitingForCalibration(
    CalibrationComponentStatus::CalibrationStatus status) {
  return status == CalibrationComponentStatus::RMAD_CALIBRATION_WAITING;
}

bool IsCompleteStatus(CalibrationComponentStatus::CalibrationStatus status) {
  return status == CalibrationComponentStatus::RMAD_CALIBRATION_COMPLETE ||
         status == CalibrationComponentStatus::RMAD_CALIBRATION_SKIP;
}

bool IsFailedStatus(CalibrationComponentStatus::CalibrationStatus status) {
  return status == CalibrationComponentStatus::RMAD_CALIBRATION_FAILED;
}

bool IsInProgressStatus(CalibrationComponentStatus::CalibrationStatus status) {
  return status == CalibrationComponentStatus::RMAD_CALIBRATION_IN_PROGRESS ||
         status == CalibrationComponentStatus::
                       RMAD_CALIBRATION_GET_ORIGINAL_CALIBBIAS ||
         status == CalibrationComponentStatus::
                       RMAD_CALIBRATION_SENSOR_DATA_RECEIVED ||
         status == CalibrationComponentStatus::
                       RMAD_CALIBRATION_CALIBBIAS_CALCULATED ||
         status ==
             CalibrationComponentStatus::RMAD_CALIBRATION_CALIBBIAS_CACHED;
}

bool IsPendingWriteStatus(
    CalibrationComponentStatus::CalibrationStatus status) {
  return status ==
         CalibrationComponentStatus::RMAD_CALIBRATION_CALIBBIAS_CACHED;
}

bool IsUnknownStatus(CalibrationComponentStatus::CalibrationStatus status) {
  return status == CalibrationComponentStatus::RMAD_CALIBRATION_UNKNOWN;
}

bool GetCalibrationMap(scoped_refptr<JsonStore> json_store,
                       InstructionCalibrationStatusMap* calibration_map) {
  if (!calibration_map) {
    LOG(ERROR) << "Missing output field of the calibration map";
    return false;
  }

  std::map<std::string, std::map<std::string, std::string>> json_value_map;
  if (!json_store->GetValue(kCalibrationMap, &json_value_map)) {
    LOG(ERROR) << "Cannot get variables from the json store";
    return false;
  }

  for (auto [instruction_name, components] : json_value_map) {
    CalibrationSetupInstruction instruction;
    if (!CalibrationSetupInstruction_Parse(instruction_name, &instruction)) {
      LOG(ERROR) << "Failed to parse setup instruction from variables";
      continue;
    }

    for (auto [component_name, status_name] : components) {
      RmadComponent component;
      if (!RmadComponent_Parse(component_name, &component)) {
        LOG(ERROR) << "Failed to parse component name from variables";
        continue;
      }
      CalibrationComponentStatus::CalibrationStatus status;
      if (!CalibrationComponentStatus::CalibrationStatus_Parse(status_name,
                                                               &status)) {
        LOG(ERROR) << "Failed to parse status name from variables";
        continue;
      }
      if (component == RmadComponent::RMAD_COMPONENT_UNKNOWN) {
        LOG(ERROR) << "Rmad: Calibration component is missing.";
        continue;
      }
      if (status == CalibrationComponentStatus::RMAD_CALIBRATION_UNKNOWN) {
        LOG(ERROR) << "Rmad: Calibration status for " << component_name
                   << " is missing.";
        continue;
      }
      if (!IsValidCalibrationComponent(component)) {
        LOG(ERROR) << "Dictionary contains unsupported component "
                   << RmadComponent_Name(component)
                   << ", we should rewrite it again.";
        continue;
      }
      (*calibration_map)[instruction][component] = status;
    }
  }

  return true;
}

bool SetCalibrationMap(scoped_refptr<JsonStore> json_store,
                       const InstructionCalibrationStatusMap& calibration_map) {
  // In order to save dictionary style variables to json, currently only
  // variables whose keys are strings are supported. This is why we converted
  // it to a string. In addition, in order to ensure that the file is still
  // readable after the enum sequence is updated, we also convert its value
  // into a readable string to deal with possible updates.
  std::map<std::string, std::map<std::string, std::string>> json_value_map;
  for (auto [instruction, components] : calibration_map) {
    std::string instruction_name =
        CalibrationSetupInstruction_Name(instruction);
    for (auto [component, status] : components) {
      if (!IsValidCalibrationComponent(component)) {
        LOG(WARNING) << "Rmad: " << RmadComponent_Name(component)
                     << " cannot be calibrated, just ignore it.";
        continue;
      }
      std::string component_name = RmadComponent_Name(component);
      std::string status_name =
          CalibrationComponentStatus::CalibrationStatus_Name(status);
      json_value_map[instruction_name][component_name] = status_name;
    }
  }

  return json_store->SetValue(kCalibrationMap, json_value_map);
}

CalibrationSetupInstruction GetCurrentSetupInstruction(
    const InstructionCalibrationStatusMap& calibration_map) {
  // If we don't find anything that needs calibration and there are no errors,
  // we don't need to check or calibrate.
  CalibrationSetupInstruction setup_instruction =
      RMAD_CALIBRATION_INSTRUCTION_NO_NEED_CALIBRATION;
  CalibrationSetupInstruction running_instruction =
      RMAD_CALIBRATION_INSTRUCTION_NO_NEED_CALIBRATION;

  // There are different priority situations:
  // 0. Unsupported component error (need to check)
  // 1. Instruction of calibration in progress (already started)
  // 2. Instruction of waiting for calibration components (not started yet)
  // 3. Everything is done, but some failed (need to check)
  // 4. All complete (no need to check)
  for (auto [instruction, components] : calibration_map) {
    for (auto [component, status] : components) {
      // We do not allow unsupported components in the dictionary.
      if (!IsValidCalibrationComponent(component)) {
        LOG(ERROR) << "Dictionary contains unsupported component "
                   << RmadComponent_Name(component)
                   << ", we should rewrite it again.";
        return RMAD_CALIBRATION_INSTRUCTION_NEED_TO_CHECK;
      }
      if (status == CalibrationComponentStatus::RMAD_CALIBRATION_IN_PROGRESS &&
          running_instruction >= instruction) {
        running_instruction = instruction;
      } else if (IsWaitingForCalibration(status) &&
                 setup_instruction >= instruction) {
        setup_instruction = instruction;
      } else if (!IsWaitingForCalibration(status) &&
                 !IsCompleteStatus(status) &&
                 setup_instruction ==
                     RMAD_CALIBRATION_INSTRUCTION_NO_NEED_CALIBRATION) {
        setup_instruction = RMAD_CALIBRATION_INSTRUCTION_NEED_TO_CHECK;
      }
    }
  }

  // If we are already running calibration, then this is the first priority.
  if (running_instruction != RMAD_CALIBRATION_INSTRUCTION_NO_NEED_CALIBRATION) {
    return running_instruction;
  }
  return setup_instruction;
}

}  // namespace rmad
