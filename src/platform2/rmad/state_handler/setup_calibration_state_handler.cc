// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "rmad/state_handler/setup_calibration_state_handler.h"

#include <base/logging.h>

#include "rmad/logs/logs_utils.h"
#include "rmad/utils/calibration_utils.h"

namespace rmad {

SetupCalibrationStateHandler::SetupCalibrationStateHandler(
    scoped_refptr<JsonStore> json_store,
    scoped_refptr<DaemonCallback> daemon_callback)
    : BaseStateHandler(json_store, daemon_callback),
      running_setup_instruction_(RMAD_CALIBRATION_INSTRUCTION_UNKNOWN) {}

RmadErrorCode SetupCalibrationStateHandler::InitializeState() {
  // The calibration map should be initialized in the provisioning state.
  if (!GetCalibrationMap(json_store_, &calibration_map_)) {
    LOG(ERROR) << "Failed to get calibration status.";
    return RMAD_ERROR_STATE_HANDLER_INITIALIZATION_FAILED;
  }

  // We mark all components with an unexpected status as failed because it may
  // have some errors.
  for (auto [instruction, components] : calibration_map_) {
    for (auto [component, status] : components) {
      if (calibration_map_.count(instruction) &&
          calibration_map_[instruction].count(component)) {
        if (IsInProgressStatus(status) || IsUnknownStatus(status)) {
          status = CalibrationComponentStatus::RMAD_CALIBRATION_FAILED;
        }
        calibration_map_[instruction][component] = status;
      }
    }
  }

  if (!SetCalibrationMap(json_store_, calibration_map_)) {
    LOG(ERROR) << "Failed to set calibration status.";
    return RMAD_ERROR_STATE_HANDLER_INITIALIZATION_FAILED;
  }

  running_setup_instruction_ = GetCurrentSetupInstruction(calibration_map_);

  auto setup_calibration_state = std::make_unique<SetupCalibrationState>();
  setup_calibration_state->set_instruction(running_setup_instruction_);
  state_.set_allocated_setup_calibration(setup_calibration_state.release());
  return RMAD_ERROR_OK;
}

BaseStateHandler::GetNextStateCaseReply
SetupCalibrationStateHandler::GetNextStateCase(const RmadState& state) {
  if (!state.has_setup_calibration()) {
    LOG(ERROR) << "RmadState missing |setup calibration| state.";
    return NextStateCaseWrapper(RMAD_ERROR_REQUEST_INVALID);
  }

  if (running_setup_instruction_ != state.setup_calibration().instruction()) {
    LOG(ERROR) << "The read-only setup instruction is changed.";
    return NextStateCaseWrapper(RMAD_ERROR_REQUEST_INVALID);
  }

  if (running_setup_instruction_ == RMAD_CALIBRATION_INSTRUCTION_UNKNOWN) {
    LOG(ERROR) << "The setup instruction is missing.";
    return NextStateCaseWrapper(RmadState::StateCase::kCheckCalibration);
  }

  // kWipeDevice should be set by previous states.
  bool wipe_device;
  if (!json_store_->GetValue(kWipeDevice, &wipe_device)) {
    LOG(ERROR) << "Variable " << kWipeDevice << " not found";
    return NextStateCaseWrapper(RMAD_ERROR_TRANSITION_FAILED);
  }

  if (running_setup_instruction_ ==
      RMAD_CALIBRATION_INSTRUCTION_NO_NEED_CALIBRATION) {
    if (wipe_device) {
      return NextStateCaseWrapper(RmadState::StateCase::kFinalize);
    } else {
      return NextStateCaseWrapper(RmadState::StateCase::kWpEnablePhysical);
    }
  }

  if (running_setup_instruction_ ==
      RMAD_CALIBRATION_INSTRUCTION_NEED_TO_CHECK) {
    return NextStateCaseWrapper(RmadState::StateCase::kCheckCalibration);
  }

  json_store_->SetValue(
      kCalibrationInstruction,
      CalibrationSetupInstruction_Name(running_setup_instruction_));
  RecordCalibrationSetupInstructionToLogs(json_store_,
                                          running_setup_instruction_);
  return NextStateCaseWrapper(RmadState::StateCase::kRunCalibration);
}

BaseStateHandler::GetNextStateCaseReply
SetupCalibrationStateHandler::TryGetNextStateCaseAtBoot() {
  if (running_setup_instruction_ ==
      RMAD_CALIBRATION_INSTRUCTION_NEED_TO_CHECK) {
    return NextStateCaseWrapper(RmadState::StateCase::kCheckCalibration);
  } else {
    return NextStateCaseWrapper(RMAD_ERROR_TRANSITION_FAILED);
  }
}

}  // namespace rmad
