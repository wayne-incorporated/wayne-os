// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RMAD_STATE_HANDLER_SETUP_CALIBRATION_STATE_HANDLER_H_
#define RMAD_STATE_HANDLER_SETUP_CALIBRATION_STATE_HANDLER_H_

#include "rmad/state_handler/base_state_handler.h"

#include <memory>
#include <utility>

#include <base/timer/timer.h>

#include "rmad/utils/calibration_utils.h"

namespace rmad {

class SetupCalibrationStateHandler : public BaseStateHandler {
 public:
  explicit SetupCalibrationStateHandler(
      scoped_refptr<JsonStore> json_store,
      scoped_refptr<DaemonCallback> daemon_callback);

  ASSIGN_STATE(RmadState::StateCase::kSetupCalibration);
  SET_REPEATABLE;

  RmadErrorCode InitializeState() override;
  GetNextStateCaseReply GetNextStateCase(const RmadState& state) override;
  GetNextStateCaseReply TryGetNextStateCaseAtBoot() override;

 protected:
  ~SetupCalibrationStateHandler() override = default;

 private:
  // To ensure that calibration starts from a higher priority, we use an
  // ordered map to traverse it with it's number of the setup instruction.
  // Once we find the first sensor to be calibrated, we only calibrate those
  // sensors that have the same setup instruction as it.
  InstructionCalibrationStatusMap calibration_map_;
  CalibrationSetupInstruction running_setup_instruction_;
};

}  // namespace rmad

#endif  // RMAD_STATE_HANDLER_SETUP_CALIBRATION_STATE_HANDLER_H_
