// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RMAD_STATE_HANDLER_RUN_CALIBRATION_STATE_HANDLER_H_
#define RMAD_STATE_HANDLER_RUN_CALIBRATION_STATE_HANDLER_H_

#include "rmad/state_handler/base_state_handler.h"

#include <map>
#include <memory>
#include <string>
#include <utility>

#include <base/memory/ref_counted.h>
#include <base/memory/scoped_refptr.h>
#include <base/task/sequenced_task_runner.h>
#include <base/task/task_runner.h>
#include <base/timer/timer.h>

#include "rmad/utils/calibration_utils.h"
#include "rmad/utils/mojo_service_utils.h"
#include "rmad/utils/sensor_calibration_utils.h"
#include "rmad/utils/vpd_utils_impl.h"

namespace rmad {

class RunCalibrationStateHandler : public BaseStateHandler {
 public:
  // Poll every 2 seconds.
  static constexpr base::TimeDelta kPollInterval = base::Seconds(2);

  explicit RunCalibrationStateHandler(
      scoped_refptr<JsonStore> json_store,
      scoped_refptr<DaemonCallback> daemon_callback);

  // Used to inject |base_acc_utils|, |lid_acc_utils|, |base_gyro_utils|, and
  // |lid_gyro_utils| to mock |sensor_calibration_utils_map_| for testing.
  explicit RunCalibrationStateHandler(
      scoped_refptr<JsonStore> json_store,
      scoped_refptr<DaemonCallback> daemon_callback,
      std::unique_ptr<SensorCalibrationUtils> base_acc_utils,
      std::unique_ptr<SensorCalibrationUtils> lid_acc_utils,
      std::unique_ptr<SensorCalibrationUtils> base_gyro_utils,
      std::unique_ptr<SensorCalibrationUtils> lid_gyro_utils,
      std::unique_ptr<VpdUtils> vpd_utils);

  ASSIGN_STATE(RmadState::StateCase::kRunCalibration);
  SET_REPEATABLE;

  RmadErrorCode InitializeState() override;
  void CleanUpState() override;
  GetNextStateCaseReply GetNextStateCase(const RmadState& state) override;
  GetNextStateCaseReply TryGetNextStateCaseAtBoot() override;

 protected:
  ~RunCalibrationStateHandler() override = default;

 private:
  bool RetrieveVarsAndCalibrate();
  void CalibrateAndSendProgress(RmadComponent component);
  void UpdateCalibrationProgress(CalibrationComponentStatus component_status);
  void UpdateCalibrationResult(const std::map<std::string, int>& result);

  void HandleMojoServiceDisconnection();
  void SaveAndSend(CalibrationComponentStatus component_status);
  void SendComponentSignal(CalibrationComponentStatus component_status);
  void SendOverallSignal(CalibrationOverallStatus overall_status);

  // To ensure that calibration starts from a higher priority, we use an
  // ordered map to traverse it with its number of the setup instruction.
  // Once we find the first sensor to be calibrated, we only calibrate those
  // sensors that have the same setup instruction as it.
  InstructionCalibrationStatusMap calibration_map_;
  // The instruction that has been setup in previous handler.
  CalibrationSetupInstruction setup_instruction_;
  // The instruction that we are going to calibrate (might be the same as the
  // setup instruction when this cycle has not completed or the next instruction
  // after the current cycle has completed).
  CalibrationSetupInstruction running_instruction_;

  // For each sensor, we should have its own utils to run calibration and poll
  // progress.
  std::map<RmadComponent, std::unique_ptr<SensorCalibrationUtils>>
      sensor_calibration_utils_map_;
  // To prevent race conditions, we post all critical sections to the same
  // SequencedTaskRunner to execute operations sequentially.
  scoped_refptr<base::SequencedTaskRunner> sequenced_task_runner_;
  SEQUENCE_CHECKER(sequence_checker_);
  std::unique_ptr<VpdUtils> vpd_utils_;
  scoped_refptr<MojoServiceUtilsImpl> mojo_service_;
  bool current_round_finished_;
  bool is_testing_ = false;

  base::WeakPtrFactory<RunCalibrationStateHandler> weak_factory_{this};
};

}  // namespace rmad

#endif  // RMAD_STATE_HANDLER_RUN_CALIBRATION_STATE_HANDLER_H_
