// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RMAD_STATE_HANDLER_FINALIZE_STATE_HANDLER_H_
#define RMAD_STATE_HANDLER_FINALIZE_STATE_HANDLER_H_

#include "rmad/state_handler/base_state_handler.h"

#include <memory>
#include <utility>

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/memory/scoped_refptr.h>
#include <base/task/sequenced_task_runner.h>
#include <base/timer/timer.h>

#include "rmad/utils/cr50_utils.h"
#include "rmad/utils/write_protect_utils.h"

namespace rmad {

class FinalizeStateHandler : public BaseStateHandler {
 public:
  // Report status every second.
  static constexpr base::TimeDelta kReportStatusInterval = base::Seconds(1);

  explicit FinalizeStateHandler(scoped_refptr<JsonStore> json_store,
                                scoped_refptr<DaemonCallback> daemon_callback);
  // Used to inject |working_dir_path_|,  |cr50_utils_|, and
  // |write_protect_utils_| for testing.
  explicit FinalizeStateHandler(
      scoped_refptr<JsonStore> json_store,
      scoped_refptr<DaemonCallback> daemon_callback,
      const base::FilePath& working_dir_path,
      std::unique_ptr<Cr50Utils> cr50_utils,
      std::unique_ptr<WriteProtectUtils> write_protect_utils);

  ASSIGN_STATE(RmadState::StateCase::kFinalize);
  SET_UNREPEATABLE;

  RmadErrorCode InitializeState() override;
  void RunState() override;
  void CleanUpState() override;
  GetNextStateCaseReply GetNextStateCase(const RmadState& state) override;

 protected:
  ~FinalizeStateHandler() override = default;

 private:
  void SendStatusSignal();
  void StartStatusTimer();
  void StopStatusTimer();

  void StartFinalize();
  void FinalizeTask();

  base::FilePath working_dir_path_;
  FinalizeStatus status_;

  std::unique_ptr<Cr50Utils> cr50_utils_;
  std::unique_ptr<WriteProtectUtils> write_protect_utils_;
  base::RepeatingTimer status_timer_;
  scoped_refptr<base::SequencedTaskRunner> task_runner_;
};

}  // namespace rmad

#endif  // RMAD_STATE_HANDLER_FINALIZE_STATE_HANDLER_H_
