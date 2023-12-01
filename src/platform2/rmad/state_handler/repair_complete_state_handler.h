// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RMAD_STATE_HANDLER_REPAIR_COMPLETE_STATE_HANDLER_H_
#define RMAD_STATE_HANDLER_REPAIR_COMPLETE_STATE_HANDLER_H_

#include "rmad/state_handler/base_state_handler.h"

#include <memory>
#include <utility>

#include <base/files/file_path.h>
#include <base/timer/timer.h>

#include "rmad/metrics/metrics_utils.h"
#include "rmad/system/power_manager_client.h"
#include "rmad/udev/udev_utils.h"
#include "rmad/utils/crossystem_utils.h"
#include "rmad/utils/sys_utils.h"

namespace rmad {

class RepairCompleteStateHandler : public BaseStateHandler {
 public:
  // Wait for 3 seconds before reboot/shutdown/cutoff.
  static constexpr base::TimeDelta kShutdownDelay = base::Seconds(3);
  // Report power cable and external disk state every second.
  static constexpr base::TimeDelta kSignalInterval = base::Seconds(1);

  explicit RepairCompleteStateHandler(
      scoped_refptr<JsonStore> json_store,
      scoped_refptr<DaemonCallback> daemon_callback);
  // Used to inject |working_dir_path_| and |unencrypted_preserve_path|, and
  // mocked |power_manager_client_|, |udev_utils_|, |crossystem_utils_|,
  // |sys_utils_| and |metrics_utils_| for testing.
  explicit RepairCompleteStateHandler(
      scoped_refptr<JsonStore> json_store,
      scoped_refptr<DaemonCallback> daemon_callback,
      const base::FilePath& working_dir_path,
      const base::FilePath& unencrypted_preserve_path,
      std::unique_ptr<PowerManagerClient> power_manager_client,
      std::unique_ptr<UdevUtils> udev_utils,
      std::unique_ptr<CrosSystemUtils> crossystem_utils,
      std::unique_ptr<SysUtils> sys_utils,
      std::unique_ptr<MetricsUtils> metrics_utils);

  ASSIGN_STATE(RmadState::StateCase::kRepairComplete);
  SET_UNREPEATABLE;

  RmadErrorCode InitializeState() override;
  void RunState() override;
  void CleanUpState() override;
  GetNextStateCaseReply GetNextStateCase(const RmadState& state) override;

  // Try to auto-transition at boot.
  GetNextStateCaseReply TryGetNextStateCaseAtBoot() override;

  // Override powerwash function. Allow disabling powerwash if running in a
  // debug build.
  bool CanDisablePowerwash() const override {
    int cros_debug;
    return crossystem_utils_->GetCrosDebug(&cros_debug) && cros_debug == 1;
  }

 protected:
  ~RepairCompleteStateHandler() override = default;

 private:
  GetNextStateCaseReply ExitRma();
  void RequestRmaPowerwash();
  void RequestRmaPowerwashCallback(bool success);
  void RequestBatteryCutoff();
  void RequestBatteryCutoffCallback(bool success);
  void Reboot();
  void Shutdown();

  bool IsExternalDiskDetected();
  void SendSignals();

  base::FilePath working_dir_path_;
  base::FilePath unencrypted_preserve_path_;

  base::RepeatingTimer signal_timer_;

  std::unique_ptr<PowerManagerClient> power_manager_client_;
  std::unique_ptr<UdevUtils> udev_utils_;
  std::unique_ptr<CrosSystemUtils> crossystem_utils_;
  std::unique_ptr<SysUtils> sys_utils_;
  std::unique_ptr<MetricsUtils> metrics_utils_;

  // If |locked_error_| is set, always return it in |GetNextStateCase|.
  RmadErrorCode locked_error_;

  base::OneShotTimer action_timer_;
};

}  // namespace rmad

#endif  // RMAD_STATE_HANDLER_REPAIR_COMPLETE_STATE_HANDLER_H_
