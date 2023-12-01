// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RMAD_STATE_HANDLER_WRITE_PROTECT_DISABLE_PHYSICAL_STATE_HANDLER_H_
#define RMAD_STATE_HANDLER_WRITE_PROTECT_DISABLE_PHYSICAL_STATE_HANDLER_H_

#include "rmad/state_handler/base_state_handler.h"

#include <memory>
#include <utility>

#include <base/files/file_path.h>
#include <base/timer/timer.h>

#include "rmad/utils/cr50_utils.h"
#include "rmad/utils/crossystem_utils.h"
#include "rmad/utils/write_protect_utils.h"

namespace rmad {

class WriteProtectDisablePhysicalStateHandler : public BaseStateHandler {
 public:
  // Poll every 2 seconds.
  static constexpr base::TimeDelta kPollInterval = base::Seconds(2);
  // Wait for 3 seconds between enabling factory mode and rebooting.
  // Enabling factory mode can take up to 2 seconds. Wait for at least 3 seconds
  // to be safe.
  static constexpr base::TimeDelta kRebootDelay = base::Seconds(3);

  explicit WriteProtectDisablePhysicalStateHandler(
      scoped_refptr<JsonStore> json_store,
      scoped_refptr<DaemonCallback> daemon_callback);
  // Used to inject mock |cr50_utils_|, |crossystem_utils_|, and
  // |write_protect_utils_| for testing.
  explicit WriteProtectDisablePhysicalStateHandler(
      scoped_refptr<JsonStore> json_store,
      scoped_refptr<DaemonCallback> daemon_callback,
      const base::FilePath& working_dir_path,
      std::unique_ptr<Cr50Utils> cr50_utils,
      std::unique_ptr<CrosSystemUtils> crossystem_utils,
      std::unique_ptr<WriteProtectUtils> write_protect_utils);

  ASSIGN_STATE(RmadState::StateCase::kWpDisablePhysical);
  SET_REPEATABLE;

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
  ~WriteProtectDisablePhysicalStateHandler() override = default;

 private:
  bool IsReadyForTransition() const;
  bool IsEcRebooted() const;
  bool IsHwwpDisabled() const;
  bool CanSkipEnablingFactoryMode() const;
  void CheckWriteProtectOffTask();
  void OnWriteProtectDisabled();
  void RequestRmaPowerwashAndRebootEc();
  void RequestRmaPowerwashAndRebootEcCallback(bool success);
  void RebootEc();
  void RebootEcCallback(bool success);

  base::FilePath working_dir_path_;

  base::OneShotTimer reboot_timer_;
  base::RepeatingTimer signal_timer_;

  std::unique_ptr<Cr50Utils> cr50_utils_;
  std::unique_ptr<CrosSystemUtils> crossystem_utils_;
  std::unique_ptr<WriteProtectUtils> write_protect_utils_;
};

}  // namespace rmad

#endif  // RMAD_STATE_HANDLER_WRITE_PROTECT_DISABLE_PHYSICAL_STATE_HANDLER_H_
