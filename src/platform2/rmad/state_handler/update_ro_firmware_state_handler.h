// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RMAD_STATE_HANDLER_UPDATE_RO_FIRMWARE_STATE_HANDLER_H_
#define RMAD_STATE_HANDLER_UPDATE_RO_FIRMWARE_STATE_HANDLER_H_

#include "rmad/state_handler/base_state_handler.h"

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <base/memory/scoped_refptr.h>
#include <base/sequence_checker.h>
#include <base/task/task_runner.h>
#include <base/timer/timer.h>

#include "rmad/proto_bindings/rmad.pb.h"
#include "rmad/system/power_manager_client.h"
#include "rmad/udev/udev_utils.h"
#include "rmad/utils/cmd_utils.h"
#include "rmad/utils/write_protect_utils.h"

namespace rmad {

class UpdateRoFirmwareStateHandler : public BaseStateHandler {
 public:
  // Report firmware update status every second.
  static constexpr base::TimeDelta kSignalInterval = base::Seconds(1);

  // Check USB status every 2 seconds.
  static constexpr base::TimeDelta kPollInterval = base::Seconds(2);

  // Wait for 3 second before rebooting.
  static constexpr base::TimeDelta kRebootDelay = base::Seconds(3);

  explicit UpdateRoFirmwareStateHandler(
      scoped_refptr<JsonStore> json_store,
      scoped_refptr<DaemonCallback> daemon_callback);
  // Used to inject mock |udev_utils_|, |cmd_utils_|, |write_protect_utils|,
  // and |power_manager_client_| for testing.
  explicit UpdateRoFirmwareStateHandler(
      scoped_refptr<JsonStore> json_store,
      scoped_refptr<DaemonCallback> daemon_callback,
      std::unique_ptr<UdevUtils> udev_utils,
      std::unique_ptr<CmdUtils> cmd_utils,
      std::unique_ptr<WriteProtectUtils> write_protect_utils,
      std::unique_ptr<PowerManagerClient> power_manager_client);

  ASSIGN_STATE(RmadState::StateCase::kUpdateRoFirmware);
  SET_REPEATABLE;

  RmadErrorCode InitializeState() override;
  void RunState() override;
  void CleanUpState() override;
  GetNextStateCaseReply GetNextStateCase(const RmadState& state) override;

 protected:
  ~UpdateRoFirmwareStateHandler() override = default;

 private:
  void StartSignalTimer();
  void StopSignalTimer();
  void StartPollingTimer();
  void StopPollingTimer();

  bool CanSkipUpdate();

  void SendFirmwareUpdateSignal();
  std::vector<std::unique_ptr<UdevDevice>> GetRemovableBlockDevices() const;
  void WaitUsb();
  void OnCopyCompleted(bool copy_success);
  void OnCopySuccess();
  void OnUpdateCompleted(bool update_success);
  bool RunFirmwareUpdater();

  // Functions for rebooting.
  void PostRebootTask();
  void Reboot();

  // True if the class is not initialized with default constructor.
  bool is_mocked_;

  // All accesses to |status_|, |usb_detected_| and timers should be on the same
  // sequence.
  SEQUENCE_CHECKER(sequence_checker_);
  UpdateRoFirmwareStatus status_;
  bool usb_detected_;
  // Timer for sending status signals.
  base::RepeatingTimer status_signal_timer_;
  // Timer for checking USB.
  base::RepeatingTimer check_usb_timer_;

  std::unique_ptr<UdevUtils> udev_utils_;
  std::unique_ptr<CmdUtils> cmd_utils_;
  std::unique_ptr<WriteProtectUtils> write_protect_utils_;
  std::unique_ptr<PowerManagerClient> power_manager_client_;

  // Sequence runner for thread-safe read/write of |status_| and
  // |usb_detected_|.
  scoped_refptr<base::SequencedTaskRunner> sequenced_task_runner_;
  // Task runner for firmware updater.
  scoped_refptr<base::TaskRunner> updater_task_runner_;
};

}  // namespace rmad

#endif  // RMAD_STATE_HANDLER_UPDATE_RO_FIRMWARE_STATE_HANDLER_H_
