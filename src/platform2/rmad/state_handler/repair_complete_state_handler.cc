// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "rmad/state_handler/repair_complete_state_handler.h"

#include <memory>
#include <utility>
#include <vector>

#include <base/files/file_path.h>
#include <base/logging.h>

#include "rmad/constants.h"
#include "rmad/metrics/metrics_utils_impl.h"
#include "rmad/system/power_manager_client_impl.h"
#include "rmad/udev/udev_device.h"
#include "rmad/udev/udev_utils.h"
#include "rmad/utils/crossystem_utils_impl.h"
#include "rmad/utils/dbus_utils.h"
#include "rmad/utils/sys_utils_impl.h"

namespace rmad {

RepairCompleteStateHandler::RepairCompleteStateHandler(
    scoped_refptr<JsonStore> json_store,
    scoped_refptr<DaemonCallback> daemon_callback)
    : BaseStateHandler(json_store, daemon_callback),
      working_dir_path_(kDefaultWorkingDirPath),
      unencrypted_preserve_path_(kDefaultUnencryptedPreservePath),
      locked_error_(RMAD_ERROR_NOT_SET) {
  power_manager_client_ =
      std::make_unique<PowerManagerClientImpl>(GetSystemBus());
  udev_utils_ = std::make_unique<UdevUtilsImpl>();
  crossystem_utils_ = std::make_unique<CrosSystemUtilsImpl>();
  sys_utils_ = std::make_unique<SysUtilsImpl>();
  metrics_utils_ = std::make_unique<MetricsUtilsImpl>();
}

RepairCompleteStateHandler::RepairCompleteStateHandler(
    scoped_refptr<JsonStore> json_store,
    scoped_refptr<DaemonCallback> daemon_callback,
    const base::FilePath& working_dir_path,
    const base::FilePath& unencrypted_preserve_path,
    std::unique_ptr<PowerManagerClient> power_manager_client,
    std::unique_ptr<UdevUtils> udev_utils,
    std::unique_ptr<CrosSystemUtils> crossystem_utils,
    std::unique_ptr<SysUtils> sys_utils,
    std::unique_ptr<MetricsUtils> metrics_utils)
    : BaseStateHandler(json_store, daemon_callback),
      working_dir_path_(working_dir_path),
      unencrypted_preserve_path_(unencrypted_preserve_path),
      power_manager_client_(std::move(power_manager_client)),
      udev_utils_(std::move(udev_utils)),
      crossystem_utils_(std::move(crossystem_utils)),
      sys_utils_(std::move(sys_utils)),
      metrics_utils_(std::move(metrics_utils)),
      locked_error_(RMAD_ERROR_NOT_SET) {}

RmadErrorCode RepairCompleteStateHandler::InitializeState() {
  if (!state_.has_repair_complete() && !RetrieveState()) {
    auto repair_complete = std::make_unique<RepairCompleteState>();
    // kWipeDevice should be set by previous states.
    bool wipe_device;
    if (!json_store_->GetValue(kWipeDevice, &wipe_device)) {
      LOG(ERROR) << "Variable " << kWipeDevice << " not found";
      return RMAD_ERROR_STATE_HANDLER_INITIALIZATION_FAILED;
    }
    repair_complete->set_powerwash_required(wipe_device);
    state_.set_allocated_repair_complete(repair_complete.release());
    // Record the current powerwash count during initialization.
    StorePowerwashCount(unencrypted_preserve_path_);
  }

  // Check if powerwash is actually required.
  if (IsPowerwashComplete(unencrypted_preserve_path_) ||
      IsPowerwashDisabled(working_dir_path_)) {
    state_.mutable_repair_complete()->set_powerwash_required(false);
  }

  return RMAD_ERROR_OK;
}

void RepairCompleteStateHandler::RunState() {
  signal_timer_.Start(FROM_HERE, kSignalInterval, this,
                      &RepairCompleteStateHandler::SendSignals);
}

void RepairCompleteStateHandler::CleanUpState() {
  signal_timer_.Stop();
}

BaseStateHandler::GetNextStateCaseReply
RepairCompleteStateHandler::GetNextStateCase(const RmadState& state) {
  if (!state.has_repair_complete()) {
    LOG(ERROR) << "RmadState missing |repair_complete| state.";
    return NextStateCaseWrapper(RMAD_ERROR_REQUEST_INVALID);
  }
  if (state.repair_complete().shutdown() ==
      RepairCompleteState::RMAD_REPAIR_COMPLETE_UNKNOWN) {
    return NextStateCaseWrapper(RMAD_ERROR_REQUEST_ARGS_MISSING);
  }
  if (state.repair_complete().powerwash_required() !=
      state_.repair_complete().powerwash_required()) {
    return NextStateCaseWrapper(RMAD_ERROR_REQUEST_ARGS_VIOLATION);
  }
  if (locked_error_ != RMAD_ERROR_NOT_SET) {
    return NextStateCaseWrapper(locked_error_);
  }

  state_ = state;
  StoreState();

  // If powerwash is required, request a powerwash and reboot.
  if (state_.repair_complete().powerwash_required()) {
    RequestRmaPowerwash();
    return NextStateCaseWrapper(GetStateCase(), RMAD_ERROR_EXPECT_REBOOT,
                                RMAD_ADDITIONAL_ACTIVITY_REBOOT);
  }

  // Exit RMA.
  return ExitRma();
}

BaseStateHandler::GetNextStateCaseReply
RepairCompleteStateHandler::TryGetNextStateCaseAtBoot() {
  // Exit RMA only if the user has selected a shutdown option before the reboot,
  // and powerwash is no longer required.
  if (state_.repair_complete().shutdown() !=
          RepairCompleteState::RMAD_REPAIR_COMPLETE_UNKNOWN &&
      !state_.repair_complete().powerwash_required()) {
    return ExitRma();
  }

  // Otherwise, stay on the same state.
  return NextStateCaseWrapper(GetStateCase());
}

BaseStateHandler::GetNextStateCaseReply RepairCompleteStateHandler::ExitRma() {
  // Clear the state file and shutdown/reboot/cutoff if the device doesn't
  // need to do a powerwash, or a powerwash is already done.
  if (!MetricsUtils::UpdateStateMetricsOnStateTransition(
          json_store_, GetStateCase(), RmadState::STATE_NOT_SET,
          base::Time::Now().ToDoubleT()) ||
      !MetricsUtils::SetMetricsValue(json_store_, kMetricsIsComplete, true) ||
      !metrics_utils_->RecordAll(json_store_)) {
    LOG(ERROR) << "RepairCompleteState: Failed to record metrics to the file";
    // TODO(genechang): We should block here if the metrics library is ready.
  }

  if (!json_store_->ClearAndDeleteFile()) {
    LOG(ERROR) << "RepairCompleteState: Failed to clear RMA state file";
    return NextStateCaseWrapper(RMAD_ERROR_CANNOT_WRITE);
  }

  switch (state_.repair_complete().shutdown()) {
    case RepairCompleteState::RMAD_REPAIR_COMPLETE_REBOOT:
      // Wait for a while before reboot.
      action_timer_.Start(FROM_HERE, kShutdownDelay, this,
                          &RepairCompleteStateHandler::Reboot);
      locked_error_ = RMAD_ERROR_EXPECT_REBOOT;
      break;
    case RepairCompleteState::RMAD_REPAIR_COMPLETE_SHUTDOWN:
      // Wait for a while before shutdown.
      action_timer_.Start(FROM_HERE, kShutdownDelay, this,
                          &RepairCompleteStateHandler::Shutdown);
      locked_error_ = RMAD_ERROR_EXPECT_SHUTDOWN;
      break;
    case RepairCompleteState::RMAD_REPAIR_COMPLETE_BATTERY_CUTOFF:
      // Wait for a while before cutoff.
      action_timer_.Start(FROM_HERE, kShutdownDelay, this,
                          &RepairCompleteStateHandler::RequestBatteryCutoff);
      locked_error_ = RMAD_ERROR_EXPECT_SHUTDOWN;
      break;
    default:
      break;
  }
  CHECK(locked_error_ != RMAD_ERROR_NOT_SET);
  return NextStateCaseWrapper(locked_error_);
}

void RepairCompleteStateHandler::RequestRmaPowerwash() {
  DLOG(INFO) << "Requesting RMA mode powerwash";
  daemon_callback_->GetExecuteRequestRmaPowerwashCallback().Run(
      base::BindOnce(&RepairCompleteStateHandler::RequestRmaPowerwashCallback,
                     base::Unretained(this)));
}

void RepairCompleteStateHandler::RequestRmaPowerwashCallback(bool success) {
  if (!success) {
    LOG(ERROR) << "Failed to request RMA mode powerwash";
  }
  action_timer_.Start(FROM_HERE, kShutdownDelay, this,
                      &RepairCompleteStateHandler::Reboot);
}

void RepairCompleteStateHandler::RequestBatteryCutoff() {
  DLOG(INFO) << "Requesting battery cutoff";
  daemon_callback_->GetExecuteRequestBatteryCutoffCallback().Run(
      base::BindOnce(&RepairCompleteStateHandler::RequestBatteryCutoffCallback,
                     base::Unretained(this)));
}

void RepairCompleteStateHandler::RequestBatteryCutoffCallback(bool success) {
  if (!success) {
    LOG(ERROR) << "Failed to request battery cutoff";
  }
  // Battery cutoff requires a reboot (not shutdown) after the request.
  if (!power_manager_client_->Restart()) {
    LOG(ERROR) << "Failed to reboot";
  }
}

void RepairCompleteStateHandler::Reboot() {
  DLOG(INFO) << "RMA flow complete. Rebooting.";
  if (!power_manager_client_->Restart()) {
    LOG(ERROR) << "Failed to reboot";
  }
}

void RepairCompleteStateHandler::Shutdown() {
  DLOG(INFO) << "RMA flow complete. Shutting down.";
  if (!power_manager_client_->Shutdown()) {
    LOG(ERROR) << "Failed to shut down";
  }
}

bool RepairCompleteStateHandler::IsExternalDiskDetected() {
  std::vector<std::unique_ptr<UdevDevice>> devices =
      udev_utils_->EnumerateBlockDevices();
  for (const auto& device : devices) {
    if (device->IsRemovable()) {
      return true;
    }
  }
  return false;
}

void RepairCompleteStateHandler::SendSignals() {
  daemon_callback_->GetPowerCableSignalCallback().Run(
      sys_utils_->IsPowerSourcePresent());
  daemon_callback_->GetExternalDiskSignalCallback().Run(
      IsExternalDiskDetected());
}

}  // namespace rmad
