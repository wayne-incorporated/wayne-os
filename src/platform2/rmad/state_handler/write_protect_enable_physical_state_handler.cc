// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "rmad/state_handler/write_protect_enable_physical_state_handler.h"

#include <memory>
#include <utility>

#include <base/files/file_path.h>

#include "rmad/utils/write_protect_utils_impl.h"

#include <base/logging.h>

namespace rmad {

WriteProtectEnablePhysicalStateHandler::WriteProtectEnablePhysicalStateHandler(
    scoped_refptr<JsonStore> json_store,
    scoped_refptr<DaemonCallback> daemon_callback)
    : BaseStateHandler(json_store, daemon_callback) {
  write_protect_utils_ = std::make_unique<WriteProtectUtilsImpl>();
}

WriteProtectEnablePhysicalStateHandler::WriteProtectEnablePhysicalStateHandler(
    scoped_refptr<JsonStore> json_store,
    scoped_refptr<DaemonCallback> daemon_callback,
    std::unique_ptr<WriteProtectUtils> write_protect_utils)
    : BaseStateHandler(json_store, daemon_callback),
      write_protect_utils_(std::move(write_protect_utils)) {}

RmadErrorCode WriteProtectEnablePhysicalStateHandler::InitializeState() {
  if (!state_.has_wp_enable_physical() && !RetrieveState()) {
    state_.set_allocated_wp_enable_physical(
        new WriteProtectEnablePhysicalState);
    // Enable SWWP when entering the state for the first time.
    if (!write_protect_utils_->EnableSoftwareWriteProtection()) {
      LOG(ERROR) << "Failed to enable software write protection";
      return RMAD_ERROR_STATE_HANDLER_INITIALIZATION_FAILED;
    }
    StoreState();
  }

  return RMAD_ERROR_OK;
}

void WriteProtectEnablePhysicalStateHandler::RunState() {
  DLOG(INFO) << "Start polling write protection";
  if (timer_.IsRunning()) {
    timer_.Stop();
  }
  timer_.Start(
      FROM_HERE, kPollInterval, this,
      &WriteProtectEnablePhysicalStateHandler::CheckWriteProtectOnTask);
}

void WriteProtectEnablePhysicalStateHandler::CleanUpState() {
  // Stop the polling loop.
  if (timer_.IsRunning()) {
    timer_.Stop();
  }
}

BaseStateHandler::GetNextStateCaseReply
WriteProtectEnablePhysicalStateHandler::GetNextStateCase(
    const RmadState& state) {
  if (!state.has_wp_enable_physical()) {
    LOG(ERROR) << "RmadState missing |write protection enable| state.";
    return NextStateCaseWrapper(RMAD_ERROR_REQUEST_INVALID);
  }

  bool hwwp_enabled;
  if (write_protect_utils_->GetHardwareWriteProtectionStatus(&hwwp_enabled) &&
      hwwp_enabled) {
    return NextStateCaseWrapper(RmadState::StateCase::kFinalize);
  }
  return NextStateCaseWrapper(RMAD_ERROR_WAIT);
}

void WriteProtectEnablePhysicalStateHandler::CheckWriteProtectOnTask() {
  VLOG(1) << "Check write protection";

  bool hwwp_enabled;
  if (!write_protect_utils_->GetHardwareWriteProtectionStatus(&hwwp_enabled)) {
    LOG(ERROR) << "Failed to get HWWP status";
    return;
  }
  if (hwwp_enabled) {
    daemon_callback_->GetWriteProtectSignalCallback().Run(true);
    timer_.Stop();
  }
}

}  // namespace rmad
