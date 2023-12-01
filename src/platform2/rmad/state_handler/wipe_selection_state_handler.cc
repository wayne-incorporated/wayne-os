// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "rmad/state_handler/wipe_selection_state_handler.h"

#include <memory>
#include <utility>

#include <base/files/file_path.h>
#include <base/logging.h>

#include "rmad/constants.h"
#include "rmad/logs/logs_utils.h"
#include "rmad/utils/write_protect_utils_impl.h"

namespace rmad {

WipeSelectionStateHandler::WipeSelectionStateHandler(
    scoped_refptr<JsonStore> json_store,
    scoped_refptr<DaemonCallback> daemon_callback)
    : BaseStateHandler(json_store, daemon_callback) {
  write_protect_utils_ = std::make_unique<WriteProtectUtilsImpl>();
}

WipeSelectionStateHandler::WipeSelectionStateHandler(
    scoped_refptr<JsonStore> json_store,
    scoped_refptr<DaemonCallback> daemon_callback,
    std::unique_ptr<WriteProtectUtils> write_protect_utils)
    : BaseStateHandler(json_store, daemon_callback),
      write_protect_utils_(std::move(write_protect_utils)) {}

RmadErrorCode WipeSelectionStateHandler::InitializeState() {
  if (!state_.has_wipe_selection()) {
    state_.set_allocated_wipe_selection(new WipeSelectionState);
  }

  if (!InitializeVarsFromStateFile()) {
    return RMAD_ERROR_STATE_HANDLER_INITIALIZATION_FAILED;
  }

  return RMAD_ERROR_OK;
}

bool WipeSelectionStateHandler::InitializeVarsFromStateFile() {
  // json_store should contain the following keys set by |DeviceDestination|:
  // - kSameOwner
  // - kWpDisableRequired
  // - kCcdBlocked (only required when kWpDisableRequired is true)
  bool same_owner;
  if (!json_store_->GetValue(kSameOwner, &same_owner)) {
    LOG(ERROR) << "Variable " << kSameOwner << " not found";
    return false;
  }
  if (!json_store_->GetValue(kWpDisableRequired, &wp_disable_required_)) {
    LOG(ERROR) << "Variable " << kWpDisableRequired << " not found";
    return false;
  }
  if (wp_disable_required_ &&
      !json_store_->GetValue(kCcdBlocked, &ccd_blocked_)) {
    LOG(ERROR) << "Variable " << kCcdBlocked << " not found";
    return false;
  }

  // We should not see "different owner" in this state, because we always wipe
  // the device if it's going to a different owner.
  if (!same_owner) {
    LOG(ERROR) << "Device is going to a different owner. "
               << "We should always wipe the device";
    return false;
  }

  return true;
}

BaseStateHandler::GetNextStateCaseReply
WipeSelectionStateHandler::GetNextStateCase(const RmadState& state) {
  if (!state.has_wipe_selection()) {
    LOG(ERROR) << "RmadState missing |wipe selection| state.";
    return NextStateCaseWrapper(RMAD_ERROR_REQUEST_INVALID);
  }

  state_ = state;

  // There are 5 paths:
  // 1. Same owner + WP disabling required + CCD blocked + wipe device:
  //    Go to kWpDisableRsu state.
  // 2. Same owner + Wp disabling required + CCD blocked + don't wipe device:
  //    Go to kWpDisablePhysical state.
  // 3. Same owner + WP disabling required + CCD not blocked + wipe device:
  //    Go to kWpDisableMethod state.
  // 4. Same owner + WP disabling required + CCD not blocked + don't wipe
  //    device:
  //    Go to kWpDisablePhysical state.
  // 5. Same owner + WP disabling not required:
  //    Go to kFinalize state.
  bool wipe_device = state_.wipe_selection().wipe_device();
  json_store_->SetValue(kWipeDevice, wipe_device);
  RecordWipeDeviceToLogs(json_store_, wipe_device);
  RmadState::StateCase next_state = RmadState::StateCase::STATE_NOT_SET;
  if (wp_disable_required_) {
    if (ccd_blocked_) {
      if (wipe_device) {
        // Case 1.
        next_state = RmadState::StateCase::kWpDisableRsu;
      } else {
        // Case 2.
        next_state = RmadState::StateCase::kWpDisablePhysical;
      }
    } else {
      if (wipe_device) {
        // Case 3.
        // If HWWP is already disabled, assume the user will select the physical
        // method and go directly to WpDisablePhysical state. Otherwise, let the
        // user choose between physical method or RSU.
        if (bool hwwp_enabled;
            write_protect_utils_->GetHardwareWriteProtectionStatus(
                &hwwp_enabled) &&
            !hwwp_enabled) {
          next_state = RmadState::StateCase::kWpDisablePhysical;
        } else {
          next_state = RmadState::StateCase::kWpDisableMethod;
        }
      } else {
        // Case 4.
        next_state = RmadState::StateCase::kWpDisablePhysical;
      }
    }
  } else {
    // Case 5.
    next_state = RmadState::StateCase::kFinalize;
  }

  return NextStateCaseWrapper(next_state);
}

}  // namespace rmad
