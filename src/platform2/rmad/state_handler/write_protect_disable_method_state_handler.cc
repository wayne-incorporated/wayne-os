// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "rmad/state_handler/write_protect_disable_method_state_handler.h"

#include <memory>
#include <utility>

#include <base/files/file_path.h>
#include <base/logging.h>
#include <base/notreached.h>

#include "rmad/constants.h"
#include "rmad/logs/logs_utils.h"
#include "rmad/utils/cr50_utils_impl.h"

namespace rmad {

WriteProtectDisableMethodStateHandler::WriteProtectDisableMethodStateHandler(
    scoped_refptr<JsonStore> json_store,
    scoped_refptr<DaemonCallback> daemon_callback)
    : BaseStateHandler(json_store, daemon_callback) {
  cr50_utils_ = std::make_unique<Cr50UtilsImpl>();
}

WriteProtectDisableMethodStateHandler::WriteProtectDisableMethodStateHandler(
    scoped_refptr<JsonStore> json_store,
    scoped_refptr<DaemonCallback> daemon_callback,
    std::unique_ptr<Cr50Utils> cr50_utils)
    : BaseStateHandler(json_store, daemon_callback),
      cr50_utils_(std::move(cr50_utils)) {}

RmadErrorCode WriteProtectDisableMethodStateHandler::InitializeState() {
  if (!state_.has_wp_disable_method()) {
    state_.set_allocated_wp_disable_method(new WriteProtectDisableMethodState);
  }

  if (!CheckVarsInStateFile()) {
    return RMAD_ERROR_STATE_HANDLER_INITIALIZATION_FAILED;
  }

  return RMAD_ERROR_OK;
}

bool WriteProtectDisableMethodStateHandler::CheckVarsInStateFile() const {
  // json_store should contain the following keys set by |DeviceDestination| and
  // |WipeSelection| states.
  // - kSameOwner
  // - kWpDisableRequired
  // - kCcdBlocked (only required when kWpDisableRequired is true)
  // - kWipeDevice
  bool same_owner, wp_disable_required, ccd_blocked, wipe_device;
  if (!json_store_->GetValue(kSameOwner, &same_owner)) {
    LOG(ERROR) << "Variable " << kSameOwner << " not found";
    return false;
  }
  if (!json_store_->GetValue(kWpDisableRequired, &wp_disable_required)) {
    LOG(ERROR) << "Variable " << kWpDisableRequired << " not found";
    return false;
  }
  if (!json_store_->GetValue(kWipeDevice, &wipe_device)) {
    LOG(ERROR) << "Variable " << kWipeDevice << " not found";
    return false;
  }
  if (wp_disable_required &&
      !json_store_->GetValue(kCcdBlocked, &ccd_blocked)) {
    LOG(ERROR) << "Variable " << kCcdBlocked << " not found";
    return false;
  }

  // The user only has the option to choose between RSU or physical when
  // - Need to disable WP, and
  // - CCD is not blocked, and
  // - User wants to wipe the device, and
  // - Cr50 factory mode is not enabled yet
  // In other scenarios, either there is only one option to disable WP and we
  // jump directly to the state, or cr50 factory mode is enabled and we skip the
  // entire WP disabling steps.
  if (!wp_disable_required || ccd_blocked || !wipe_device) {
    LOG(ERROR) << "There is only one available method to disable WP.";
    return false;
  }
  if (cr50_utils_->IsFactoryModeEnabled()) {
    LOG(ERROR) << "Cr50 factory mode is already enabled.";
    return false;
  }

  return true;
}

BaseStateHandler::GetNextStateCaseReply
WriteProtectDisableMethodStateHandler::GetNextStateCase(
    const RmadState& state) {
  if (!state.has_wp_disable_method()) {
    LOG(ERROR) << "RmadState missing |write protection disable method| state.";
    return NextStateCaseWrapper(RMAD_ERROR_REQUEST_INVALID);
  }

  state_ = state;

  const WriteProtectDisableMethodState::DisableMethod disable_method =
      state.wp_disable_method().disable_method();

  RecordWpDisableMethodToLogs(
      json_store_,
      WriteProtectDisableMethodState::DisableMethod_Name(disable_method));

  // Go to the selected WP disabling method.
  switch (disable_method) {
    case WriteProtectDisableMethodState::RMAD_WP_DISABLE_UNKNOWN:
      return NextStateCaseWrapper(RMAD_ERROR_REQUEST_ARGS_MISSING);
    case WriteProtectDisableMethodState::RMAD_WP_DISABLE_RSU:
      return NextStateCaseWrapper(RmadState::StateCase::kWpDisableRsu);
    case WriteProtectDisableMethodState::RMAD_WP_DISABLE_PHYSICAL:
      return NextStateCaseWrapper(RmadState::StateCase::kWpDisablePhysical);
    default:
      break;
  }
  NOTREACHED();
  return NextStateCaseWrapper(RmadState::StateCase::STATE_NOT_SET,
                              RMAD_ERROR_NOT_SET,
                              RMAD_ADDITIONAL_ACTIVITY_NOTHING);
}

}  // namespace rmad
