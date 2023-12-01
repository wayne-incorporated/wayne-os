// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "rmad/state_handler/write_protect_disable_complete_state_handler.h"

#include <memory>
#include <string>
#include <utility>

#include <base/logging.h>
#include <base/notreached.h>

#include "rmad/constants.h"
#include "rmad/proto_bindings/rmad.pb.h"
#include "rmad/utils/write_protect_utils_impl.h"

namespace rmad {

WriteProtectDisableCompleteStateHandler::
    WriteProtectDisableCompleteStateHandler(
        scoped_refptr<JsonStore> json_store,
        scoped_refptr<DaemonCallback> daemon_callback)
    : BaseStateHandler(json_store, daemon_callback) {
  write_protect_utils_ = std::make_unique<WriteProtectUtilsImpl>();
}

WriteProtectDisableCompleteStateHandler::
    WriteProtectDisableCompleteStateHandler(
        scoped_refptr<JsonStore> json_store,
        scoped_refptr<DaemonCallback> daemon_callback,
        std::unique_ptr<WriteProtectUtils> write_protect_utils)
    : BaseStateHandler(json_store, daemon_callback),
      write_protect_utils_(std::move(write_protect_utils)) {}

RmadErrorCode WriteProtectDisableCompleteStateHandler::InitializeState() {
  WpDisableMethod wp_disable_method;
  if (std::string wp_disable_method_name;
      !json_store_->GetValue(kWpDisableMethod, &wp_disable_method_name) ||
      !WpDisableMethod_Parse(wp_disable_method_name, &wp_disable_method)) {
    LOG(ERROR) << "Failed to get |wp_disable_method|";
    return RMAD_ERROR_STATE_HANDLER_INITIALIZATION_FAILED;
  }

  switch (wp_disable_method) {
    case RMAD_WP_DISABLE_METHOD_UNKNOWN:
      // This should not happen.
      LOG(ERROR) << "WP disable method should not be UNKNOWN";
      return RMAD_ERROR_STATE_HANDLER_INITIALIZATION_FAILED;
    case RMAD_WP_DISABLE_METHOD_SKIPPED:
      state_.mutable_wp_disable_complete()->set_action(
          WriteProtectDisableCompleteState::RMAD_WP_DISABLE_COMPLETE_NO_OP);
      break;

    case RMAD_WP_DISABLE_METHOD_RSU:
      state_.mutable_wp_disable_complete()->set_action(
          WriteProtectDisableCompleteState::RMAD_WP_DISABLE_COMPLETE_NO_OP);
      break;
    case RMAD_WP_DISABLE_METHOD_PHYSICAL_ASSEMBLE_DEVICE:
      state_.mutable_wp_disable_complete()->set_action(
          WriteProtectDisableCompleteState::
              RMAD_WP_DISABLE_COMPLETE_ASSEMBLE_DEVICE);
      break;
    case RMAD_WP_DISABLE_METHOD_PHYSICAL_KEEP_DEVICE_OPEN:
      state_.mutable_wp_disable_complete()->set_action(
          WriteProtectDisableCompleteState::
              RMAD_WP_DISABLE_COMPLETE_KEEP_DEVICE_OPEN);
      break;
    default:
      // We already enumerated all the enums.
      NOTREACHED();
  }

  return RMAD_ERROR_OK;
}

BaseStateHandler::GetNextStateCaseReply
WriteProtectDisableCompleteStateHandler::GetNextStateCase(
    const RmadState& state) {
  if (!state.has_wp_disable_complete()) {
    LOG(ERROR) << "RmadState missing |WP disable complete| state.";
    return NextStateCaseWrapper(RMAD_ERROR_REQUEST_INVALID);
  }

  if (!write_protect_utils_->DisableSoftwareWriteProtection()) {
    LOG(ERROR) << "Failed to disable software write protect";
    return NextStateCaseWrapper(RMAD_ERROR_WP_ENABLED);
  }

  return NextStateCaseWrapper(RmadState::StateCase::kUpdateRoFirmware);
}

}  // namespace rmad
