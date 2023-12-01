// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "rmad/state_handler/restock_state_handler.h"

#include <memory>
#include <utility>

#include <base/logging.h>
#include <base/notreached.h>

#include "rmad/logs/logs_utils.h"
#include "rmad/system/power_manager_client_impl.h"
#include "rmad/utils/dbus_utils.h"

namespace rmad {

RestockStateHandler::RestockStateHandler(
    scoped_refptr<JsonStore> json_store,
    scoped_refptr<DaemonCallback> daemon_callback)
    : BaseStateHandler(json_store, daemon_callback) {
  power_manager_client_ =
      std::make_unique<PowerManagerClientImpl>(GetSystemBus());
}

RestockStateHandler::RestockStateHandler(
    scoped_refptr<JsonStore> json_store,
    scoped_refptr<DaemonCallback> daemon_callback,
    std::unique_ptr<PowerManagerClient> power_manager_client)
    : BaseStateHandler(json_store, daemon_callback),
      power_manager_client_(std::move(power_manager_client)) {}

RmadErrorCode RestockStateHandler::InitializeState() {
  if (!state_.has_restock() && !RetrieveState()) {
    state_.set_allocated_restock(new RestockState);
  }
  shutdown_scheduled_ = false;
  return RMAD_ERROR_OK;
}

BaseStateHandler::GetNextStateCaseReply RestockStateHandler::GetNextStateCase(
    const RmadState& state) {
  if (!state.has_restock()) {
    LOG(ERROR) << "RmadState missing |restock| state.";
    return NextStateCaseWrapper(RMAD_ERROR_REQUEST_INVALID);
  }
  if (shutdown_scheduled_) {
    return NextStateCaseWrapper(RMAD_ERROR_EXPECT_SHUTDOWN);
  }

  // For the first bootup after restock and shutdown, the state machine will try
  // to automatically transition to the next state. Therefore, we do not store
  // the state to prevent the continuous shutdown.
  switch (state.restock().choice()) {
    case RestockState::RMAD_RESTOCK_UNKNOWN:
      return NextStateCaseWrapper(RMAD_ERROR_REQUEST_ARGS_MISSING);
    case RestockState::RMAD_RESTOCK_SHUTDOWN_AND_RESTOCK:
      RecordRestockOptionToLogs(json_store_, /*restock=*/true);
      // Wait for a while before shutting down.
      timer_.Start(FROM_HERE, kShutdownDelay, this,
                   &RestockStateHandler::Shutdown);
      shutdown_scheduled_ = true;
      return NextStateCaseWrapper(GetStateCase(), RMAD_ERROR_EXPECT_SHUTDOWN,
                                  RMAD_ADDITIONAL_ACTIVITY_SHUTDOWN);
    case RestockState::RMAD_RESTOCK_CONTINUE_RMA:
      RecordRestockOptionToLogs(json_store_, /*restock=*/false);
      return NextStateCaseWrapper(RmadState::StateCase::kUpdateDeviceInfo);
    default:
      break;
  }
  NOTREACHED();
  return NextStateCaseWrapper(RmadState::StateCase::STATE_NOT_SET,
                              RMAD_ERROR_NOT_SET,
                              RMAD_ADDITIONAL_ACTIVITY_NOTHING);
}

void RestockStateHandler::Shutdown() {
  DLOG(INFO) << "Shutting down to restock";
  if (!power_manager_client_->Shutdown()) {
    LOG(ERROR) << "Failed to shut down";
  }
}

}  // namespace rmad
