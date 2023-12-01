// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RMAD_STATE_HANDLER_WRITE_PROTECT_DISABLE_COMPLETE_STATE_HANDLER_H_
#define RMAD_STATE_HANDLER_WRITE_PROTECT_DISABLE_COMPLETE_STATE_HANDLER_H_

#include "rmad/state_handler/base_state_handler.h"

#include <memory>

#include "rmad/utils/write_protect_utils.h"

namespace rmad {

class WriteProtectDisableCompleteStateHandler : public BaseStateHandler {
 public:
  explicit WriteProtectDisableCompleteStateHandler(
      scoped_refptr<JsonStore> json_store,
      scoped_refptr<DaemonCallback> daemon_callback);
  // Used to inject mock |write_protect_utils_| for testing.
  explicit WriteProtectDisableCompleteStateHandler(
      scoped_refptr<JsonStore> json_store,
      scoped_refptr<DaemonCallback> daemon_callback,
      std::unique_ptr<WriteProtectUtils> write_protect_utils);

  ASSIGN_STATE(RmadState::StateCase::kWpDisableComplete);
  SET_UNREPEATABLE;

  RmadErrorCode InitializeState() override;
  GetNextStateCaseReply GetNextStateCase(const RmadState& state) override;

 protected:
  ~WriteProtectDisableCompleteStateHandler() override = default;

 private:
  std::unique_ptr<WriteProtectUtils> write_protect_utils_;
};

}  // namespace rmad

#endif  // RMAD_STATE_HANDLER_WRITE_PROTECT_DISABLE_COMPLETE_STATE_HANDLER_H_
