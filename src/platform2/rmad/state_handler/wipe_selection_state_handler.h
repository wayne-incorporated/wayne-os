// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RMAD_STATE_HANDLER_WIPE_SELECTION_STATE_HANDLER_H_
#define RMAD_STATE_HANDLER_WIPE_SELECTION_STATE_HANDLER_H_

#include "rmad/state_handler/base_state_handler.h"

#include <memory>

#include <base/files/file_path.h>

#include "rmad/utils/write_protect_utils.h"

namespace rmad {

class WipeSelectionStateHandler : public BaseStateHandler {
 public:
  explicit WipeSelectionStateHandler(
      scoped_refptr<JsonStore> json_store,
      scoped_refptr<DaemonCallback> daemon_callback);
  // Used to inject mock |write_protect_utils_| for testing.
  explicit WipeSelectionStateHandler(
      scoped_refptr<JsonStore> json_store,
      scoped_refptr<DaemonCallback> daemon_callback,
      std::unique_ptr<WriteProtectUtils> write_protect_utils);

  ASSIGN_STATE(RmadState::StateCase::kWipeSelection);
  SET_REPEATABLE;

  RmadErrorCode InitializeState() override;
  GetNextStateCaseReply GetNextStateCase(const RmadState& state) override;

 protected:
  ~WipeSelectionStateHandler() override = default;

 private:
  bool InitializeVarsFromStateFile();

  std::unique_ptr<WriteProtectUtils> write_protect_utils_;

  bool wp_disable_required_;
  bool ccd_blocked_;
};

}  // namespace rmad

#endif  // RMAD_STATE_HANDLER_WIPE_SELECTION_STATE_HANDLER_H_
