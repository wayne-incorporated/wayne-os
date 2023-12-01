// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RMAD_STATE_HANDLER_COMPONENTS_REPAIR_STATE_HANDLER_H_
#define RMAD_STATE_HANDLER_COMPONENTS_REPAIR_STATE_HANDLER_H_

#include "rmad/state_handler/base_state_handler.h"

#include <memory>
#include <string>
#include <vector>

#include <base/files/file_path.h>

#include "rmad/system/cryptohome_client.h"
#include "rmad/system/runtime_probe_client.h"
#include "rmad/utils/write_protect_utils.h"

namespace rmad {

class ComponentsRepairStateHandler : public BaseStateHandler {
 public:
  explicit ComponentsRepairStateHandler(
      scoped_refptr<JsonStore> json_store,
      scoped_refptr<DaemonCallback> daemon_callback);
  // Used to inject mocked |cryptohome_client_|, |runtime_probe_client_|,
  // and |crossystem_utils_| for testing.
  explicit ComponentsRepairStateHandler(
      scoped_refptr<JsonStore> json_store,
      scoped_refptr<DaemonCallback> daemon_callback,
      std::unique_ptr<CryptohomeClient> cryptohome_client,
      std::unique_ptr<RuntimeProbeClient> runtime_probe_client,
      std::unique_ptr<WriteProtectUtils> write_protect_utils);

  ASSIGN_STATE(RmadState::StateCase::kComponentsRepair);
  SET_REPEATABLE;

  RmadErrorCode InitializeState() override;
  void CleanUpState() override;
  GetNextStateCaseReply GetNextStateCase(const RmadState& state) override;

 protected:
  ~ComponentsRepairStateHandler() override = default;

 private:
  // Use the provided state to update every component. Return true if all the
  // components are properly updated.
  bool ApplyUserSelection(const RmadState& state);
  // Store variables that can be used by other state handlers to make decisions.
  bool StoreVars() const;
  // Get the list of replaced components.
  std::vector<std::string> GetReplacedComponents() const;

  bool active_;
  std::unique_ptr<CryptohomeClient> cryptohome_client_;
  std::unique_ptr<RuntimeProbeClient> runtime_probe_client_;
  std::unique_ptr<WriteProtectUtils> write_protect_utils_;
};

}  // namespace rmad

#endif  // RMAD_STATE_HANDLER_COMPONENTS_REPAIR_STATE_HANDLER_H_
