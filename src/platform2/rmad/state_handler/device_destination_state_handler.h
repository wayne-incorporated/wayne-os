// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RMAD_STATE_HANDLER_DEVICE_DESTINATION_STATE_HANDLER_H_
#define RMAD_STATE_HANDLER_DEVICE_DESTINATION_STATE_HANDLER_H_

#include <memory>

#include "rmad/state_handler/base_state_handler.h"
#include "rmad/system/cryptohome_client.h"
#include "rmad/utils/write_protect_utils.h"

namespace rmad {

class DeviceDestinationStateHandler : public BaseStateHandler {
 public:
  explicit DeviceDestinationStateHandler(
      scoped_refptr<JsonStore> json_store,
      scoped_refptr<DaemonCallback> daemon_callback);
  // Used to inject mock |cryptohome_client_| and |write_protect_utils_| for
  // testing.
  explicit DeviceDestinationStateHandler(
      scoped_refptr<JsonStore> json_store,
      scoped_refptr<DaemonCallback> daemon_callback,
      std::unique_ptr<CryptohomeClient> cryptohome_client,
      std::unique_ptr<WriteProtectUtils> crossystem_utils);

  ASSIGN_STATE(RmadState::StateCase::kDeviceDestination);
  SET_REPEATABLE;

  RmadErrorCode InitializeState() override;
  GetNextStateCaseReply GetNextStateCase(const RmadState& state) override;

 protected:
  ~DeviceDestinationStateHandler() override = default;

 private:
  bool ReplacedComponentNeedHwwpDisabled() const;

  std::unique_ptr<CryptohomeClient> cryptohome_client_;
  std::unique_ptr<WriteProtectUtils> write_protect_utils_;
};

}  // namespace rmad

#endif  // RMAD_STATE_HANDLER_DEVICE_DESTINATION_STATE_HANDLER_H_
