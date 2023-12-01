// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RMAD_STATE_HANDLER_WELCOME_SCREEN_STATE_HANDLER_H_
#define RMAD_STATE_HANDLER_WELCOME_SCREEN_STATE_HANDLER_H_

#include "rmad/state_handler/base_state_handler.h"

#include <memory>
#include <utility>

#include <base/files/file_path.h>

#include "rmad/system/hardware_verifier_client.h"

namespace rmad {

class WelcomeScreenStateHandler : public BaseStateHandler {
 public:
  explicit WelcomeScreenStateHandler(
      scoped_refptr<JsonStore> json_store,
      scoped_refptr<DaemonCallback> daemon_callback);
  // Used to inject mock |hardware_verifier_client_| for testing.
  explicit WelcomeScreenStateHandler(
      scoped_refptr<JsonStore> json_store,
      scoped_refptr<DaemonCallback> daemon_callback,
      std::unique_ptr<HardwareVerifierClient> hardware_verifier_client);

  ASSIGN_STATE(RmadState::StateCase::kWelcome);
  SET_REPEATABLE;

  RmadErrorCode InitializeState() override;
  GetNextStateCaseReply GetNextStateCase(const RmadState& state) override;

  void RunHardwareVerifier() const;

 protected:
  ~WelcomeScreenStateHandler() override = default;

  void OnGetStateTask() const override;

 private:
  // Helper utilities.
  std::unique_ptr<HardwareVerifierClient> hardware_verifier_client_;
};

}  // namespace rmad

#endif  // RMAD_STATE_HANDLER_WELCOME_SCREEN_STATE_HANDLER_H_
