// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RMAD_STATE_HANDLER_RESTOCK_STATE_HANDLER_H_
#define RMAD_STATE_HANDLER_RESTOCK_STATE_HANDLER_H_

#include "rmad/state_handler/base_state_handler.h"

#include <memory>

#include <base/files/file_path.h>
#include <base/timer/timer.h>

#include "rmad/system/power_manager_client.h"

namespace rmad {

class RestockStateHandler : public BaseStateHandler {
 public:
  // Wait for 3 seconds before shutting down.
  static constexpr base::TimeDelta kShutdownDelay = base::Seconds(3);

  explicit RestockStateHandler(scoped_refptr<JsonStore> json_store,
                               scoped_refptr<DaemonCallback> daemon_callback);
  // Used to inject mocked |power_manager_client_| for testing.
  explicit RestockStateHandler(
      scoped_refptr<JsonStore> json_store,
      scoped_refptr<DaemonCallback> daemon_callback,
      std::unique_ptr<PowerManagerClient> power_manager_client);

  ASSIGN_STATE(RmadState::StateCase::kRestock);
  SET_REPEATABLE;

  RmadErrorCode InitializeState() override;
  GetNextStateCaseReply GetNextStateCase(const RmadState& state) override;

 protected:
  ~RestockStateHandler() override = default;

 private:
  void Shutdown();

  std::unique_ptr<PowerManagerClient> power_manager_client_;

  bool shutdown_scheduled_;
  base::OneShotTimer timer_;
};

}  // namespace rmad

#endif  // RMAD_STATE_HANDLER_RESTOCK_STATE_HANDLER_H_
