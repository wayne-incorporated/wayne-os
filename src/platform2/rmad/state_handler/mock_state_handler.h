// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RMAD_STATE_HANDLER_MOCK_STATE_HANDLER_H_
#define RMAD_STATE_HANDLER_MOCK_STATE_HANDLER_H_

#include "rmad/state_handler/base_state_handler.h"

#include <gmock/gmock.h>

namespace rmad {

class MockStateHandler : public BaseStateHandler {
 public:
  explicit MockStateHandler(scoped_refptr<JsonStore> json_store,
                            scoped_refptr<DaemonCallback> daemon_callback)
      : BaseStateHandler(json_store, daemon_callback) {}

  MOCK_METHOD(RmadState::StateCase, GetStateCase, (), (const, override));
  MOCK_METHOD(const RmadState&, GetState, (bool), (const, override));
  MOCK_METHOD(bool, IsRepeatable, (), (const, override));
  MOCK_METHOD(RmadErrorCode, InitializeState, (), (override));
  MOCK_METHOD(void, CleanUpState, (), (override));
  MOCK_METHOD(BaseStateHandler::GetNextStateCaseReply,
              GetNextStateCase,
              (const RmadState&),
              (override));
  MOCK_METHOD(BaseStateHandler::GetNextStateCaseReply,
              TryGetNextStateCaseAtBoot,
              (),
              (override));

 protected:
  ~MockStateHandler() override = default;
};

}  // namespace rmad

#endif  // RMAD_STATE_HANDLER_MOCK_STATE_HANDLER_H_
