// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>

#include <base/files/file_path.h>
#include <base/test/task_environment.h>
#include <base/memory/scoped_refptr.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "rmad/daemon/daemon_callback.h"
#include "rmad/state_handler/mock_state_handler.h"
#include "rmad/state_handler/state_handler_manager.h"
#include "rmad/utils/json_store.h"

namespace rmad {

using testing::_;
using testing::Return;
using testing::SetArgPointee;
using testing::StrictMock;

class StateHandlerManagerTest : public testing::Test {
 public:
  StateHandlerManagerTest() {
    json_store_ = base::MakeRefCounted<JsonStore>(base::FilePath(""));
    daemon_callback_ = base::MakeRefCounted<DaemonCallback>();
    state_handler_manager_ = std::make_unique<StateHandlerManager>(json_store_);
  }

  scoped_refptr<BaseStateHandler> CreateMockStateHandler(
      RmadState::StateCase state,
      RmadState::StateCase next_state,
      RmadErrorCode update_error = RMAD_ERROR_OK) {
    auto handler = base::MakeRefCounted<StrictMock<MockStateHandler>>(
        json_store_, daemon_callback_);
    EXPECT_CALL(*handler, GetStateCase()).WillRepeatedly(Return(state));
    EXPECT_CALL(*handler, InitializeState())
        .WillRepeatedly(Return(RMAD_ERROR_OK));
    EXPECT_CALL(*handler, GetNextStateCase(_))
        .WillRepeatedly(Return(BaseStateHandler::GetNextStateCaseReply{
            .error = update_error, .state_case = next_state}));

    return handler;
  }

 protected:
  scoped_refptr<JsonStore> json_store_;
  scoped_refptr<DaemonCallback> daemon_callback_;
  std::unique_ptr<StateHandlerManager> state_handler_manager_;
};

TEST_F(StateHandlerManagerTest, GetStateHandler) {
  auto handler1 = CreateMockStateHandler(RmadState::kComponentsRepair,
                                         RmadState::kDeviceDestination);
  auto handler2 =
      CreateMockStateHandler(RmadState::kWelcome, RmadState::STATE_NOT_SET);
  state_handler_manager_->RegisterStateHandler(handler1);
  state_handler_manager_->RegisterStateHandler(handler2);

  auto nonexistent_handler =
      state_handler_manager_->GetStateHandler(RmadState::STATE_NOT_SET);
  EXPECT_FALSE(nonexistent_handler.get());

  auto retrieve_handler =
      state_handler_manager_->GetStateHandler(RmadState::kWelcome);
  EXPECT_TRUE(retrieve_handler.get());
  EXPECT_EQ(RmadState::kWelcome, retrieve_handler->GetStateCase());
  BaseStateHandler::GetNextStateCaseReply reply =
      retrieve_handler->GetNextStateCase(RmadState());
  EXPECT_EQ(RMAD_ERROR_OK, reply.error);
  EXPECT_EQ(RmadState::STATE_NOT_SET, reply.state_case);
}

TEST_F(StateHandlerManagerTest, RegisterStateHandlerCollision) {
  RmadState welcome_proto;
  welcome_proto.set_allocated_welcome(new WelcomeState());
  auto handler1 =
      CreateMockStateHandler(RmadState::kWelcome, RmadState::STATE_NOT_SET);
  auto handler2 =
      CreateMockStateHandler(RmadState::kWelcome, RmadState::kComponentsRepair);
  state_handler_manager_->RegisterStateHandler(handler1);
  EXPECT_DEATH(state_handler_manager_->RegisterStateHandler(handler2),
               "Registered handlers should have unique RmadStates.");
}

TEST_F(StateHandlerManagerTest, RegisterStateHandlers) {
  base::test::SingleThreadTaskEnvironment task_environment;
  state_handler_manager_->RegisterStateHandlers(daemon_callback_);
}

}  // namespace rmad
