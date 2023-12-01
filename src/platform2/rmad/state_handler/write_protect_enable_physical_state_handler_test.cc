// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <base/memory/scoped_refptr.h>
#include <base/test/task_environment.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "rmad/state_handler/state_handler_test_common.h"
#include "rmad/state_handler/write_protect_enable_physical_state_handler.h"
#include "rmad/utils/mock_write_protect_utils.h"

using testing::_;
using testing::Assign;
using testing::DoAll;
using testing::Eq;
using testing::InSequence;
using testing::IsTrue;
using testing::NiceMock;
using testing::Return;
using testing::SetArgPointee;
using testing::StrictMock;

namespace {

struct StateHandlerArgs {
  std::vector<bool> wp_status_list = {};
  bool enable_swwp_succeeded = true;
};

}  // namespace

namespace rmad {

class WriteProtectEnablePhysicalStateHandlerTest : public StateHandlerTest {
 public:
  // Helper class to mock the callback function to send signal.
  class SignalSender {
   public:
    MOCK_METHOD(void, SendHardwareWriteProtectSignal, (bool), (const));
  };

  scoped_refptr<WriteProtectEnablePhysicalStateHandler> CreateStateHandler(
      const StateHandlerArgs& args = {}) {
    // Mock |WriteProtectUtils|.
    auto mock_write_protect_utils =
        std::make_unique<StrictMock<MockWriteProtectUtils>>();
    {
      InSequence seq;
      for (bool enabled : args.wp_status_list) {
        EXPECT_CALL(*mock_write_protect_utils,
                    GetHardwareWriteProtectionStatus(_))
            .WillOnce(DoAll(SetArgPointee<0, bool>(enabled), Return(true)));
      }
    }
    EXPECT_CALL(*mock_write_protect_utils, EnableSoftwareWriteProtection())
        .WillRepeatedly(Return(args.enable_swwp_succeeded));

    // Register signal callback.
    daemon_callback_->SetWriteProtectSignalCallback(
        base::BindRepeating(&SignalSender::SendHardwareWriteProtectSignal,
                            base::Unretained(&signal_sender_)));

    return base::MakeRefCounted<WriteProtectEnablePhysicalStateHandler>(
        json_store_, daemon_callback_, std::move(mock_write_protect_utils));
  }

 protected:
  StrictMock<SignalSender> signal_sender_;

  // Variables for TaskRunner.
  base::test::SingleThreadTaskEnvironment task_environment_{
      base::test::TaskEnvironment::TimeSource::MOCK_TIME};
};

TEST_F(WriteProtectEnablePhysicalStateHandlerTest, InitializeState_Succeeded) {
  auto handler = CreateStateHandler();
  EXPECT_EQ(handler->InitializeState(), RMAD_ERROR_OK);
}

TEST_F(WriteProtectEnablePhysicalStateHandlerTest, InitializeState_Fail) {
  auto handler = CreateStateHandler({.enable_swwp_succeeded = false});
  EXPECT_EQ(handler->InitializeState(),
            RMAD_ERROR_STATE_HANDLER_INITIALIZATION_FAILED);
}

TEST_F(WriteProtectEnablePhysicalStateHandlerTest, GetNextStateCase_Succeeded) {
  auto handler = CreateStateHandler({.wp_status_list = {true}});
  EXPECT_EQ(handler->InitializeState(), RMAD_ERROR_OK);

  RmadState state;
  state.set_allocated_wp_enable_physical(new WriteProtectEnablePhysicalState);

  auto [error, state_case] = handler->GetNextStateCase(state);
  EXPECT_EQ(error, RMAD_ERROR_OK);
  EXPECT_EQ(state_case, RmadState::StateCase::kFinalize);
}

TEST_F(WriteProtectEnablePhysicalStateHandlerTest,
       GetNextStateCase_MissingState) {
  auto handler = CreateStateHandler();
  EXPECT_EQ(handler->InitializeState(), RMAD_ERROR_OK);

  // No WriteProtectEnablePhysicalState.
  RmadState state;

  auto [error, state_case] = handler->GetNextStateCase(state);
  EXPECT_EQ(error, RMAD_ERROR_REQUEST_INVALID);
  EXPECT_EQ(state_case, RmadState::StateCase::kWpEnablePhysical);
}

TEST_F(WriteProtectEnablePhysicalStateHandlerTest, GetNextStateCase_Wait) {
  auto handler =
      CreateStateHandler({.wp_status_list = {false, false, false, true}});
  EXPECT_EQ(handler->InitializeState(), RMAD_ERROR_OK);
  handler->RunState();

  RmadState state;
  state.set_allocated_wp_enable_physical(new WriteProtectEnablePhysicalState);

  // First call to |mock_write_protect_utils_|, get 0.
  auto [error, state_case] = handler->GetNextStateCase(state);
  EXPECT_EQ(error, RMAD_ERROR_WAIT);
  EXPECT_EQ(state_case, RmadState::StateCase::kWpEnablePhysical);

  bool signal_sent = false;
  EXPECT_CALL(signal_sender_, SendHardwareWriteProtectSignal(IsTrue()))
      .WillOnce(Assign(&signal_sent, true));

  // Second call to |mock_write_protect_utils_| during polling, get 0.
  task_environment_.FastForwardBy(
      WriteProtectEnablePhysicalStateHandler::kPollInterval);
  EXPECT_FALSE(signal_sent);
  // Third call to |mock_write_protect_utils_| during polling, get 0.
  task_environment_.FastForwardBy(
      WriteProtectEnablePhysicalStateHandler::kPollInterval);
  EXPECT_FALSE(signal_sent);
  // Forth call to |mock_write_protect_utils_| during polling, get 1.
  task_environment_.FastForwardBy(
      WriteProtectEnablePhysicalStateHandler::kPollInterval);
  EXPECT_TRUE(signal_sent);
}

}  // namespace rmad
