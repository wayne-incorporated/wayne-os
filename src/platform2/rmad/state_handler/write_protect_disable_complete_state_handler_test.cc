// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <string>
#include <utility>

#include <base/memory/scoped_refptr.h>
#include <gtest/gtest.h>

#include "rmad/constants.h"
#include "rmad/proto_bindings/rmad.pb.h"
#include "rmad/state_handler/state_handler_test_common.h"
#include "rmad/state_handler/write_protect_disable_complete_state_handler.h"
#include "rmad/utils/mock_write_protect_utils.h"

using testing::NiceMock;
using testing::Return;

namespace {

struct StateHandlerArgs {
  bool disable_swwp_succeeded = true;
};

};  // namespace

namespace rmad {

class WriteProtectDisableCompleteStateHandlerTest : public StateHandlerTest {
 public:
  scoped_refptr<WriteProtectDisableCompleteStateHandler> CreateStateHandler(
      const StateHandlerArgs& args = {}) {
    // Mock |WriteProtectUtils|.
    auto mock_write_protect_utils =
        std::make_unique<NiceMock<MockWriteProtectUtils>>();
    ON_CALL(*mock_write_protect_utils, DisableSoftwareWriteProtection())
        .WillByDefault(Return(args.disable_swwp_succeeded));

    return base::MakeRefCounted<WriteProtectDisableCompleteStateHandler>(
        json_store_, daemon_callback_, std::move(mock_write_protect_utils));
  }
};

TEST_F(WriteProtectDisableCompleteStateHandlerTest, InitializeState_Skipped) {
  // Set up environment for skipping disabling WP.
  EXPECT_TRUE(json_store_->SetValue(
      kWpDisableMethod, WpDisableMethod_Name(RMAD_WP_DISABLE_METHOD_SKIPPED)));

  auto handler = CreateStateHandler();
  EXPECT_EQ(handler->InitializeState(), RMAD_ERROR_OK);
  EXPECT_EQ(handler->GetState().wp_disable_complete().action(),
            WriteProtectDisableCompleteState::RMAD_WP_DISABLE_COMPLETE_NO_OP);
}

TEST_F(WriteProtectDisableCompleteStateHandlerTest, InitializeState_Rsu) {
  // Set up environment for using RSU to disable WP.
  EXPECT_TRUE(json_store_->SetValue(
      kWpDisableMethod, WpDisableMethod_Name(RMAD_WP_DISABLE_METHOD_RSU)));

  auto handler = CreateStateHandler();
  EXPECT_EQ(handler->InitializeState(), RMAD_ERROR_OK);
  EXPECT_EQ(handler->GetState().wp_disable_complete().action(),
            WriteProtectDisableCompleteState::RMAD_WP_DISABLE_COMPLETE_NO_OP);
}

TEST_F(WriteProtectDisableCompleteStateHandlerTest,
       InitializeState_PhysicalAssembleDevice) {
  // Set up environment for using physical method to disable WP and turn on
  // factory mode.
  EXPECT_TRUE(json_store_->SetValue(
      kWpDisableMethod,
      WpDisableMethod_Name(RMAD_WP_DISABLE_METHOD_PHYSICAL_ASSEMBLE_DEVICE)));

  auto handler = CreateStateHandler();
  EXPECT_EQ(handler->InitializeState(), RMAD_ERROR_OK);
  EXPECT_EQ(handler->GetState().wp_disable_complete().action(),
            WriteProtectDisableCompleteState::
                RMAD_WP_DISABLE_COMPLETE_ASSEMBLE_DEVICE);
}

TEST_F(WriteProtectDisableCompleteStateHandlerTest,
       InitializeState_PhysicalKeepDeviceOpen) {
  // Set up environment for using physical method to disable WP and doesn't turn
  // on factory mode.
  EXPECT_TRUE(json_store_->SetValue(
      kWpDisableMethod,
      WpDisableMethod_Name(RMAD_WP_DISABLE_METHOD_PHYSICAL_KEEP_DEVICE_OPEN)));

  auto handler = CreateStateHandler();
  EXPECT_EQ(handler->InitializeState(), RMAD_ERROR_OK);
  EXPECT_EQ(handler->GetState().wp_disable_complete().action(),
            WriteProtectDisableCompleteState::
                RMAD_WP_DISABLE_COMPLETE_KEEP_DEVICE_OPEN);
}

TEST_F(WriteProtectDisableCompleteStateHandlerTest, InitializeState_Failed) {
  // |kWpDisableMethod| not set.
  auto handler = CreateStateHandler();
  EXPECT_EQ(handler->InitializeState(),
            RMAD_ERROR_STATE_HANDLER_INITIALIZATION_FAILED);
}

TEST_F(WriteProtectDisableCompleteStateHandlerTest,
       GetNextStateCase_Succeeded) {
  // Set up environment for using RSU to disable WP.
  EXPECT_TRUE(json_store_->SetValue(
      kWpDisableMethod, WpDisableMethod_Name(RMAD_WP_DISABLE_METHOD_RSU)));

  auto handler = CreateStateHandler();
  EXPECT_EQ(handler->InitializeState(), RMAD_ERROR_OK);

  RmadState state;
  state.set_allocated_wp_disable_complete(new WriteProtectDisableCompleteState);

  auto [error, state_case] = handler->GetNextStateCase(state);
  EXPECT_EQ(error, RMAD_ERROR_OK);
  EXPECT_EQ(state_case, RmadState::StateCase::kUpdateRoFirmware);
}

TEST_F(WriteProtectDisableCompleteStateHandlerTest,
       GetNextStateCase_DisableSwwpFailed) {
  // Set up environment for using RSU to disable WP.
  EXPECT_TRUE(json_store_->SetValue(
      kWpDisableMethod, WpDisableMethod_Name(RMAD_WP_DISABLE_METHOD_RSU)));

  auto handler = CreateStateHandler({.disable_swwp_succeeded = false});
  EXPECT_EQ(handler->InitializeState(), RMAD_ERROR_OK);

  RmadState state;
  state.set_allocated_wp_disable_complete(new WriteProtectDisableCompleteState);

  auto [error, state_case] = handler->GetNextStateCase(state);
  EXPECT_EQ(error, RMAD_ERROR_WP_ENABLED);
  EXPECT_EQ(state_case, RmadState::StateCase::kWpDisableComplete);
}

TEST_F(WriteProtectDisableCompleteStateHandlerTest,
       GetNextStateCase_MissingState) {
  // Set up environment for using RSU to disable WP.
  EXPECT_TRUE(json_store_->SetValue(
      kWpDisableMethod, WpDisableMethod_Name(RMAD_WP_DISABLE_METHOD_RSU)));

  auto handler = CreateStateHandler();
  EXPECT_EQ(handler->InitializeState(), RMAD_ERROR_OK);

  // No WriteProtectDisableCompleteState.
  RmadState state;

  auto [error, state_case] = handler->GetNextStateCase(state);
  EXPECT_EQ(error, RMAD_ERROR_REQUEST_INVALID);
  EXPECT_EQ(state_case, RmadState::StateCase::kWpDisableComplete);
}

}  // namespace rmad
