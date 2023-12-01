// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <string>
#include <utility>

#include <base/memory/scoped_refptr.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "rmad/constants.h"
#include "rmad/logs/logs_constants.h"
#include "rmad/state_handler/state_handler_test_common.h"
#include "rmad/state_handler/wipe_selection_state_handler.h"
#include "rmad/utils/mock_write_protect_utils.h"

using testing::_;
using testing::DoAll;
using testing::Eq;
using testing::NiceMock;
using testing::Return;
using testing::SetArgPointee;

namespace rmad {

class WipeSelectionStateHandlerTest : public StateHandlerTest {
 public:
  scoped_refptr<WipeSelectionStateHandler> CreateStateHandler(
      bool hwwp_enabled) {
    // Mock |WriteProtectUtils|.
    auto mock_write_protect_utils =
        std::make_unique<NiceMock<MockWriteProtectUtils>>();
    ON_CALL(*mock_write_protect_utils, GetHardwareWriteProtectionStatus(_))
        .WillByDefault(DoAll(SetArgPointee<0>(hwwp_enabled), Return(true)));

    return base::MakeRefCounted<WipeSelectionStateHandler>(
        json_store_, daemon_callback_, std::move(mock_write_protect_utils));
  }

  void CheckJsonStoreWipeDevice(bool expected_wipe_device) {
    bool wipe_device;
    EXPECT_TRUE(json_store_->GetValue(kWipeDevice, &wipe_device));
    EXPECT_EQ(wipe_device, expected_wipe_device);
  }

  void CheckJsonStoreWpDisableSkipped(bool expected_skipped) {
    std::string wp_disable_method_name;
    WpDisableMethod wp_disable_method;

    if (expected_skipped) {
      EXPECT_TRUE(
          json_store_->GetValue(kWpDisableMethod, &wp_disable_method_name));
      EXPECT_TRUE(
          WpDisableMethod_Parse(wp_disable_method_name, &wp_disable_method));
      EXPECT_EQ(wp_disable_method, RMAD_WP_DISABLE_METHOD_SKIPPED);
    } else {
      EXPECT_FALSE(
          json_store_->GetValue(kWpDisableMethod, &wp_disable_method_name));
    }
  }
};

TEST_F(WipeSelectionStateHandlerTest, InitializeState_Success) {
  json_store_->SetValue(kSameOwner, true);
  json_store_->SetValue(kWpDisableRequired, true);
  json_store_->SetValue(kCcdBlocked, true);

  auto handler = CreateStateHandler(true);
  EXPECT_EQ(handler->InitializeState(), RMAD_ERROR_OK);
}

TEST_F(WipeSelectionStateHandlerTest, InitializeState_MissingVars_SameOwner) {
  // No kSameOwner in |json_store_|.

  auto handler = CreateStateHandler(true);
  EXPECT_EQ(handler->InitializeState(),
            RMAD_ERROR_STATE_HANDLER_INITIALIZATION_FAILED);
}

TEST_F(WipeSelectionStateHandlerTest,
       InitializeState_MissingVars_WpDisableRequired) {
  // No kWpDisableRequired in |json_store_|.
  json_store_->SetValue(kSameOwner, true);

  auto handler = CreateStateHandler(true);
  EXPECT_EQ(handler->InitializeState(),
            RMAD_ERROR_STATE_HANDLER_INITIALIZATION_FAILED);
}

TEST_F(WipeSelectionStateHandlerTest, InitializeState_MissingVars_CcdBlocked) {
  // No kCcdBlocked in |json_store_|.
  json_store_->SetValue(kSameOwner, true);
  json_store_->SetValue(kWpDisableRequired, true);

  auto handler = CreateStateHandler(true);
  EXPECT_EQ(handler->InitializeState(),
            RMAD_ERROR_STATE_HANDLER_INITIALIZATION_FAILED);
}

TEST_F(WipeSelectionStateHandlerTest,
       InitializeState_WrongCondition_DifferentOwner) {
  json_store_->SetValue(kSameOwner, false);

  auto handler = CreateStateHandler(true);
  EXPECT_EQ(handler->InitializeState(),
            RMAD_ERROR_STATE_HANDLER_INITIALIZATION_FAILED);
}

// Definition of Case 1 ~ Case 5 are described in
// wipe_selection_state_handler.cc
TEST_F(WipeSelectionStateHandlerTest, GetNextStateCase_Case1) {
  json_store_->SetValue(kSameOwner, true);
  json_store_->SetValue(kWpDisableRequired, true);
  json_store_->SetValue(kCcdBlocked, true);

  auto handler = CreateStateHandler(true);
  EXPECT_EQ(handler->InitializeState(), RMAD_ERROR_OK);

  RmadState state;
  state.mutable_wipe_selection()->set_wipe_device(true);

  auto [error, state_case] = handler->GetNextStateCase(state);
  EXPECT_EQ(error, RMAD_ERROR_OK);
  EXPECT_EQ(state_case, RmadState::StateCase::kWpDisableRsu);

  CheckJsonStoreWipeDevice(true);
  CheckJsonStoreWpDisableSkipped(false);
}

TEST_F(WipeSelectionStateHandlerTest, GetNextStateCase_Case2) {
  json_store_->SetValue(kSameOwner, true);
  json_store_->SetValue(kWpDisableRequired, true);
  json_store_->SetValue(kCcdBlocked, true);

  auto handler = CreateStateHandler(true);
  EXPECT_EQ(handler->InitializeState(), RMAD_ERROR_OK);

  RmadState state;
  state.mutable_wipe_selection()->set_wipe_device(false);

  auto [error, state_case] = handler->GetNextStateCase(state);
  EXPECT_EQ(error, RMAD_ERROR_OK);
  EXPECT_EQ(state_case, RmadState::StateCase::kWpDisablePhysical);

  CheckJsonStoreWipeDevice(false);
  CheckJsonStoreWpDisableSkipped(false);

  // Verify the wipe device selection was recorded to logs.
  base::Value logs(base::Value::Type::DICT);
  json_store_->GetValue(kLogs, &logs);

  const base::Value::List* events = logs.GetDict().FindList(kEvents);
  EXPECT_EQ(1, events->size());
  const base::Value::Dict& event = (*events)[0].GetDict();
  EXPECT_EQ(static_cast<int>(LogEventType::kData), event.FindInt(kType));
  EXPECT_FALSE(event.FindDict(kDetails)->FindBool(kLogWipeDevice).value());
}

TEST_F(WipeSelectionStateHandlerTest, GetNextStateCase_Case3_HwwpEnabled) {
  json_store_->SetValue(kSameOwner, true);
  json_store_->SetValue(kWpDisableRequired, true);
  json_store_->SetValue(kCcdBlocked, false);

  auto handler = CreateStateHandler(true);
  EXPECT_EQ(handler->InitializeState(), RMAD_ERROR_OK);

  RmadState state;
  state.mutable_wipe_selection()->set_wipe_device(true);

  auto [error, state_case] = handler->GetNextStateCase(state);
  EXPECT_EQ(error, RMAD_ERROR_OK);
  EXPECT_EQ(state_case, RmadState::StateCase::kWpDisableMethod);

  CheckJsonStoreWipeDevice(true);
  CheckJsonStoreWpDisableSkipped(false);
}

TEST_F(WipeSelectionStateHandlerTest, GetNextStateCase_Case3_HwwpDisabled) {
  json_store_->SetValue(kSameOwner, true);
  json_store_->SetValue(kWpDisableRequired, true);
  json_store_->SetValue(kCcdBlocked, false);

  auto handler = CreateStateHandler(false);
  EXPECT_EQ(handler->InitializeState(), RMAD_ERROR_OK);

  RmadState state;
  state.mutable_wipe_selection()->set_wipe_device(true);

  auto [error, state_case] = handler->GetNextStateCase(state);
  EXPECT_EQ(error, RMAD_ERROR_OK);
  EXPECT_EQ(state_case, RmadState::StateCase::kWpDisablePhysical);

  CheckJsonStoreWipeDevice(true);
  CheckJsonStoreWpDisableSkipped(false);
}

TEST_F(WipeSelectionStateHandlerTest, GetNextStateCase_Case4) {
  json_store_->SetValue(kSameOwner, true);
  json_store_->SetValue(kWpDisableRequired, true);
  json_store_->SetValue(kCcdBlocked, false);

  auto handler = CreateStateHandler(true);
  EXPECT_EQ(handler->InitializeState(), RMAD_ERROR_OK);

  RmadState state;
  state.mutable_wipe_selection()->set_wipe_device(false);

  auto [error, state_case] = handler->GetNextStateCase(state);
  EXPECT_EQ(error, RMAD_ERROR_OK);
  EXPECT_EQ(state_case, RmadState::StateCase::kWpDisablePhysical);

  CheckJsonStoreWipeDevice(false);
  CheckJsonStoreWpDisableSkipped(false);
}

TEST_F(WipeSelectionStateHandlerTest, GetNextStateCase_Case5) {
  json_store_->SetValue(kSameOwner, true);
  json_store_->SetValue(kWpDisableRequired, false);

  auto handler = CreateStateHandler(true);
  EXPECT_EQ(handler->InitializeState(), RMAD_ERROR_OK);

  RmadState state;
  state.mutable_wipe_selection()->set_wipe_device(true);

  auto [error, state_case] = handler->GetNextStateCase(state);
  EXPECT_EQ(error, RMAD_ERROR_OK);
  EXPECT_EQ(state_case, RmadState::StateCase::kFinalize);

  CheckJsonStoreWipeDevice(true);
}

TEST_F(WipeSelectionStateHandlerTest, GetNextStateCase_MissingState) {
  json_store_->SetValue(kSameOwner, true);
  json_store_->SetValue(kWpDisableRequired, false);

  auto handler = CreateStateHandler(true);
  EXPECT_EQ(handler->InitializeState(), RMAD_ERROR_OK);

  // No WipeSelectionState.
  RmadState state;

  auto [error, state_case] = handler->GetNextStateCase(state);
  EXPECT_EQ(error, RMAD_ERROR_REQUEST_INVALID);
  EXPECT_EQ(state_case, RmadState::StateCase::kWipeSelection);
}

TEST_F(WipeSelectionStateHandlerTest, TryGetNextStateCaseAtBoot) {
  json_store_->SetValue(kSameOwner, true);
  json_store_->SetValue(kWpDisableRequired, false);

  auto handler = CreateStateHandler(true);
  EXPECT_EQ(handler->InitializeState(), RMAD_ERROR_OK);

  auto [error, state_case] = handler->TryGetNextStateCaseAtBoot();
  EXPECT_EQ(error, RMAD_ERROR_TRANSITION_FAILED);
  EXPECT_EQ(state_case, RmadState::StateCase::kWipeSelection);
}

}  // namespace rmad
