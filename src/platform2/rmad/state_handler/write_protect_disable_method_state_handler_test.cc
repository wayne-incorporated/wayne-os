// Copyright 2021 The ChromiumOS Authors
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
#include "rmad/state_handler/write_protect_disable_method_state_handler.h"
#include "rmad/utils/mock_cr50_utils.h"

using testing::NiceMock;
using testing::Return;

namespace {

struct StateHandlerArgs {
  bool factory_mode_enabled = false;
};

}  // namespace

namespace rmad {

class WriteProtectDisableMethodStateHandlerTest : public StateHandlerTest {
 public:
  scoped_refptr<WriteProtectDisableMethodStateHandler> CreateStateHandler(
      const StateHandlerArgs& args = {}) {
    // Mock |Cr50Utils|.
    auto mock_cr50_utils = std::make_unique<NiceMock<MockCr50Utils>>();
    ON_CALL(*mock_cr50_utils, IsFactoryModeEnabled())
        .WillByDefault(Return(args.factory_mode_enabled));

    return base::MakeRefCounted<WriteProtectDisableMethodStateHandler>(
        json_store_, daemon_callback_, std::move(mock_cr50_utils));
  }
};

TEST_F(WriteProtectDisableMethodStateHandlerTest, InitializeState_Succeeded) {
  // Set up a valid environment.
  json_store_->SetValue(kSameOwner, true);
  json_store_->SetValue(kWpDisableRequired, true);
  json_store_->SetValue(kCcdBlocked, false);
  json_store_->SetValue(kWipeDevice, true);

  auto handler = CreateStateHandler();
  EXPECT_EQ(handler->InitializeState(), RMAD_ERROR_OK);
}

TEST_F(WriteProtectDisableMethodStateHandlerTest,
       InitializeState_MissingVars_SameOwner) {
  // No kSameOwner in |json_store_|.

  auto handler = CreateStateHandler();
  EXPECT_EQ(handler->InitializeState(),
            RMAD_ERROR_STATE_HANDLER_INITIALIZATION_FAILED);
}

TEST_F(WriteProtectDisableMethodStateHandlerTest,
       InitializeState_MissingVars_WpDisableRequired) {
  // No kWpDisableRequired in |json_store_|.
  json_store_->SetValue(kSameOwner, true);

  auto handler = CreateStateHandler();
  EXPECT_EQ(handler->InitializeState(),
            RMAD_ERROR_STATE_HANDLER_INITIALIZATION_FAILED);
}

TEST_F(WriteProtectDisableMethodStateHandlerTest,
       InitializeState_MissingVars_WipeDevice) {
  // No kWipeDevice in |json_store_|.
  json_store_->SetValue(kSameOwner, true);
  json_store_->SetValue(kWpDisableRequired, true);

  auto handler = CreateStateHandler();
  EXPECT_EQ(handler->InitializeState(),
            RMAD_ERROR_STATE_HANDLER_INITIALIZATION_FAILED);
}

TEST_F(WriteProtectDisableMethodStateHandlerTest,
       InitializeState_MissingVars_CcdBlocked) {
  // No kCcdBlocked in |json_store_|.
  json_store_->SetValue(kSameOwner, true);
  json_store_->SetValue(kWpDisableRequired, true);
  json_store_->SetValue(kWipeDevice, true);

  auto handler = CreateStateHandler();
  EXPECT_EQ(handler->InitializeState(),
            RMAD_ERROR_STATE_HANDLER_INITIALIZATION_FAILED);
}

TEST_F(WriteProtectDisableMethodStateHandlerTest,
       InitializeState_WrongCondition_WpDisableNotRequired) {
  // If we don't need to disable WP, we shouldn't enter this state.
  json_store_->SetValue(kSameOwner, true);
  json_store_->SetValue(kWpDisableRequired, false);
  json_store_->SetValue(kWipeDevice, true);

  auto handler = CreateStateHandler();
  EXPECT_EQ(handler->InitializeState(),
            RMAD_ERROR_STATE_HANDLER_INITIALIZATION_FAILED);
}

TEST_F(WriteProtectDisableMethodStateHandlerTest,
       InitializeState_WrongCondition_CcdBlocked) {
  // If CCD is blocked, RSU is the only option to disable WP and we shouldn't
  // enter this state.
  json_store_->SetValue(kSameOwner, true);
  json_store_->SetValue(kWpDisableRequired, true);
  json_store_->SetValue(kCcdBlocked, true);
  json_store_->SetValue(kWipeDevice, true);

  auto handler = CreateStateHandler();
  EXPECT_EQ(handler->InitializeState(),
            RMAD_ERROR_STATE_HANDLER_INITIALIZATION_FAILED);
}

TEST_F(WriteProtectDisableMethodStateHandlerTest,
       InitializeState_WrongCondition_NoWipeDevice) {
  // If we don't want to wipe the device, physical method is the only option to
  // disable WP and we shouldn't enter this state.
  json_store_->SetValue(kSameOwner, true);
  json_store_->SetValue(kWpDisableRequired, true);
  json_store_->SetValue(kCcdBlocked, false);
  json_store_->SetValue(kWipeDevice, false);

  auto handler = CreateStateHandler();
  EXPECT_EQ(handler->InitializeState(),
            RMAD_ERROR_STATE_HANDLER_INITIALIZATION_FAILED);
}

TEST_F(WriteProtectDisableMethodStateHandlerTest,
       InitializeState_WrongCondition_FactoryModeEnabled) {
  // If factory mode is enabled, we can skip the whole WP disabling steps and we
  // shouldn't enter this state.
  json_store_->SetValue(kSameOwner, true);
  json_store_->SetValue(kWpDisableRequired, true);
  json_store_->SetValue(kCcdBlocked, false);
  json_store_->SetValue(kWipeDevice, true);

  auto handler = CreateStateHandler({.factory_mode_enabled = true});
  EXPECT_EQ(handler->InitializeState(),
            RMAD_ERROR_STATE_HANDLER_INITIALIZATION_FAILED);
}

TEST_F(WriteProtectDisableMethodStateHandlerTest,
       GetNextStateCase_Succeeded_RSU) {
  // Set up environment where multiple WP disabling methods are available.
  json_store_->SetValue(kSameOwner, true);
  json_store_->SetValue(kWpDisableRequired, true);
  json_store_->SetValue(kCcdBlocked, false);
  json_store_->SetValue(kWipeDevice, true);

  auto handler = CreateStateHandler();
  EXPECT_EQ(handler->InitializeState(), RMAD_ERROR_OK);

  RmadState state;
  state.mutable_wp_disable_method()->set_disable_method(
      WriteProtectDisableMethodState::RMAD_WP_DISABLE_RSU);

  auto [error, state_case] = handler->GetNextStateCase(state);
  EXPECT_EQ(error, RMAD_ERROR_OK);
  EXPECT_EQ(state_case, RmadState::StateCase::kWpDisableRsu);

  // Verify the wp disable method was recorded to logs.
  base::Value logs(base::Value::Type::DICT);
  json_store_->GetValue(kLogs, &logs);

  const base::Value::List* events = logs.GetDict().FindList(kEvents);
  EXPECT_EQ(1, events->size());
  const base::Value::Dict& event = (*events)[0].GetDict();
  EXPECT_EQ(static_cast<int>(LogEventType::kData), event.FindInt(kType));
  EXPECT_EQ(WriteProtectDisableMethodState::DisableMethod_Name(
                WriteProtectDisableMethodState::RMAD_WP_DISABLE_RSU),
            *event.FindDict(kDetails)->FindString(kLogWpDisableMethod));
}

TEST_F(WriteProtectDisableMethodStateHandlerTest,
       GetNextStateCase_Succeeded_Physical) {
  // Set up environment where multiple WP disabling methods are available.
  json_store_->SetValue(kSameOwner, false);
  json_store_->SetValue(kWpDisableRequired, true);
  json_store_->SetValue(kCcdBlocked, false);
  json_store_->SetValue(kWipeDevice, true);

  auto handler = CreateStateHandler();
  EXPECT_EQ(handler->InitializeState(), RMAD_ERROR_OK);

  RmadState state;
  state.mutable_wp_disable_method()->set_disable_method(
      WriteProtectDisableMethodState::RMAD_WP_DISABLE_PHYSICAL);

  auto [error, state_case] = handler->GetNextStateCase(state);
  EXPECT_EQ(error, RMAD_ERROR_OK);
  EXPECT_EQ(state_case, RmadState::StateCase::kWpDisablePhysical);

  // Verify the wp disable method was recorded to logs.
  base::Value logs(base::Value::Type::DICT);
  json_store_->GetValue(kLogs, &logs);

  const base::Value::List* events = logs.GetDict().FindList(kEvents);
  EXPECT_EQ(1, events->size());
  const base::Value::Dict& event = (*events)[0].GetDict();
  EXPECT_EQ(static_cast<int>(LogEventType::kData), event.FindInt(kType));
  EXPECT_EQ(WriteProtectDisableMethodState::DisableMethod_Name(
                WriteProtectDisableMethodState::RMAD_WP_DISABLE_PHYSICAL),
            *event.FindDict(kDetails)->FindString(kLogWpDisableMethod));
}

TEST_F(WriteProtectDisableMethodStateHandlerTest,
       GetNextStateCase_MissingState) {
  // Set up environment where multiple WP disabling methods are available.
  json_store_->SetValue(kSameOwner, true);
  json_store_->SetValue(kWpDisableRequired, true);
  json_store_->SetValue(kCcdBlocked, false);
  json_store_->SetValue(kWipeDevice, true);

  auto handler = CreateStateHandler();
  EXPECT_EQ(handler->InitializeState(), RMAD_ERROR_OK);

  // No WriteProtectDisableMethodState.
  RmadState state;

  auto [error, state_case] = handler->GetNextStateCase(state);
  EXPECT_EQ(error, RMAD_ERROR_REQUEST_INVALID);
  EXPECT_EQ(state_case, RmadState::StateCase::kWpDisableMethod);
}

TEST_F(WriteProtectDisableMethodStateHandlerTest,
       GetNextStateCase_MissingArgs) {
  // Set up environment where multiple WP disabling methods are available.
  json_store_->SetValue(kSameOwner, true);
  json_store_->SetValue(kWpDisableRequired, true);
  json_store_->SetValue(kCcdBlocked, false);
  json_store_->SetValue(kWipeDevice, true);

  auto handler = CreateStateHandler();
  EXPECT_EQ(handler->InitializeState(), RMAD_ERROR_OK);

  RmadState state;
  state.mutable_wp_disable_method()->set_disable_method(
      WriteProtectDisableMethodState::RMAD_WP_DISABLE_UNKNOWN);

  auto [error, state_case] = handler->GetNextStateCase(state);
  EXPECT_EQ(error, RMAD_ERROR_REQUEST_ARGS_MISSING);
  EXPECT_EQ(state_case, RmadState::StateCase::kWpDisableMethod);
}

}  // namespace rmad
