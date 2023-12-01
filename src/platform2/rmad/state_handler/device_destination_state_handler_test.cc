// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <base/memory/scoped_refptr.h>
#include <gtest/gtest.h>

#include "rmad/constants.h"
#include "rmad/logs/logs_constants.h"
#include "rmad/logs/logs_utils.h"
#include "rmad/metrics/metrics_utils.h"
#include "rmad/state_handler/device_destination_state_handler.h"
#include "rmad/state_handler/state_handler_test_common.h"
#include "rmad/system/mock_cryptohome_client.h"
#include "rmad/utils/mock_write_protect_utils.h"

using testing::_;
using testing::DoAll;
using testing::Eq;
using testing::NiceMock;
using testing::Return;
using testing::SetArgPointee;

namespace rmad {

using ComponentRepairStatus = ComponentsRepairState::ComponentRepairStatus;

class DeviceDestinationStateHandlerTest : public StateHandlerTest {
 public:
  scoped_refptr<DeviceDestinationStateHandler> CreateStateHandler(
      bool ccd_blocked, bool hwwp_enabled) {
    // Mock |CryptohomeClient|.
    auto mock_cryptohome_client =
        std::make_unique<NiceMock<MockCryptohomeClient>>();
    ON_CALL(*mock_cryptohome_client, IsCcdBlocked())
        .WillByDefault(Return(ccd_blocked));
    // Mock |WriteProtectUtils|.
    auto mock_write_protect_utils =
        std::make_unique<NiceMock<MockWriteProtectUtils>>();
    ON_CALL(*mock_write_protect_utils, GetHardwareWriteProtectionStatus(_))
        .WillByDefault(DoAll(SetArgPointee<0>(hwwp_enabled), Return(true)));

    return base::MakeRefCounted<DeviceDestinationStateHandler>(
        json_store_, daemon_callback_, std::move(mock_cryptohome_client),
        std::move(mock_write_protect_utils));
  }
};

TEST_F(DeviceDestinationStateHandlerTest, InitializeState_Success) {
  auto handler = CreateStateHandler(false, true);
  EXPECT_EQ(handler->InitializeState(), RMAD_ERROR_OK);
}

TEST_F(DeviceDestinationStateHandlerTest,
       GetNextStateCase_Success_Same_WpDisableRequired_MlbRepair_CcdBlocked) {
  auto handler = CreateStateHandler(true, true);
  EXPECT_EQ(handler->InitializeState(), RMAD_ERROR_OK);

  json_store_->SetValue(kMlbRepair, true);

  RmadState state;
  state.mutable_device_destination()->set_destination(
      DeviceDestinationState::RMAD_DESTINATION_SAME);

  auto [error, state_case] = handler->GetNextStateCase(state);
  EXPECT_EQ(error, RMAD_ERROR_OK);
  EXPECT_EQ(state_case, RmadState::StateCase::kWipeSelection);

  bool same_owner;
  EXPECT_TRUE(json_store_->GetValue(kSameOwner, &same_owner));
  EXPECT_TRUE(same_owner);

  bool wp_disable_required;
  EXPECT_TRUE(json_store_->GetValue(kWpDisableRequired, &wp_disable_required));
  EXPECT_TRUE(wp_disable_required);

  bool ccd_blocked;
  EXPECT_TRUE(json_store_->GetValue(kCcdBlocked, &ccd_blocked));
  EXPECT_TRUE(ccd_blocked);

  bool wipe_device;
  EXPECT_FALSE(json_store_->GetValue(kWipeDevice, &wipe_device));

  base::Value logs(base::Value::Type::DICT);
  json_store_->GetValue(kLogs, &logs);

  const base::Value::List* events = logs.GetDict().FindList(kEvents);
  EXPECT_EQ(1, events->size());
  const base::Value::Dict& event = (*events)[0].GetDict();
  EXPECT_EQ(static_cast<int>(LogEventType::kData), event.FindInt(kType));
  EXPECT_EQ(
      ReturningOwner_Name(ReturningOwner::RMAD_RETURNING_OWNER_SAME_OWNER),
      *event.FindDict(kDetails)->FindString(kLogDestination));
}

TEST_F(
    DeviceDestinationStateHandlerTest,
    GetNextStateCase_Success_Same_WpDisableRequired_NonMlbRepair_CcdBlocked) {
  auto handler = CreateStateHandler(true, true);
  EXPECT_EQ(handler->InitializeState(), RMAD_ERROR_OK);

  json_store_->SetValue(kReplacedComponentNames,
                        std::vector<std::string>{
                            RmadComponent_Name(RMAD_COMPONENT_BASE_GYROSCOPE)});

  RmadState state;
  state.mutable_device_destination()->set_destination(
      DeviceDestinationState::RMAD_DESTINATION_SAME);

  auto [error, state_case] = handler->GetNextStateCase(state);
  EXPECT_EQ(error, RMAD_ERROR_OK);
  EXPECT_EQ(state_case, RmadState::StateCase::kWipeSelection);

  bool same_owner;
  EXPECT_TRUE(json_store_->GetValue(kSameOwner, &same_owner));
  EXPECT_TRUE(same_owner);

  bool wp_disable_required;
  EXPECT_TRUE(json_store_->GetValue(kWpDisableRequired, &wp_disable_required));
  EXPECT_TRUE(wp_disable_required);

  bool ccd_blocked;
  EXPECT_TRUE(json_store_->GetValue(kCcdBlocked, &ccd_blocked));
  EXPECT_TRUE(ccd_blocked);

  bool wipe_device;
  EXPECT_FALSE(json_store_->GetValue(kWipeDevice, &wipe_device));

  base::Value logs(base::Value::Type::DICT);
  json_store_->GetValue(kLogs, &logs);

  const base::Value::List* events = logs.GetDict().FindList(kEvents);
  EXPECT_EQ(1, events->size());
  const base::Value::Dict& event = (*events)[0].GetDict();
  EXPECT_EQ(static_cast<int>(LogEventType::kData), event.FindInt(kType));
  EXPECT_EQ(
      ReturningOwner_Name(ReturningOwner::RMAD_RETURNING_OWNER_SAME_OWNER),
      *event.FindDict(kDetails)->FindString(kLogDestination));
}

TEST_F(DeviceDestinationStateHandlerTest,
       GetNextStateCase_Success_Same_WpDisableRequired_CcdNotBlocked) {
  auto handler = CreateStateHandler(false, true);
  EXPECT_EQ(handler->InitializeState(), RMAD_ERROR_OK);

  json_store_->SetValue(kReplacedComponentNames,
                        std::vector<std::string>{
                            RmadComponent_Name(RMAD_COMPONENT_BASE_GYROSCOPE)});

  RmadState state;
  state.mutable_device_destination()->set_destination(
      DeviceDestinationState::RMAD_DESTINATION_SAME);

  auto [error, state_case] = handler->GetNextStateCase(state);
  EXPECT_EQ(error, RMAD_ERROR_OK);
  EXPECT_EQ(state_case, RmadState::StateCase::kWipeSelection);

  bool same_owner;
  EXPECT_TRUE(json_store_->GetValue(kSameOwner, &same_owner));
  EXPECT_TRUE(same_owner);

  bool wp_disable_required;
  EXPECT_TRUE(json_store_->GetValue(kWpDisableRequired, &wp_disable_required));
  EXPECT_TRUE(wp_disable_required);

  bool ccd_blocked;
  EXPECT_TRUE(json_store_->GetValue(kCcdBlocked, &ccd_blocked));
  EXPECT_FALSE(ccd_blocked);

  bool wipe_device;
  EXPECT_FALSE(json_store_->GetValue(kWipeDevice, &wipe_device));
}

TEST_F(DeviceDestinationStateHandlerTest,
       GetNextStateCase_Success_Same_WpDisableNotRequired) {
  auto handler = CreateStateHandler(false, true);
  EXPECT_EQ(handler->InitializeState(), RMAD_ERROR_OK);

  json_store_->SetValue(kReplacedComponentNames,
                        std::vector<RmadComponent>{RMAD_COMPONENT_KEYBOARD});

  RmadState state;
  state.mutable_device_destination()->set_destination(
      DeviceDestinationState::RMAD_DESTINATION_SAME);

  auto [error, state_case] = handler->GetNextStateCase(state);
  EXPECT_EQ(error, RMAD_ERROR_OK);
  EXPECT_EQ(state_case, RmadState::StateCase::kWipeSelection);

  bool same_owner;
  EXPECT_TRUE(json_store_->GetValue(kSameOwner, &same_owner));
  EXPECT_TRUE(same_owner);

  bool wp_disable_required;
  EXPECT_TRUE(json_store_->GetValue(kWpDisableRequired, &wp_disable_required));
  EXPECT_FALSE(wp_disable_required);

  bool ccd_blocked;
  EXPECT_FALSE(json_store_->GetValue(kCcdBlocked, &ccd_blocked));

  bool wipe_device;
  EXPECT_FALSE(json_store_->GetValue(kWipeDevice, &wipe_device));
}

TEST_F(DeviceDestinationStateHandlerTest,
       GetNextStateCase_Success_Different_CcdBlocked) {
  auto handler = CreateStateHandler(true, true);
  EXPECT_EQ(handler->InitializeState(), RMAD_ERROR_OK);

  RmadState state;
  state.mutable_device_destination()->set_destination(
      DeviceDestinationState::RMAD_DESTINATION_DIFFERENT);

  auto [error, state_case] = handler->GetNextStateCase(state);
  EXPECT_EQ(error, RMAD_ERROR_OK);
  EXPECT_EQ(state_case, RmadState::StateCase::kWpDisableRsu);

  bool same_owner;
  EXPECT_TRUE(json_store_->GetValue(kSameOwner, &same_owner));
  EXPECT_FALSE(same_owner);

  bool wp_disable_required;
  EXPECT_TRUE(json_store_->GetValue(kWpDisableRequired, &wp_disable_required));
  EXPECT_TRUE(wp_disable_required);

  bool ccd_blocked;
  EXPECT_TRUE(json_store_->GetValue(kCcdBlocked, &ccd_blocked));
  EXPECT_TRUE(ccd_blocked);

  bool wipe_device;
  EXPECT_TRUE(json_store_->GetValue(kWipeDevice, &wipe_device));
  EXPECT_TRUE(wipe_device);
}

TEST_F(DeviceDestinationStateHandlerTest,
       GetNextStateCase_Success_Different_CcdNotBlocked_HwwpDisabled) {
  auto handler = CreateStateHandler(false, false);
  EXPECT_EQ(handler->InitializeState(), RMAD_ERROR_OK);

  RmadState state;
  state.mutable_device_destination()->set_destination(
      DeviceDestinationState::RMAD_DESTINATION_DIFFERENT);

  auto [error, state_case] = handler->GetNextStateCase(state);
  EXPECT_EQ(error, RMAD_ERROR_OK);
  EXPECT_EQ(state_case, RmadState::StateCase::kWpDisablePhysical);

  bool same_owner;
  EXPECT_TRUE(json_store_->GetValue(kSameOwner, &same_owner));
  EXPECT_FALSE(same_owner);

  bool wp_disable_required;
  EXPECT_TRUE(json_store_->GetValue(kWpDisableRequired, &wp_disable_required));
  EXPECT_TRUE(wp_disable_required);

  bool ccd_blocked;
  EXPECT_TRUE(json_store_->GetValue(kCcdBlocked, &ccd_blocked));
  EXPECT_FALSE(ccd_blocked);

  bool wipe_device;
  EXPECT_TRUE(json_store_->GetValue(kWipeDevice, &wipe_device));
  EXPECT_TRUE(wipe_device);
}

TEST_F(DeviceDestinationStateHandlerTest,
       GetNextStateCase_Success_Different_CcdNotBlocked_HwwpEnabled) {
  auto handler = CreateStateHandler(false, true);
  EXPECT_EQ(handler->InitializeState(), RMAD_ERROR_OK);

  RmadState state;
  state.mutable_device_destination()->set_destination(
      DeviceDestinationState::RMAD_DESTINATION_DIFFERENT);

  auto [error, state_case] = handler->GetNextStateCase(state);
  EXPECT_EQ(error, RMAD_ERROR_OK);
  EXPECT_EQ(state_case, RmadState::StateCase::kWpDisableMethod);

  bool same_owner;
  EXPECT_TRUE(json_store_->GetValue(kSameOwner, &same_owner));
  EXPECT_FALSE(same_owner);

  bool wp_disable_required;
  EXPECT_TRUE(json_store_->GetValue(kWpDisableRequired, &wp_disable_required));
  EXPECT_TRUE(wp_disable_required);

  bool ccd_blocked;
  EXPECT_TRUE(json_store_->GetValue(kCcdBlocked, &ccd_blocked));
  EXPECT_FALSE(ccd_blocked);

  bool wipe_device;
  EXPECT_TRUE(json_store_->GetValue(kWipeDevice, &wipe_device));
  EXPECT_TRUE(wipe_device);
}

}  // namespace rmad
