// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "rmad/state_handler/setup_calibration_state_handler.h"

#include <map>
#include <memory>
#include <set>
#include <string>

#include <base/files/file_util.h>
#include <base/strings/string_number_conversions.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "rmad/logs/logs_constants.h"
#include "rmad/state_handler/state_handler_test_common.h"
#include "rmad/utils/calibration_utils.h"

using testing::_;
using testing::Assign;
using testing::DoAll;
using testing::NiceMock;
using testing::Return;
using testing::StrictMock;

namespace {

constexpr char kBaseInstructionName[] =
    "RMAD_CALIBRATION_INSTRUCTION_PLACE_BASE_ON_FLAT_SURFACE";
constexpr char kLidInstructionName[] =
    "RMAD_CALIBRATION_INSTRUCTION_PLACE_LID_ON_FLAT_SURFACE";

constexpr char kBaseAccName[] = "RMAD_COMPONENT_BASE_ACCELEROMETER";
constexpr char kLidAccName[] = "RMAD_COMPONENT_LID_ACCELEROMETER";
constexpr char kBaseGyroName[] = "RMAD_COMPONENT_BASE_GYROSCOPE";
constexpr char kLidGyroName[] = "RMAD_COMPONENT_LID_GYROSCOPE";

constexpr char kStatusWaitingName[] = "RMAD_CALIBRATION_WAITING";
constexpr char kStatusCompleteName[] = "RMAD_CALIBRATION_COMPLETE";
constexpr char kStatusInProgressName[] = "RMAD_CALIBRATION_IN_PROGRESS";
constexpr char kStatusSkipName[] = "RMAD_CALIBRATION_SKIP";
constexpr char kStatusFailedName[] = "RMAD_CALIBRATION_FAILED";

}  // namespace

namespace rmad {

class SetupCalibrationStateHandlerTest : public StateHandlerTest {
 public:
  scoped_refptr<SetupCalibrationStateHandler> CreateStateHandler() {
    return base::MakeRefCounted<SetupCalibrationStateHandler>(json_store_,
                                                              daemon_callback_);
  }
};

TEST_F(SetupCalibrationStateHandlerTest, InitializeState_Success) {
  const std::map<std::string, std::map<std::string, std::string>>
      predefined_calibration_map = {{kBaseInstructionName,
                                     {{kBaseAccName, kStatusWaitingName},
                                      {kBaseGyroName, kStatusWaitingName}}},
                                    {kLidInstructionName,
                                     {{kLidAccName, kStatusWaitingName},
                                      {kLidGyroName, kStatusWaitingName}}}};
  EXPECT_TRUE(
      json_store_->SetValue(kCalibrationMap, predefined_calibration_map));

  auto handler = CreateStateHandler();
  EXPECT_EQ(handler->InitializeState(), RMAD_ERROR_OK);
}

TEST_F(SetupCalibrationStateHandlerTest,
       InitializeState_FailedCalibrationMapNotSet) {
  auto handler = CreateStateHandler();
  EXPECT_EQ(handler->InitializeState(),
            RMAD_ERROR_STATE_HANDLER_INITIALIZATION_FAILED);
}

TEST_F(SetupCalibrationStateHandlerTest,
       InitializeState_SuccessNotFinishedComponent) {
  const std::map<std::string, std::map<std::string, std::string>>
      predefined_calibration_map = {{kBaseInstructionName,
                                     {{kBaseAccName, kStatusInProgressName},
                                      {kBaseGyroName, kStatusInProgressName}}},
                                    {kLidInstructionName,
                                     {{kLidAccName, kStatusWaitingName},
                                      {kLidGyroName, kStatusWaitingName}}}};
  EXPECT_TRUE(
      json_store_->SetValue(kCalibrationMap, predefined_calibration_map));

  auto handler = CreateStateHandler();
  EXPECT_EQ(handler->InitializeState(), RMAD_ERROR_OK);
}

TEST_F(SetupCalibrationStateHandlerTest, InitializeState_JsonFailed) {
  // Since we are not allowed to be in-progress in the setup state, we can set
  // base acc to in-progress to ensure that the change (in-progress -> failed)
  // will happen in the calibration map. Then, we can test the writing part of
  // the json file.
  const std::map<std::string, std::map<std::string, std::string>>
      predefined_calibration_map = {{kBaseInstructionName,
                                     {{kBaseAccName, kStatusInProgressName},
                                      {kBaseGyroName, kStatusWaitingName}}},
                                    {kLidInstructionName,
                                     {{kLidAccName, kStatusWaitingName},
                                      {kLidGyroName, kStatusWaitingName}}}};
  EXPECT_TRUE(
      json_store_->SetValue(kCalibrationMap, predefined_calibration_map));
  base::SetPosixFilePermissions(GetStateFilePath(), 0444);
  auto handler = CreateStateHandler();
  EXPECT_EQ(handler->InitializeState(),
            RMAD_ERROR_STATE_HANDLER_INITIALIZATION_FAILED);
}

TEST_F(SetupCalibrationStateHandlerTest, GetNextStateCase_Success) {
  EXPECT_TRUE(json_store_->SetValue(kWipeDevice, true));

  const std::map<std::string, std::map<std::string, std::string>>
      predefined_calibration_map = {{kBaseInstructionName,
                                     {{kBaseAccName, kStatusWaitingName},
                                      {kBaseGyroName, kStatusWaitingName}}},
                                    {kLidInstructionName,
                                     {{kLidAccName, kStatusWaitingName},
                                      {kLidGyroName, kStatusWaitingName}}}};
  EXPECT_TRUE(
      json_store_->SetValue(kCalibrationMap, predefined_calibration_map));

  auto handler = CreateStateHandler();
  EXPECT_EQ(handler->InitializeState(), RMAD_ERROR_OK);

  RmadState state = handler->GetState();
  auto [error, state_case] = handler->GetNextStateCase(state);
  EXPECT_EQ(error, RMAD_ERROR_OK);
  EXPECT_EQ(state_case, RmadState::StateCase::kRunCalibration);

  // Verify the setup instruction was recorded to logs.
  base::Value logs(base::Value::Type::DICT);
  json_store_->GetValue(kLogs, &logs);

  const base::Value::List* events = logs.GetDict().FindList(kEvents);
  EXPECT_EQ(1, events->size());
  const base::Value::Dict& event = (*events)[0].GetDict();
  EXPECT_EQ(static_cast<int>(RmadState::kSetupCalibration),
            event.FindInt(kStateId));
  EXPECT_EQ(static_cast<int>(LogEventType::kData), event.FindInt(kType));
  EXPECT_EQ(
      static_cast<int>(RMAD_CALIBRATION_INSTRUCTION_PLACE_BASE_ON_FLAT_SURFACE),
      *event.FindDict(kDetails)->FindInt(kLogCalibrationSetupInstruction));
}

TEST_F(SetupCalibrationStateHandlerTest,
       GetNextStateCase_SuccessNoNeedCalibration) {
  EXPECT_TRUE(json_store_->SetValue(kWipeDevice, true));

  const std::map<std::string, std::map<std::string, std::string>>
      predefined_calibration_map = {{kBaseInstructionName,
                                     {{kBaseAccName, kStatusCompleteName},
                                      {kBaseGyroName, kStatusCompleteName}}},
                                    {kLidInstructionName,
                                     {{kLidAccName, kStatusSkipName},
                                      {kLidGyroName, kStatusCompleteName}}}};
  EXPECT_TRUE(
      json_store_->SetValue(kCalibrationMap, predefined_calibration_map));

  auto handler = CreateStateHandler();
  EXPECT_EQ(handler->InitializeState(), RMAD_ERROR_OK);

  RmadState state = handler->GetState();
  auto [error, state_case] = handler->GetNextStateCase(state);
  EXPECT_EQ(error, RMAD_ERROR_OK);
  EXPECT_EQ(state_case, RmadState::StateCase::kFinalize);

  // Verify no setup instruction was recorded to logs.
  base::Value logs(base::Value::Type::DICT);
  EXPECT_FALSE(json_store_->GetValue(kLogs, &logs));
}

TEST_F(SetupCalibrationStateHandlerTest,
       GetNextStateCase_SuccessNoNeedCalibration_NoWipeDevice) {
  EXPECT_TRUE(json_store_->SetValue(kWipeDevice, false));

  const std::map<std::string, std::map<std::string, std::string>>
      predefined_calibration_map = {{kBaseInstructionName,
                                     {{kBaseAccName, kStatusCompleteName},
                                      {kBaseGyroName, kStatusCompleteName}}},
                                    {kLidInstructionName,
                                     {{kLidAccName, kStatusSkipName},
                                      {kLidGyroName, kStatusCompleteName}}}};
  EXPECT_TRUE(
      json_store_->SetValue(kCalibrationMap, predefined_calibration_map));

  auto handler = CreateStateHandler();
  EXPECT_EQ(handler->InitializeState(), RMAD_ERROR_OK);

  RmadState state = handler->GetState();
  auto [error, state_case] = handler->GetNextStateCase(state);
  EXPECT_EQ(error, RMAD_ERROR_OK);
  EXPECT_EQ(state_case, RmadState::StateCase::kWpEnablePhysical);
}

TEST_F(SetupCalibrationStateHandlerTest, GetNextStateCase_SuccessNoSensor) {
  EXPECT_TRUE(json_store_->SetValue(kWipeDevice, true));
  EXPECT_TRUE(SetCalibrationMap(json_store_, {}));

  auto handler = CreateStateHandler();
  EXPECT_EQ(handler->InitializeState(), RMAD_ERROR_OK);

  RmadState state = handler->GetState();
  auto [error, state_case] = handler->GetNextStateCase(state);
  EXPECT_EQ(error, RMAD_ERROR_OK);
  EXPECT_EQ(state_case, RmadState::StateCase::kFinalize);
}

TEST_F(SetupCalibrationStateHandlerTest,
       GetNextStateCase_SuccessNoSensor_NoWipeDevice) {
  EXPECT_TRUE(json_store_->SetValue(kWipeDevice, false));
  EXPECT_TRUE(SetCalibrationMap(json_store_, {}));

  auto handler = CreateStateHandler();
  EXPECT_EQ(handler->InitializeState(), RMAD_ERROR_OK);

  RmadState state = handler->GetState();
  auto [error, state_case] = handler->GetNextStateCase(state);
  EXPECT_EQ(error, RMAD_ERROR_OK);
  EXPECT_EQ(state_case, RmadState::StateCase::kWpEnablePhysical);
}

TEST_F(SetupCalibrationStateHandlerTest, GetNextStateCase_SuccessNeedToCheck) {
  EXPECT_TRUE(json_store_->SetValue(kWipeDevice, true));

  const std::map<std::string, std::map<std::string, std::string>>
      predefined_calibration_map = {{kBaseInstructionName,
                                     {{kBaseAccName, kStatusFailedName},
                                      {kBaseGyroName, kStatusCompleteName}}},
                                    {kLidInstructionName,
                                     {{kLidAccName, kStatusFailedName},
                                      {kLidGyroName, kStatusCompleteName}}}};
  EXPECT_TRUE(
      json_store_->SetValue(kCalibrationMap, predefined_calibration_map));

  auto handler = CreateStateHandler();
  EXPECT_EQ(handler->InitializeState(), RMAD_ERROR_OK);

  RmadState state = handler->GetState();
  auto [error, state_case] = handler->GetNextStateCase(state);
  EXPECT_EQ(error, RMAD_ERROR_OK);
  EXPECT_EQ(state_case, RmadState::StateCase::kCheckCalibration);
}

TEST_F(SetupCalibrationStateHandlerTest,
       GetNextStateCase_SuccessNeedToCheckAutoTransition) {
  EXPECT_TRUE(json_store_->SetValue(kWipeDevice, true));

  const std::map<std::string, std::map<std::string, std::string>>
      predefined_calibration_map = {{kBaseInstructionName,
                                     {{kBaseAccName, kStatusFailedName},
                                      {kBaseGyroName, kStatusCompleteName}}},
                                    {kLidInstructionName,
                                     {{kLidAccName, kStatusFailedName},
                                      {kLidGyroName, kStatusCompleteName}}}};
  EXPECT_TRUE(
      json_store_->SetValue(kCalibrationMap, predefined_calibration_map));

  auto handler = CreateStateHandler();
  EXPECT_EQ(handler->InitializeState(), RMAD_ERROR_OK);

  // Simulate the auto-transition scenario
  RmadState state = handler->GetState();

  auto [error, state_case] = handler->GetNextStateCase(state);
  EXPECT_EQ(error, RMAD_ERROR_OK);
  EXPECT_EQ(state_case, RmadState::StateCase::kCheckCalibration);
}

TEST_F(SetupCalibrationStateHandlerTest, GetNextStateCase_MissingState) {
  EXPECT_TRUE(json_store_->SetValue(kWipeDevice, true));
  EXPECT_TRUE(SetCalibrationMap(json_store_, {}));

  auto handler = CreateStateHandler();
  EXPECT_EQ(handler->InitializeState(), RMAD_ERROR_OK);

  // No SetupCalibrationState.
  RmadState state;

  auto [error, state_case] = handler->GetNextStateCase(state);
  EXPECT_EQ(error, RMAD_ERROR_REQUEST_INVALID);
  EXPECT_EQ(state_case, RmadState::StateCase::kSetupCalibration);
}

TEST_F(SetupCalibrationStateHandlerTest,
       GetNextStateCase_MissingWipeDeviceVar) {
  // No kWipeDevice set.

  const std::map<std::string, std::map<std::string, std::string>>
      predefined_calibration_map = {{kBaseInstructionName,
                                     {{kBaseAccName, kStatusFailedName},
                                      {kBaseGyroName, kStatusCompleteName}}},
                                    {kLidInstructionName,
                                     {{kLidAccName, kStatusFailedName},
                                      {kLidGyroName, kStatusCompleteName}}}};
  EXPECT_TRUE(
      json_store_->SetValue(kCalibrationMap, predefined_calibration_map));

  auto handler = CreateStateHandler();
  EXPECT_EQ(handler->InitializeState(), RMAD_ERROR_OK);

  RmadState state = handler->GetState();
  auto [error, state_case] = handler->GetNextStateCase(state);
  EXPECT_EQ(error, RMAD_ERROR_TRANSITION_FAILED);
  EXPECT_EQ(state_case, RmadState::StateCase::kSetupCalibration);
}

TEST_F(SetupCalibrationStateHandlerTest,
       GetNextStateCase_ReadOnlyInstructionChanged) {
  EXPECT_TRUE(json_store_->SetValue(kWipeDevice, true));

  const std::map<std::string, std::map<std::string, std::string>>
      predefined_calibration_map = {{kBaseInstructionName,
                                     {{kBaseAccName, kStatusWaitingName},
                                      {kBaseGyroName, kStatusWaitingName}}},
                                    {kLidInstructionName,
                                     {{kLidAccName, kStatusCompleteName},
                                      {kLidGyroName, kStatusCompleteName}}}};
  EXPECT_TRUE(
      json_store_->SetValue(kCalibrationMap, predefined_calibration_map));

  auto handler = CreateStateHandler();
  EXPECT_EQ(handler->InitializeState(), RMAD_ERROR_OK);

  RmadState state = handler->GetState();
  auto setup_calibration_state =
      std::make_unique<SetupCalibrationState>(state.setup_calibration());
  setup_calibration_state->set_instruction(
      RMAD_CALIBRATION_INSTRUCTION_PLACE_LID_ON_FLAT_SURFACE);
  state.set_allocated_setup_calibration(setup_calibration_state.release());

  auto [error, state_case] = handler->GetNextStateCase(state);
  EXPECT_EQ(error, RMAD_ERROR_REQUEST_INVALID);
  EXPECT_EQ(state_case, RmadState::StateCase::kSetupCalibration);
}

TEST_F(SetupCalibrationStateHandlerTest, GetNextStateCase_NotInitialized) {
  EXPECT_TRUE(json_store_->SetValue(kWipeDevice, true));

  const std::map<std::string, std::map<std::string, std::string>>
      predefined_calibration_map = {{kBaseInstructionName,
                                     {{kBaseAccName, kStatusWaitingName},
                                      {kBaseGyroName, kStatusWaitingName}}},
                                    {kLidInstructionName,
                                     {{kLidAccName, kStatusCompleteName},
                                      {kLidGyroName, kStatusCompleteName}}}};
  EXPECT_TRUE(
      json_store_->SetValue(kCalibrationMap, predefined_calibration_map));

  auto handler = CreateStateHandler();

  RmadState state;
  auto setup_calibration_state = std::make_unique<SetupCalibrationState>();
  state.set_allocated_setup_calibration(setup_calibration_state.release());

  // In order to be further checked by the user in kCheckCalibration, it should
  // return OK for transition.
  auto [error, state_case] = handler->GetNextStateCase(state);
  EXPECT_EQ(error, RMAD_ERROR_OK);
  EXPECT_EQ(state_case, RmadState::StateCase::kCheckCalibration);
}

TEST_F(SetupCalibrationStateHandlerTest, TryGetNextStateCaseAtBoot_Success) {
  EXPECT_TRUE(json_store_->SetValue(kWipeDevice, true));

  const std::map<std::string, std::map<std::string, std::string>>
      predefined_calibration_map = {{kBaseInstructionName,
                                     {{kBaseAccName, kStatusWaitingName},
                                      {kBaseGyroName, kStatusWaitingName}}},
                                    {kLidInstructionName,
                                     {{kLidAccName, kStatusWaitingName},
                                      {kLidGyroName, kStatusWaitingName}}}};
  EXPECT_TRUE(
      json_store_->SetValue(kCalibrationMap, predefined_calibration_map));

  auto handler = CreateStateHandler();
  EXPECT_EQ(handler->InitializeState(), RMAD_ERROR_OK);

  auto [error, state_case] = handler->TryGetNextStateCaseAtBoot();
  EXPECT_EQ(error, RMAD_ERROR_TRANSITION_FAILED);
  EXPECT_EQ(state_case, RmadState::StateCase::kSetupCalibration);
}

TEST_F(SetupCalibrationStateHandlerTest,
       TryGetNextStateCaseAtBoot_SuccessNeedToCheck) {
  EXPECT_TRUE(json_store_->SetValue(kWipeDevice, true));

  const std::map<std::string, std::map<std::string, std::string>>
      predefined_calibration_map = {{kBaseInstructionName,
                                     {{kBaseAccName, kStatusFailedName},
                                      {kBaseGyroName, kStatusCompleteName}}},
                                    {kLidInstructionName,
                                     {{kLidAccName, kStatusFailedName},
                                      {kLidGyroName, kStatusCompleteName}}}};
  EXPECT_TRUE(
      json_store_->SetValue(kCalibrationMap, predefined_calibration_map));

  auto handler = CreateStateHandler();
  EXPECT_EQ(handler->InitializeState(), RMAD_ERROR_OK);

  auto [error, state_case] = handler->TryGetNextStateCaseAtBoot();
  EXPECT_EQ(error, RMAD_ERROR_OK);
  EXPECT_EQ(state_case, RmadState::StateCase::kCheckCalibration);
}

}  // namespace rmad
