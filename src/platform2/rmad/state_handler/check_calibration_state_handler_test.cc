// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "rmad/state_handler/check_calibration_state_handler.h"

#include <map>
#include <memory>
#include <set>
#include <string>
#include <utility>

#include <base/files/file_util.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "rmad/logs/logs_constants.h"
#include "rmad/state_handler/state_handler_test_common.h"

using testing::_;
using testing::DoAll;
using testing::Invoke;
using testing::NiceMock;
using testing::Return;

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

class CheckCalibrationStateHandlerTest : public StateHandlerTest {
 public:
  scoped_refptr<CheckCalibrationStateHandler> CreateStateHandler() {
    return base::MakeRefCounted<CheckCalibrationStateHandler>(json_store_,
                                                              daemon_callback_);
  }

 protected:
  void SetUp() override { StateHandlerTest::SetUp(); }
};

TEST_F(CheckCalibrationStateHandlerTest, InitializeState_Success) {
  EXPECT_TRUE(SetCalibrationMap(json_store_, {}));
  auto handler = CreateStateHandler();
  EXPECT_EQ(handler->InitializeState(), RMAD_ERROR_OK);
}

TEST_F(CheckCalibrationStateHandlerTest,
       InitializeState_SuccessUnknownComponentProbed) {
  const std::map<std::string, std::map<std::string, std::string>>
      predefined_calibration_map = {{kBaseInstructionName,
                                     {{kBaseAccName, kStatusCompleteName},
                                      {kBaseGyroName, kStatusCompleteName}}},
                                    {kLidInstructionName,
                                     {{kLidAccName, kStatusCompleteName},
                                      {kLidGyroName, kStatusCompleteName}}}};
  EXPECT_TRUE(
      json_store_->SetValue(kCalibrationMap, predefined_calibration_map));

  auto handler = CreateStateHandler();
  EXPECT_EQ(handler->InitializeState(), RMAD_ERROR_OK);
}

TEST_F(CheckCalibrationStateHandlerTest,
       InitializeState_SuccessInvalidComponentProbed) {
  const std::map<std::string, std::map<std::string, std::string>>
      predefined_calibration_map = {{kBaseInstructionName,
                                     {{kBaseAccName, kStatusCompleteName},
                                      {kBaseGyroName, kStatusCompleteName}}},
                                    {kLidInstructionName,
                                     {{kLidAccName, kStatusCompleteName},
                                      {kLidGyroName, kStatusCompleteName}}}};
  EXPECT_TRUE(
      json_store_->SetValue(kCalibrationMap, predefined_calibration_map));

  auto handler = CreateStateHandler();
  EXPECT_EQ(handler->InitializeState(), RMAD_ERROR_OK);
}

TEST_F(CheckCalibrationStateHandlerTest,
       InitializeState_SuccessUndeterminedStatus) {
  const std::map<std::string, std::map<std::string, std::string>>
      predefined_calibration_map = {{kBaseInstructionName,
                                     {{kBaseAccName, kStatusCompleteName},
                                      {kBaseGyroName, kStatusCompleteName}}},
                                    {kLidInstructionName,
                                     {{kLidAccName, kStatusInProgressName},
                                      {kLidGyroName, kStatusInProgressName}}}};
  EXPECT_TRUE(
      json_store_->SetValue(kCalibrationMap, predefined_calibration_map));

  auto handler = CreateStateHandler();
  EXPECT_EQ(handler->InitializeState(), RMAD_ERROR_OK);

  // All undetermined statuses should be marked as failed, because we expect
  // everything to be done in this state.
  std::map<std::string, std::map<std::string, std::string>>
      current_calibration_map;
  EXPECT_TRUE(json_store_->GetValue(kCalibrationMap, &current_calibration_map));
  const std::map<std::string, std::map<std::string, std::string>>
      target_calibration_map = {{kBaseInstructionName,
                                 {{kBaseAccName, kStatusCompleteName},
                                  {kBaseGyroName, kStatusCompleteName}}},
                                {kLidInstructionName,
                                 {{kLidAccName, kStatusFailedName},
                                  {kLidGyroName, kStatusFailedName}}}};
  EXPECT_EQ(current_calibration_map, target_calibration_map);
}

TEST_F(CheckCalibrationStateHandlerTest, InitializeState_JsonFailed) {
  const std::map<std::string, std::map<std::string, std::string>>
      predefined_calibration_map = {{kBaseInstructionName,
                                     {{kBaseAccName, kStatusCompleteName},
                                      {kBaseGyroName, kStatusCompleteName}}},
                                    {kLidInstructionName,
                                     {{kLidAccName, kStatusInProgressName},
                                      {kLidGyroName, kStatusInProgressName}}}};
  EXPECT_TRUE(
      json_store_->SetValue(kCalibrationMap, predefined_calibration_map));

  base::SetPosixFilePermissions(GetStateFilePath(), 0444);

  auto handler = CreateStateHandler();
  EXPECT_EQ(handler->InitializeState(),
            RMAD_ERROR_STATE_HANDLER_INITIALIZATION_FAILED);
}

TEST_F(CheckCalibrationStateHandlerTest, GetNextStateCase_Success_WipeDevice) {
  EXPECT_TRUE(json_store_->SetValue(kWipeDevice, true));

  const std::map<std::string, std::map<std::string, std::string>>
      predefined_calibration_map = {{kBaseInstructionName,
                                     {{kBaseAccName, kStatusCompleteName},
                                      {kBaseGyroName, kStatusCompleteName}}},
                                    {kLidInstructionName,
                                     {{kLidAccName, kStatusCompleteName},
                                      {kLidGyroName, kStatusCompleteName}}}};
  EXPECT_TRUE(
      json_store_->SetValue(kCalibrationMap, predefined_calibration_map));

  auto handler = CreateStateHandler();
  EXPECT_EQ(handler->InitializeState(), RMAD_ERROR_OK);

  RmadState state = handler->GetState();

  auto [error, state_case] = handler->GetNextStateCase(state);
  EXPECT_EQ(error, RMAD_ERROR_OK);
  EXPECT_EQ(state_case, RmadState::StateCase::kFinalize);

  std::map<std::string, std::map<std::string, std::string>>
      current_calibration_map;
  EXPECT_TRUE(json_store_->GetValue(kCalibrationMap, &current_calibration_map));

  const std::map<std::string, std::map<std::string, std::string>>
      target_calibration_map = {{kBaseInstructionName,
                                 {{kBaseAccName, kStatusCompleteName},
                                  {kBaseGyroName, kStatusCompleteName}}},
                                {kLidInstructionName,
                                 {{kLidAccName, kStatusCompleteName},
                                  {kLidGyroName, kStatusCompleteName}}}};

  EXPECT_EQ(current_calibration_map, target_calibration_map);
}

TEST_F(CheckCalibrationStateHandlerTest,
       GetNextStateCase_Success_NoWipeDevice) {
  EXPECT_TRUE(json_store_->SetValue(kWipeDevice, false));

  const std::map<std::string, std::map<std::string, std::string>>
      predefined_calibration_map = {{kBaseInstructionName,
                                     {{kBaseAccName, kStatusCompleteName},
                                      {kBaseGyroName, kStatusCompleteName}}},
                                    {kLidInstructionName,
                                     {{kLidAccName, kStatusCompleteName},
                                      {kLidGyroName, kStatusCompleteName}}}};
  EXPECT_TRUE(
      json_store_->SetValue(kCalibrationMap, predefined_calibration_map));

  auto handler = CreateStateHandler();
  EXPECT_EQ(handler->InitializeState(), RMAD_ERROR_OK);

  RmadState state = handler->GetState();

  auto [error, state_case] = handler->GetNextStateCase(state);
  EXPECT_EQ(error, RMAD_ERROR_OK);
  EXPECT_EQ(state_case, RmadState::StateCase::kWpEnablePhysical);

  std::map<std::string, std::map<std::string, std::string>>
      current_calibration_map;
  EXPECT_TRUE(json_store_->GetValue(kCalibrationMap, &current_calibration_map));

  const std::map<std::string, std::map<std::string, std::string>>
      target_calibration_map = {{kBaseInstructionName,
                                 {{kBaseAccName, kStatusCompleteName},
                                  {kBaseGyroName, kStatusCompleteName}}},
                                {kLidInstructionName,
                                 {{kLidAccName, kStatusCompleteName},
                                  {kLidGyroName, kStatusCompleteName}}}};

  EXPECT_EQ(current_calibration_map, target_calibration_map);
}

TEST_F(CheckCalibrationStateHandlerTest,
       GetNextStateCase_SuccessNeedCalibration) {
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
  handler->RunState();

  std::unique_ptr<CheckCalibrationState> check_calibration =
      std::make_unique<CheckCalibrationState>();
  auto base_accelerometer = check_calibration->add_components();
  base_accelerometer->set_component(RMAD_COMPONENT_BASE_ACCELEROMETER);
  base_accelerometer->set_status(
      CalibrationComponentStatus::RMAD_CALIBRATION_WAITING);
  auto lid_accelerometer = check_calibration->add_components();
  lid_accelerometer->set_component(RMAD_COMPONENT_LID_ACCELEROMETER);
  lid_accelerometer->set_status(
      CalibrationComponentStatus::RMAD_CALIBRATION_WAITING);
  auto base_gyroscope = check_calibration->add_components();
  base_gyroscope->set_component(RMAD_COMPONENT_BASE_GYROSCOPE);
  base_gyroscope->set_status(
      CalibrationComponentStatus::RMAD_CALIBRATION_COMPLETE);
  auto lid_gyroscope = check_calibration->add_components();
  lid_gyroscope->set_component(RMAD_COMPONENT_LID_GYROSCOPE);
  lid_gyroscope->set_status(
      CalibrationComponentStatus::RMAD_CALIBRATION_COMPLETE);

  RmadState state;
  state.set_allocated_check_calibration(check_calibration.release());

  auto [error, state_case] = handler->GetNextStateCase(state);
  EXPECT_EQ(error, RMAD_ERROR_OK);
  EXPECT_EQ(state_case, RmadState::StateCase::kSetupCalibration);

  std::map<std::string, std::map<std::string, std::string>>
      current_calibration_map;
  EXPECT_TRUE(json_store_->GetValue(kCalibrationMap, &current_calibration_map));

  const std::map<std::string, std::map<std::string, std::string>>
      target_calibration_map = {{kBaseInstructionName,
                                 {{kBaseAccName, kStatusWaitingName},
                                  {kBaseGyroName, kStatusCompleteName}}},
                                {kLidInstructionName,
                                 {{kLidAccName, kStatusWaitingName},
                                  {kLidGyroName, kStatusCompleteName}}}};

  EXPECT_EQ(current_calibration_map, target_calibration_map);

  // Verify the failed and retried calibrations were recorded to logs.
  base::Value logs(base::Value::Type::DICT);
  json_store_->GetValue(kLogs, &logs);

  const base::Value::List* events = logs.GetDict().FindList(kEvents);
  const base::Value::List* skipped_components =
      (*events)[0].GetDict().FindDict(kDetails)->FindList(
          kLogCalibrationComponents);
  EXPECT_EQ(2, skipped_components->size());
  EXPECT_EQ(kBaseAccName,
            *(*skipped_components)[0].GetDict().FindString(kLogComponent));
  EXPECT_EQ(static_cast<int>(LogCalibrationStatus::kFailed),
            (*skipped_components)[0].GetDict().FindInt(kLogCalibrationStatus));
  EXPECT_EQ(kLidAccName,
            *(*skipped_components)[1].GetDict().FindString(kLogComponent));
  EXPECT_EQ(static_cast<int>(LogCalibrationStatus::kFailed),
            (*skipped_components)[1].GetDict().FindInt(kLogCalibrationStatus));

  const base::Value::List* retry_components =
      (*events)[1].GetDict().FindDict(kDetails)->FindList(
          kLogCalibrationComponents);
  EXPECT_EQ(2, retry_components->size());
  EXPECT_EQ(kBaseAccName,
            *(*retry_components)[0].GetDict().FindString(kLogComponent));
  EXPECT_EQ(static_cast<int>(LogCalibrationStatus::kRetry),
            (*retry_components)[0].GetDict().FindInt(kLogCalibrationStatus));
  EXPECT_EQ(kLidAccName,
            *(*retry_components)[1].GetDict().FindString(kLogComponent));
  EXPECT_EQ(static_cast<int>(LogCalibrationStatus::kRetry),
            (*retry_components)[1].GetDict().FindInt(kLogCalibrationStatus));
}

TEST_F(CheckCalibrationStateHandlerTest, GetNextStateCase_SuccessSkipSensors) {
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
  handler->RunState();

  std::unique_ptr<CheckCalibrationState> check_calibration =
      std::make_unique<CheckCalibrationState>();
  auto base_accelerometer = check_calibration->add_components();
  base_accelerometer->set_component(RMAD_COMPONENT_BASE_ACCELEROMETER);
  base_accelerometer->set_status(
      CalibrationComponentStatus::RMAD_CALIBRATION_SKIP);
  auto lid_accelerometer = check_calibration->add_components();
  lid_accelerometer->set_component(RMAD_COMPONENT_LID_ACCELEROMETER);
  lid_accelerometer->set_status(
      CalibrationComponentStatus::RMAD_CALIBRATION_SKIP);
  auto base_gyroscope = check_calibration->add_components();
  base_gyroscope->set_component(RMAD_COMPONENT_BASE_GYROSCOPE);
  base_gyroscope->set_status(
      CalibrationComponentStatus::RMAD_CALIBRATION_COMPLETE);
  auto lid_gyroscope = check_calibration->add_components();
  lid_gyroscope->set_component(RMAD_COMPONENT_LID_GYROSCOPE);
  lid_gyroscope->set_status(
      CalibrationComponentStatus::RMAD_CALIBRATION_COMPLETE);

  RmadState state;
  state.set_allocated_check_calibration(check_calibration.release());

  auto [error, state_case] = handler->GetNextStateCase(state);
  EXPECT_EQ(error, RMAD_ERROR_OK);
  EXPECT_EQ(state_case, RmadState::StateCase::kFinalize);

  std::map<std::string, std::map<std::string, std::string>>
      current_calibration_map;
  EXPECT_TRUE(json_store_->GetValue(kCalibrationMap, &current_calibration_map));

  const std::map<std::string, std::map<std::string, std::string>>
      target_calibration_map = {{kBaseInstructionName,
                                 {{kBaseAccName, kStatusSkipName},
                                  {kBaseGyroName, kStatusCompleteName}}},
                                {kLidInstructionName,
                                 {{kLidAccName, kStatusSkipName},
                                  {kLidGyroName, kStatusCompleteName}}}};

  EXPECT_EQ(current_calibration_map, target_calibration_map);

  // Verify the skipped calibrations were recorded to logs.
  base::Value logs(base::Value::Type::DICT);
  json_store_->GetValue(kLogs, &logs);

  const base::Value::List* events = logs.GetDict().FindList(kEvents);
  const base::Value::List* components =
      (*events)[1].GetDict().FindDict(kDetails)->FindList(
          kLogCalibrationComponents);
  EXPECT_EQ(2, components->size());
  EXPECT_EQ(kBaseAccName,
            *(*components)[0].GetDict().FindString(kLogComponent));
  EXPECT_EQ(static_cast<int>(LogCalibrationStatus::kSkip),
            (*components)[0].GetDict().FindInt(kLogCalibrationStatus));
  EXPECT_EQ(kLidAccName, *(*components)[1].GetDict().FindString(kLogComponent));
  EXPECT_EQ(static_cast<int>(LogCalibrationStatus::kSkip),
            (*components)[1].GetDict().FindInt(kLogCalibrationStatus));
}

TEST_F(CheckCalibrationStateHandlerTest, GetNextStateCase_WrongComponentsSize) {
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

  std::unique_ptr<CheckCalibrationState> check_calibration =
      std::make_unique<CheckCalibrationState>();
  auto base_accelerometer = check_calibration->add_components();
  base_accelerometer->set_component(RMAD_COMPONENT_BASE_ACCELEROMETER);
  base_accelerometer->set_status(
      CalibrationComponentStatus::RMAD_CALIBRATION_SKIP);
  auto lid_accelerometer = check_calibration->add_components();
  lid_accelerometer->set_component(RMAD_COMPONENT_LID_ACCELEROMETER);
  lid_accelerometer->set_status(
      CalibrationComponentStatus::RMAD_CALIBRATION_SKIP);
  auto base_gyroscope = check_calibration->add_components();
  base_gyroscope->set_component(RMAD_COMPONENT_BASE_GYROSCOPE);
  base_gyroscope->set_status(
      CalibrationComponentStatus::RMAD_CALIBRATION_COMPLETE);

  RmadState state;
  state.set_allocated_check_calibration(check_calibration.release());

  auto [error, state_case] = handler->GetNextStateCase(state);
  EXPECT_EQ(error, RMAD_ERROR_CALIBRATION_COMPONENT_MISSING);
  EXPECT_EQ(state_case, RmadState::StateCase::kCheckCalibration);
}

TEST_F(CheckCalibrationStateHandlerTest, GetNextStateCase_UnknownComponent) {
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

  std::unique_ptr<CheckCalibrationState> check_calibration =
      std::make_unique<CheckCalibrationState>();
  auto base_accelerometer = check_calibration->add_components();
  base_accelerometer->set_component(RMAD_COMPONENT_BASE_ACCELEROMETER);
  base_accelerometer->set_status(
      CalibrationComponentStatus::RMAD_CALIBRATION_WAITING);
  auto lid_accelerometer = check_calibration->add_components();
  lid_accelerometer->set_component(RMAD_COMPONENT_LID_ACCELEROMETER);
  lid_accelerometer->set_status(
      CalibrationComponentStatus::RMAD_CALIBRATION_WAITING);
  auto base_gyroscope = check_calibration->add_components();
  base_gyroscope->set_component(RMAD_COMPONENT_BASE_GYROSCOPE);
  base_gyroscope->set_status(
      CalibrationComponentStatus::RMAD_CALIBRATION_COMPLETE);
  auto unknown = check_calibration->add_components();
  unknown->set_component(RMAD_COMPONENT_UNKNOWN);
  unknown->set_status(CalibrationComponentStatus::RMAD_CALIBRATION_COMPLETE);

  RmadState state;
  state.set_allocated_check_calibration(check_calibration.release());

  auto [error, state_case] = handler->GetNextStateCase(state);
  EXPECT_EQ(error, RMAD_ERROR_CALIBRATION_COMPONENT_INVALID);
  EXPECT_EQ(state_case, RmadState::StateCase::kCheckCalibration);
}

TEST_F(CheckCalibrationStateHandlerTest, GetNextStateCase_DecisionNotMade) {
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

  std::unique_ptr<CheckCalibrationState> check_calibration =
      std::make_unique<CheckCalibrationState>();
  auto base_accelerometer = check_calibration->add_components();
  base_accelerometer->set_component(RMAD_COMPONENT_BASE_ACCELEROMETER);
  base_accelerometer->set_status(
      CalibrationComponentStatus::RMAD_CALIBRATION_WAITING);
  auto lid_accelerometer = check_calibration->add_components();
  lid_accelerometer->set_component(RMAD_COMPONENT_LID_ACCELEROMETER);
  lid_accelerometer->set_status(
      CalibrationComponentStatus::RMAD_CALIBRATION_FAILED);
  auto base_gyroscope = check_calibration->add_components();
  base_gyroscope->set_component(RMAD_COMPONENT_BASE_GYROSCOPE);
  base_gyroscope->set_status(
      CalibrationComponentStatus::RMAD_CALIBRATION_COMPLETE);
  auto lid_gyroscope = check_calibration->add_components();
  lid_gyroscope->set_component(RMAD_COMPONENT_LID_GYROSCOPE);
  lid_gyroscope->set_status(
      CalibrationComponentStatus::RMAD_CALIBRATION_COMPLETE);

  RmadState state;
  state.set_allocated_check_calibration(check_calibration.release());

  auto [error, state_case] = handler->GetNextStateCase(state);
  EXPECT_EQ(error, RMAD_ERROR_CALIBRATION_STATUS_MISSING);
  EXPECT_EQ(state_case, RmadState::StateCase::kCheckCalibration);
}

TEST_F(CheckCalibrationStateHandlerTest, GetNextStateCase_MissingState) {
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

  // No CheckCalibrationState.
  RmadState state;

  auto [error, state_case] = handler->GetNextStateCase(state);
  EXPECT_EQ(error, RMAD_ERROR_REQUEST_INVALID);
  EXPECT_EQ(state_case, RmadState::StateCase::kCheckCalibration);
}

TEST_F(CheckCalibrationStateHandlerTest,
       GetNextStateCase_MissingWipeDeviceVar) {
  // No kWipeDevice set.

  const std::map<std::string, std::map<std::string, std::string>>
      predefined_calibration_map = {{kBaseInstructionName,
                                     {{kBaseAccName, kStatusCompleteName},
                                      {kBaseGyroName, kStatusCompleteName}}},
                                    {kLidInstructionName,
                                     {{kLidAccName, kStatusCompleteName},
                                      {kLidGyroName, kStatusCompleteName}}}};
  EXPECT_TRUE(
      json_store_->SetValue(kCalibrationMap, predefined_calibration_map));

  auto handler = CreateStateHandler();
  EXPECT_EQ(handler->InitializeState(), RMAD_ERROR_OK);

  RmadState state = handler->GetState();

  auto [error, state_case] = handler->GetNextStateCase(state);
  EXPECT_EQ(error, RMAD_ERROR_TRANSITION_FAILED);
  EXPECT_EQ(state_case, RmadState::StateCase::kCheckCalibration);
}

}  // namespace rmad
