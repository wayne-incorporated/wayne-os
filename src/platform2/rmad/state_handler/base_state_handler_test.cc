// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "rmad/state_handler/base_state_handler.h"

#include <set>
#include <string>
#include <vector>

#include <base/files/file_util.h>
#include <base/test/task_environment.h>
#include <gtest/gtest.h>

#include "rmad/constants.h"
#include "rmad/logs/logs_constants.h"
#include "rmad/metrics/metrics_constants.h"
#include "rmad/metrics/metrics_utils.h"
#include "rmad/state_handler/state_handler_test_common.h"

namespace {

constexpr int kDelayTimeInSec = 1;
constexpr std::array<rmad::AdditionalActivity, 5> kTestAdditionalActivities = {
    rmad::RMAD_ADDITIONAL_ACTIVITY_REBOOT,
    rmad::RMAD_ADDITIONAL_ACTIVITY_BATTERY_CUTOFF,
    rmad::RMAD_ADDITIONAL_ACTIVITY_DIAGNOSTICS,
    rmad::RMAD_ADDITIONAL_ACTIVITY_OS_UPDATE,
    rmad::RMAD_ADDITIONAL_ACTIVITY_SHUTDOWN};

}  // namespace

namespace rmad {

class TestBaseStateHandler : public BaseStateHandler {
 public:
  TestBaseStateHandler(scoped_refptr<JsonStore> json_store,
                       scoped_refptr<DaemonCallback> daemon_callback)
      : BaseStateHandler(json_store, daemon_callback) {}

  RmadState::StateCase GetStateCase() const override {
    return RmadState::STATE_NOT_SET;
  }

  SET_REPEATABLE

  RmadErrorCode InitializeState() override { return RMAD_ERROR_OK; }

  GetNextStateCaseReply GetNextStateCase(const RmadState& state) override {
    return {.error = RMAD_ERROR_OK, .state_case = RmadState::STATE_NOT_SET};
  }

  RmadState& GetStateInternalForTest() { return state_; }

 protected:
  ~TestBaseStateHandler() override = default;
};

class TestUnrepeatableBaseStateHandler : public BaseStateHandler {
 public:
  TestUnrepeatableBaseStateHandler(
      scoped_refptr<JsonStore> json_store,
      scoped_refptr<DaemonCallback> daemon_callback)
      : BaseStateHandler(json_store, daemon_callback) {}

  RmadState::StateCase GetStateCase() const override {
    return RmadState::STATE_NOT_SET;
  }

  SET_UNREPEATABLE

  RmadErrorCode InitializeState() override { return RMAD_ERROR_OK; }

  GetNextStateCaseReply GetNextStateCase(const RmadState& state) override {
    return {.error = RMAD_ERROR_OK, .state_case = RmadState::STATE_NOT_SET};
  }

 protected:
  ~TestUnrepeatableBaseStateHandler() override = default;
};

class BaseStateHandlerTest : public StateHandlerTest {
 public:
  scoped_refptr<TestBaseStateHandler> CreateStateHandler() {
    return base::MakeRefCounted<TestBaseStateHandler>(json_store_,
                                                      daemon_callback_);
  }

  scoped_refptr<TestUnrepeatableBaseStateHandler>
  CreateUnrepeatableStateHandler() {
    return base::MakeRefCounted<TestUnrepeatableBaseStateHandler>(
        json_store_, daemon_callback_);
  }

 protected:
  // Variables for TaskRunner.
  base::test::TaskEnvironment task_environment_{
      base::test::TaskEnvironment::ThreadPoolExecutionMode::ASYNC,
      base::test::TaskEnvironment::TimeSource::MOCK_TIME};

  void SetUp() override { StateHandlerTest::SetUp(); }
};

TEST_F(BaseStateHandlerTest, CleanUpState_Success) {
  auto handler = CreateStateHandler();
  handler->CleanUpState();
}

TEST_F(BaseStateHandlerTest, IsRepeatable_RepeatableSuccess) {
  auto handler = CreateStateHandler();
  EXPECT_TRUE(handler->IsRepeatable());
}

TEST_F(BaseStateHandlerTest, IsRepeatable_UnrepeatableSuccess) {
  auto handler = CreateUnrepeatableStateHandler();
  EXPECT_FALSE(handler->IsRepeatable());
}

TEST_F(BaseStateHandlerTest, StoreState_EmptySuccess) {
  auto handler = CreateStateHandler();
  EXPECT_TRUE(handler->StoreState());
}

TEST_F(BaseStateHandlerTest, StoreState_WelcomeSuccess) {
  auto handler = CreateStateHandler();
  EXPECT_FALSE(handler->GetStateInternalForTest().has_welcome());
  handler->GetStateInternalForTest().set_allocated_welcome(new WelcomeState);
  EXPECT_TRUE(handler->GetStateInternalForTest().has_welcome());
  EXPECT_TRUE(handler->StoreState());
}

TEST_F(BaseStateHandlerTest, RetrieveState_EmptyFailed) {
  auto handler = CreateStateHandler();
  EXPECT_FALSE(handler->RetrieveState());
}

TEST_F(BaseStateHandlerTest, RetrieveState_EmptyStateSuccess) {
  auto handler = CreateStateHandler();
  EXPECT_TRUE(handler->StoreState());

  auto handler2 = CreateStateHandler();
  EXPECT_TRUE(handler2->RetrieveState());
}

TEST_F(BaseStateHandlerTest, RetrieveState_WelcomeStateSuccess) {
  auto handler = CreateStateHandler();
  EXPECT_FALSE(handler->GetStateInternalForTest().has_welcome());
  handler->GetStateInternalForTest().set_allocated_welcome(new WelcomeState);
  EXPECT_TRUE(handler->GetStateInternalForTest().has_welcome());
  EXPECT_TRUE(handler->StoreState());

  auto handler2 = CreateStateHandler();
  EXPECT_TRUE(handler2->RetrieveState());
  EXPECT_TRUE(handler2->GetStateInternalForTest().has_welcome());
}

TEST_F(BaseStateHandlerTest, StoreErrorCode_Success) {
  std::vector<std::string> target_occurred_errors;
  const RmadState::StateCase current_state = RmadState::kComponentsRepair;
  for (int i = RmadErrorCode_MIN; i <= RmadErrorCode_MAX; i++) {
    auto handler = CreateStateHandler();
    RmadErrorCode error_code = static_cast<RmadErrorCode>(i);
    EXPECT_TRUE(handler->StoreErrorCode(current_state, error_code));

    if (std::find(kExpectedErrorCodes.begin(), kExpectedErrorCodes.end(),
                  error_code) == kExpectedErrorCodes.end()) {
      target_occurred_errors.push_back(RmadErrorCode_Name(error_code));
    }
  }

  std::vector<std::string> occurred_errors;
  MetricsUtils::GetMetricsValue(json_store_, kMetricsOccurredErrors,
                                &occurred_errors);
  EXPECT_EQ(occurred_errors, target_occurred_errors);

  base::Value logs(base::Value::Type::DICT);
  json_store_->GetValue(kLogs, &logs);

  const base::Value::List* events = logs.GetDict().FindList(kEvents);
  const int num_error_codes =
      RmadErrorCode_MAX - RmadErrorCode_MIN - kExpectedErrorCodes.size() + 1;
  EXPECT_EQ(num_error_codes, events->size());
  const base::Value::Dict& event = (*events)[0].GetDict();
  EXPECT_EQ(static_cast<int>(current_state), event.FindInt(kStateId));
  EXPECT_EQ(static_cast<int>(LogEventType::kError), event.FindInt(kType));

  // TODO(genechang): Refactor and check metrics parsing here.
}

TEST_F(BaseStateHandlerTest, StoreErrorCode_Failed) {
  base::SetPosixFilePermissions(GetStateFilePath(), 0444);

  for (int i = RmadErrorCode_MIN; i <= RmadErrorCode_MAX; i++) {
    auto handler = CreateStateHandler();
    RmadErrorCode error_code = static_cast<RmadErrorCode>(i);
    if (std::find(kExpectedErrorCodes.begin(), kExpectedErrorCodes.end(),
                  error_code) == kExpectedErrorCodes.end()) {
      EXPECT_FALSE(
          handler->StoreErrorCode(RmadState::kComponentsRepair, error_code));
    } else {
      EXPECT_TRUE(
          handler->StoreErrorCode(RmadState::kComponentsRepair, error_code));
    }
  }

  // TODO(genechang): Refactor and check metrics parsing here.
}

TEST_F(BaseStateHandlerTest, StoreAdditionalActivity_NothingSuccess) {
  auto handler = CreateStateHandler();
  EXPECT_TRUE(
      handler->StoreAdditionalActivity(RMAD_ADDITIONAL_ACTIVITY_NOTHING));
  // TODO(genechang): Refactor and check metrics parsing here.
}

TEST_F(BaseStateHandlerTest, StoreAdditionalActivity_Success) {
  std::vector<std::string> target_additional_activities;

  for (AdditionalActivity activity : kTestAdditionalActivities) {
    auto handler = CreateStateHandler();
    if (std::find(kExpectedPowerCycleActivities.begin(),
                  kExpectedPowerCycleActivities.end(),
                  activity) != kExpectedPowerCycleActivities.end()) {
      EXPECT_TRUE(MetricsUtils::SetMetricsValue(
          json_store_, kMetricsSetupTimestamp, base::Time::Now().ToDoubleT()));
      task_environment_.FastForwardBy(base::Seconds(kDelayTimeInSec));

      double pre_running_time = 0.0;
      MetricsUtils::GetMetricsValue(json_store_, kMetricsRunningTime,
                                    &pre_running_time);

      EXPECT_TRUE(handler->StoreAdditionalActivity(activity));

      double running_time;
      EXPECT_TRUE(MetricsUtils::GetMetricsValue(
          json_store_, kMetricsRunningTime, &running_time));
      EXPECT_EQ(running_time - pre_running_time, kDelayTimeInSec);
    } else {
      EXPECT_TRUE(handler->StoreAdditionalActivity(activity));
    }

    if (activity != RMAD_ADDITIONAL_ACTIVITY_NOTHING) {
      target_additional_activities.push_back(AdditionalActivity_Name(activity));
    }
  }

  std::vector<std::string> additional_activities;
  MetricsUtils::GetMetricsValue(json_store_, kMetricsAdditionalActivities,
                                &additional_activities);
  EXPECT_EQ(additional_activities, target_additional_activities);
  // TODO(genechang): Refactor and check metrics parsing here.
}

TEST_F(BaseStateHandlerTest, StoreAdditionalActivity_JsonFailed) {
  EXPECT_TRUE(MetricsUtils::SetMetricsValue(json_store_, kMetricsSetupTimestamp,
                                            base::Time::Now().ToDoubleT()));
  base::SetPosixFilePermissions(GetStateFilePath(), 0444);

  for (AdditionalActivity activity : kTestAdditionalActivities) {
    auto handler = CreateStateHandler();
    EXPECT_FALSE(handler->StoreAdditionalActivity(activity));
  }
}

TEST_F(BaseStateHandlerTest, StoreAdditionalActivity_RunningTimeFailed) {
  for (AdditionalActivity activity : kTestAdditionalActivities) {
    auto handler = CreateStateHandler();
    // If it does power cycle, it needs to calculate the running time.
    if (std::find(kExpectedPowerCycleActivities.begin(),
                  kExpectedPowerCycleActivities.end(),
                  activity) != kExpectedPowerCycleActivities.end()) {
      EXPECT_FALSE(handler->StoreAdditionalActivity(activity));
    } else {
      EXPECT_TRUE(handler->StoreAdditionalActivity(activity));
    }
  }
  // TODO(genechang): Refactor and check metrics parsing here.
}

TEST_F(BaseStateHandlerTest, NextStateCaseWrapper_Sucesss) {
  std::vector<std::string> target_occurred_errors;
  std::vector<std::string> target_additional_activities;

  RmadState::StateCase state_case = RmadState::kWelcome;

  for (int i = RmadErrorCode_MIN; i <= RmadErrorCode_MAX; i++) {
    RmadErrorCode error_code = static_cast<RmadErrorCode>(i);
    auto handler = CreateStateHandler();

    BaseStateHandler::GetNextStateCaseReply reply =
        handler->NextStateCaseWrapper(state_case, error_code,
                                      RMAD_ADDITIONAL_ACTIVITY_NOTHING);
    EXPECT_EQ(reply.state_case, state_case);
    EXPECT_EQ(reply.error, error_code);

    if (std::find(kExpectedErrorCodes.begin(), kExpectedErrorCodes.end(),
                  error_code) == kExpectedErrorCodes.end()) {
      target_occurred_errors.push_back(RmadErrorCode_Name(error_code));
    }
  }

  for (AdditionalActivity activity : kTestAdditionalActivities) {
    auto handler = CreateStateHandler();

    if (std::find(kExpectedPowerCycleActivities.begin(),
                  kExpectedPowerCycleActivities.end(),
                  activity) != kExpectedPowerCycleActivities.end()) {
      EXPECT_TRUE(MetricsUtils::SetMetricsValue(
          json_store_, kMetricsSetupTimestamp, base::Time::Now().ToDoubleT()));
      task_environment_.FastForwardBy(base::Seconds(kDelayTimeInSec));

      double pre_running_time = 0.0;
      MetricsUtils::GetMetricsValue(json_store_, kMetricsRunningTime,
                                    &pre_running_time);

      BaseStateHandler::GetNextStateCaseReply reply =
          handler->NextStateCaseWrapper(state_case, RMAD_ERROR_OK, activity);
      EXPECT_EQ(reply.state_case, state_case);
      EXPECT_EQ(reply.error, RMAD_ERROR_OK);

      double running_time;
      EXPECT_TRUE(MetricsUtils::GetMetricsValue(
          json_store_, kMetricsRunningTime, &running_time));
      EXPECT_EQ(running_time - pre_running_time, kDelayTimeInSec);
    } else {
      BaseStateHandler::GetNextStateCaseReply reply =
          handler->NextStateCaseWrapper(state_case, RMAD_ERROR_OK, activity);
      EXPECT_EQ(reply.state_case, state_case);
      EXPECT_EQ(reply.error, RMAD_ERROR_OK);
    }

    if (activity != RMAD_ADDITIONAL_ACTIVITY_NOTHING) {
      target_additional_activities.push_back(AdditionalActivity_Name(activity));
    }
  }

  std::vector<std::string> additional_activities;
  EXPECT_TRUE(MetricsUtils::GetMetricsValue(
      json_store_, kMetricsAdditionalActivities, &additional_activities));
  EXPECT_EQ(additional_activities, target_additional_activities);

  std::vector<std::string> occurred_errors;
  EXPECT_TRUE(MetricsUtils::GetMetricsValue(json_store_, kMetricsOccurredErrors,
                                            &occurred_errors));
  EXPECT_EQ(occurred_errors, target_occurred_errors);
  // TODO(genechang): Refactor and check metrics parsing here.
}

TEST_F(BaseStateHandlerTest, NextStateCaseWrapper_JsonFailed) {
  base::SetPosixFilePermissions(GetStateFilePath(), 0444);

  std::vector<std::string> target_occurred_errors;

  RmadState::StateCase state_case = RmadState::kWelcome;

  for (int i = RmadErrorCode_MIN; i <= RmadErrorCode_MAX; i++) {
    RmadErrorCode error_code = static_cast<RmadErrorCode>(i);
    auto handler = CreateStateHandler();

    BaseStateHandler::GetNextStateCaseReply reply =
        handler->NextStateCaseWrapper(state_case, error_code,
                                      RMAD_ADDITIONAL_ACTIVITY_NOTHING);
    EXPECT_EQ(reply.state_case, state_case);
    EXPECT_EQ(reply.error, error_code);
  }

  for (AdditionalActivity activity : kTestAdditionalActivities) {
    auto handler = CreateStateHandler();

    BaseStateHandler::GetNextStateCaseReply reply =
        handler->NextStateCaseWrapper(state_case, RMAD_ERROR_OK, activity);
    EXPECT_EQ(reply.state_case, state_case);
    EXPECT_EQ(reply.error, RMAD_ERROR_OK);
  }

  std::vector<std::string> additional_activities;
  MetricsUtils::GetMetricsValue(json_store_, kMetricsAdditionalActivities,
                                &additional_activities);
  EXPECT_EQ(additional_activities, std::vector<std::string>());

  std::vector<std::string> occurred_errors;
  MetricsUtils::GetMetricsValue(json_store_, kMetricsOccurredErrors,
                                &occurred_errors);
  EXPECT_EQ(occurred_errors, std::vector<std::string>());
}

TEST_F(BaseStateHandlerTest, NextStateCaseWrapper_RunningTimeFailed) {
  std::vector<std::string> target_occurred_errors;
  std::vector<std::string> target_additional_activities;

  RmadState::StateCase state_case = RmadState::kWelcome;

  for (int i = RmadErrorCode_MIN; i <= RmadErrorCode_MAX; i++) {
    RmadErrorCode error_code = static_cast<RmadErrorCode>(i);
    auto handler = CreateStateHandler();

    BaseStateHandler::GetNextStateCaseReply reply =
        handler->NextStateCaseWrapper(state_case, error_code,
                                      RMAD_ADDITIONAL_ACTIVITY_NOTHING);
    EXPECT_EQ(reply.state_case, state_case);
    EXPECT_EQ(reply.error, error_code);

    if (std::find(kExpectedErrorCodes.begin(), kExpectedErrorCodes.end(),
                  error_code) == kExpectedErrorCodes.end()) {
      target_occurred_errors.push_back(RmadErrorCode_Name(error_code));
    }
  }

  for (AdditionalActivity activity : kTestAdditionalActivities) {
    auto handler = CreateStateHandler();

    BaseStateHandler::GetNextStateCaseReply reply =
        handler->NextStateCaseWrapper(state_case, RMAD_ERROR_OK, activity);
    EXPECT_EQ(reply.state_case, state_case);
    EXPECT_EQ(reply.error, RMAD_ERROR_OK);

    if (activity != RMAD_ADDITIONAL_ACTIVITY_NOTHING &&
        std::find(kExpectedPowerCycleActivities.begin(),
                  kExpectedPowerCycleActivities.end(),
                  activity) == kExpectedPowerCycleActivities.end()) {
      target_additional_activities.push_back(AdditionalActivity_Name(activity));
    }
  }

  std::vector<std::string> additional_activities;
  EXPECT_TRUE(MetricsUtils::GetMetricsValue(
      json_store_, kMetricsAdditionalActivities, &additional_activities));
  EXPECT_EQ(additional_activities, target_additional_activities);

  std::vector<std::string> occurred_errors;
  EXPECT_TRUE(MetricsUtils::GetMetricsValue(json_store_, kMetricsOccurredErrors,
                                            &occurred_errors));
  EXPECT_EQ(occurred_errors, target_occurred_errors);
  // TODO(genechang): Refactor and check metrics parsing here.
}

}  // namespace rmad
