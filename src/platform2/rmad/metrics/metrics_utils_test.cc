// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "rmad/metrics/metrics_utils.h"
#include "rmad/metrics/metrics_utils_impl.h"
#include "rmad/metrics/mock_metrics_utils.h"

#include <map>
#include <memory>
#include <vector>

#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/memory/scoped_refptr.h>
#include <base/time/time.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "rmad/constants.h"
#include "rmad/metrics/metrics_constants.h"
#include "rmad/metrics/state_metrics.h"
#include "rmad/utils/json_store.h"

using testing::_;
using testing::Return;

namespace {

constexpr char kTestJsonStoreFilename[] = "test.json";
constexpr char kDefaultMetricsJson[] = R"(
{
  "metrics": {
    "first_setup_timestamp": 123.456,
    "setup_timestamp": 456.789,
    "running_time": 333.333,
    "ro_firmware_verified": true,
    "replaced_component_names": [],
    "occurred_errors": ["RMAD_ERROR_MISSING_COMPONENT"],
    "additional_activities": ["RMAD_ADDITIONAL_ACTIVITY_REBOOT"],
    "state_metrics": {
      "1": {
        "state_case": 1,
        "state_is_aborted": false,
        "state_setup_timestamp": 0.0,
        "state_overall_time": 123.456,
        "state_transition_count": 2,
        "state_get_log_count": 3,
        "state_save_log_count": 4
      },
      "2": {
        "state_case": 2,
        "state_is_aborted": true,
        "state_setup_timestamp": 123.456,
        "state_overall_time": 332.544,
        "state_transition_count": 1,
        "state_get_log_count": 0,
        "state_save_log_count": 0
      }
    }
  }
}
)";
constexpr char kEmptyMetricsJson[] = "{}";
// This is the exact json string to match. DO NOT format it.
constexpr char kDefaultMetricsSummaryJson[] = R"({
   "additional_activities": [ "RMAD_ADDITIONAL_ACTIVITY_REBOOT" ],
   "occurred_errors": [ "RMAD_ERROR_MISSING_COMPONENT" ],
   "replaced_component_names": [  ],
   "ro_firmware_verified": true,
   "running_time": 333.333,
   "state_metrics": {
      "ComponentsRepair": {
         "state_case": 2,
         "state_get_log_count": 0,
         "state_is_aborted": true,
         "state_overall_time": 332.544,
         "state_save_log_count": 0,
         "state_transition_count": 1
      },
      "Welcome": {
         "state_case": 1,
         "state_get_log_count": 3,
         "state_is_aborted": false,
         "state_overall_time": 123.456,
         "state_save_log_count": 4,
         "state_transition_count": 2
      }
   }
}
)";

constexpr char kInvalidStateMetricsTimestampJson[] = R"(
{
  "metrics": {
    "state_metrics": {
      "1": {
        "state_case": 1,
        "state_is_aborted": false,
        "state_setup_timestamp": -1,
        "state_overall_time": 123.456,
        "state_transition_count": 2,
        "state_get_log_count": 3,
        "state_save_log_count": 4
      }
    }
  }
}
)";

constexpr double kDefaultFirstSetupTimestamp = 123.456;
constexpr double kDefaultSetupTimestamp = 456.789;
constexpr double kDefaultRunningTime = 333.333;
constexpr bool kDefaultRoFirmwareVerified = true;
const std::vector<std::string> kDefaultOccurredErrors = {
    "RMAD_ERROR_MISSING_COMPONENT"};
const std::vector<std::string> kDefaultAdditionalActivities = {
    "RMAD_ADDITIONAL_ACTIVITY_REBOOT"};
const std::map<int, rmad::StateMetricsData> kDefaultStateMetrics = {
    {1,
     {.state_case = rmad::RmadState::StateCase::kWelcome,
      .is_aborted = false,
      .setup_timestamp = 0.0,
      .overall_time = 123.456,
      .transition_count = 2,
      .get_log_count = 3,
      .save_log_count = 4}},
    {2,
     {.state_case = rmad::RmadState::StateCase::kComponentsRepair,
      .is_aborted = true,
      .setup_timestamp = 123.456,
      .overall_time = 332.544,
      .transition_count = 1,
      .get_log_count = 0,
      .save_log_count = 0}}};

constexpr double kTestFirstSetupTimestamp = 111.111;
constexpr double kTestSetupTimestamp = 666.666;
constexpr double kTestRunningTime = 555.555;
constexpr bool kTestRoFirmwareVerified = false;
const std::vector<std::string> kTestOccurredErrors = {
    "RMAD_ERROR_RMA_NOT_REQUIRED", "RMAD_ERROR_STATE_HANDLER_MISSING",
    "RMAD_ERROR_STATE_HANDLER_INITIALIZATION_FAILED"};
const std::vector<std::string> kTestAdditionalActivities = {
    "RMAD_ADDITIONAL_ACTIVITY_REBOOT",
    "RMAD_ADDITIONAL_ACTIVITY_BATTERY_CUTOFF",
    "RMAD_ADDITIONAL_ACTIVITY_DIAGNOSTICS"};

constexpr double kTestStateSetupTimestamp = 111.111;
constexpr double kTestStateLeaveTimestamp = 666.666;
constexpr double kTestStateOverallTime = 555.555;

}  // namespace

namespace rmad {

class MetricsUtilsTest : public testing::Test {
 public:
  MetricsUtilsTest() = default;

 protected:
  void SetUp() override {
    ASSERT_TRUE(temp_dir_.CreateUniqueTempDir());
    file_path_ = temp_dir_.GetPath().AppendASCII(kTestJsonStoreFilename);
  }

  bool CreateInputFile(const char* str, int size) {
    if (base::WriteFile(file_path_, str, size) == size) {
      json_store_ = base::MakeRefCounted<JsonStore>(file_path_);
      return true;
    }
    return false;
  }

  base::ScopedTempDir temp_dir_;
  scoped_refptr<JsonStore> json_store_;
  base::FilePath file_path_;
};

TEST_F(MetricsUtilsTest, GetValue) {
  EXPECT_TRUE(
      CreateInputFile(kDefaultMetricsJson, std::size(kDefaultMetricsJson) - 1));

  double first_setup_ts;
  EXPECT_TRUE(MetricsUtils::GetMetricsValue(
      json_store_, kMetricsFirstSetupTimestamp, &first_setup_ts));
  EXPECT_EQ(first_setup_ts, kDefaultFirstSetupTimestamp);

  double setup_ts;
  EXPECT_TRUE(MetricsUtils::GetMetricsValue(json_store_, kMetricsSetupTimestamp,
                                            &setup_ts));
  EXPECT_EQ(setup_ts, kDefaultSetupTimestamp);

  double running_time;
  EXPECT_TRUE(MetricsUtils::GetMetricsValue(json_store_, kMetricsRunningTime,
                                            &running_time));
  EXPECT_EQ(running_time, kDefaultRunningTime);

  bool ro_fw_verified;
  EXPECT_TRUE(MetricsUtils::GetMetricsValue(
      json_store_, kMetricsRoFirmwareVerified, &ro_fw_verified));
  EXPECT_EQ(ro_fw_verified, kDefaultRoFirmwareVerified);

  std::vector<std::string> occurred_errors;
  EXPECT_TRUE(MetricsUtils::GetMetricsValue(json_store_, kMetricsOccurredErrors,
                                            &occurred_errors));
  EXPECT_EQ(occurred_errors, kDefaultOccurredErrors);

  std::vector<std::string> additional_activities;
  EXPECT_TRUE(MetricsUtils::GetMetricsValue(
      json_store_, kMetricsAdditionalActivities, &additional_activities));
  EXPECT_EQ(additional_activities, kDefaultAdditionalActivities);

  std::map<int, StateMetricsData> state_metrics;
  EXPECT_TRUE(MetricsUtils::GetMetricsValue(json_store_, kStateMetrics,
                                            &state_metrics));
  EXPECT_EQ(state_metrics, kDefaultStateMetrics);
}

TEST_F(MetricsUtilsTest, SetValue_FirstSetupTimestamp) {
  EXPECT_TRUE(
      CreateInputFile(kEmptyMetricsJson, std::size(kEmptyMetricsJson) - 1));

  EXPECT_TRUE(MetricsUtils::SetMetricsValue(
      json_store_, kMetricsFirstSetupTimestamp, kTestFirstSetupTimestamp));

  double first_setup_ts;
  EXPECT_TRUE(MetricsUtils::GetMetricsValue(
      json_store_, kMetricsFirstSetupTimestamp, &first_setup_ts));
  EXPECT_EQ(first_setup_ts, kTestFirstSetupTimestamp);
}

TEST_F(MetricsUtilsTest, SetValue_SetupTimestamp) {
  EXPECT_TRUE(
      CreateInputFile(kEmptyMetricsJson, std::size(kEmptyMetricsJson) - 1));

  EXPECT_TRUE(MetricsUtils::SetMetricsValue(json_store_, kMetricsSetupTimestamp,
                                            kTestSetupTimestamp));

  double setup_ts;
  EXPECT_TRUE(MetricsUtils::GetMetricsValue(json_store_, kMetricsSetupTimestamp,
                                            &setup_ts));
  EXPECT_EQ(setup_ts, kTestSetupTimestamp);
}

TEST_F(MetricsUtilsTest, SetValue_RunningTime) {
  EXPECT_TRUE(
      CreateInputFile(kEmptyMetricsJson, std::size(kEmptyMetricsJson) - 1));

  EXPECT_TRUE(MetricsUtils::SetMetricsValue(json_store_, kMetricsRunningTime,
                                            kTestRunningTime));

  double running_time;
  EXPECT_TRUE(MetricsUtils::GetMetricsValue(json_store_, kMetricsRunningTime,
                                            &running_time));
  EXPECT_EQ(running_time, kTestRunningTime);
}

TEST_F(MetricsUtilsTest, SetValue_RoFirmwareVerified) {
  EXPECT_TRUE(
      CreateInputFile(kEmptyMetricsJson, std::size(kEmptyMetricsJson) - 1));

  EXPECT_TRUE(MetricsUtils::SetMetricsValue(
      json_store_, kMetricsRoFirmwareVerified, kTestRoFirmwareVerified));

  bool ro_fw_verified;
  EXPECT_TRUE(MetricsUtils::GetMetricsValue(
      json_store_, kMetricsRoFirmwareVerified, &ro_fw_verified));
  EXPECT_EQ(ro_fw_verified, kTestRoFirmwareVerified);
}

TEST_F(MetricsUtilsTest, SetValue_OccurredErrors) {
  EXPECT_TRUE(
      CreateInputFile(kEmptyMetricsJson, std::size(kEmptyMetricsJson) - 1));

  EXPECT_TRUE(MetricsUtils::SetMetricsValue(json_store_, kMetricsOccurredErrors,
                                            kTestOccurredErrors));

  std::vector<std::string> occurred_errors;
  EXPECT_TRUE(MetricsUtils::GetMetricsValue(json_store_, kMetricsOccurredErrors,
                                            &occurred_errors));
  EXPECT_EQ(occurred_errors, kTestOccurredErrors);
}

TEST_F(MetricsUtilsTest, SetValue_AddtionalActivities) {
  EXPECT_TRUE(
      CreateInputFile(kEmptyMetricsJson, std::size(kEmptyMetricsJson) - 1));

  EXPECT_TRUE(MetricsUtils::SetMetricsValue(
      json_store_, kMetricsAdditionalActivities, kTestAdditionalActivities));

  std::vector<std::string> additional_activities;
  EXPECT_TRUE(MetricsUtils::GetMetricsValue(
      json_store_, kMetricsAdditionalActivities, &additional_activities));
  EXPECT_EQ(additional_activities, kTestAdditionalActivities);
}

TEST_F(MetricsUtilsTest, SetValue_StateMetrics) {
  EXPECT_TRUE(
      CreateInputFile(kEmptyMetricsJson, std::size(kEmptyMetricsJson) - 1));

  EXPECT_TRUE(MetricsUtils::SetMetricsValue(json_store_, kStateMetrics,
                                            kDefaultStateMetrics));

  std::map<int, StateMetricsData> state_metrics;
  EXPECT_TRUE(MetricsUtils::GetMetricsValue(json_store_, kStateMetrics,
                                            &state_metrics));
  EXPECT_EQ(state_metrics, kDefaultStateMetrics);
}

TEST_F(MetricsUtilsTest, UpdateStateMetricsOnStateTransition) {
  EXPECT_TRUE(
      CreateInputFile(kEmptyMetricsJson, std::size(kEmptyMetricsJson) - 1));

  RmadState::StateCase state_case = RmadState::StateCase::kRestock;
  EXPECT_TRUE(MetricsUtils::UpdateStateMetricsOnStateTransition(
      json_store_, RmadState::StateCase::STATE_NOT_SET, state_case,
      kTestStateSetupTimestamp));

  std::map<int, StateMetricsData> state_metrics;
  EXPECT_TRUE(MetricsUtils::GetMetricsValue(json_store_, kStateMetrics,
                                            &state_metrics));

  auto state_it = state_metrics.find(static_cast<int>(state_case));
  EXPECT_NE(state_it, state_metrics.end());
  EXPECT_DOUBLE_EQ(state_it->second.setup_timestamp, kTestStateSetupTimestamp);

  EXPECT_TRUE(MetricsUtils::UpdateStateMetricsOnStateTransition(
      json_store_, state_case, RmadState::StateCase::STATE_NOT_SET,
      kTestStateLeaveTimestamp));

  EXPECT_TRUE(MetricsUtils::GetMetricsValue(json_store_, kStateMetrics,
                                            &state_metrics));
  state_it = state_metrics.find(static_cast<int>(state_case));
  EXPECT_NE(state_it, state_metrics.end());
  EXPECT_DOUBLE_EQ(state_it->second.setup_timestamp, kTestStateLeaveTimestamp);
  EXPECT_DOUBLE_EQ(state_it->second.overall_time, kTestStateOverallTime);
}

TEST_F(MetricsUtilsTest, UpdateStateMetricsOnStateTransition_StateNotFound) {
  EXPECT_TRUE(
      CreateInputFile(kEmptyMetricsJson, std::size(kEmptyMetricsJson) - 1));

  EXPECT_FALSE(MetricsUtils::UpdateStateMetricsOnStateTransition(
      json_store_, RmadState::StateCase::kWelcome,
      RmadState::StateCase::kRestock, kTestStateSetupTimestamp));
}

TEST_F(MetricsUtilsTest, UpdateStateMetricsOnStateTransition_InvalidTimestamp) {
  EXPECT_TRUE(
      CreateInputFile(kInvalidStateMetricsTimestampJson,
                      std::size(kInvalidStateMetricsTimestampJson) - 1));

  RmadState::StateCase state_case = RmadState::StateCase::kRestock;
  EXPECT_FALSE(MetricsUtils::UpdateStateMetricsOnStateTransition(
      json_store_, RmadState::StateCase::kWelcome, state_case,
      kTestStateLeaveTimestamp));
}

TEST_F(MetricsUtilsTest,
       UpdateStateMetricsOnStateTransition_NotIncreasedTimestamp) {
  EXPECT_TRUE(
      CreateInputFile(kEmptyMetricsJson, std::size(kEmptyMetricsJson) - 1));

  RmadState::StateCase state_case = RmadState::StateCase::kRestock;
  EXPECT_TRUE(MetricsUtils::UpdateStateMetricsOnStateTransition(
      json_store_, RmadState::StateCase::STATE_NOT_SET, state_case,
      kTestStateSetupTimestamp));

  std::map<int, StateMetricsData> state_metrics;
  EXPECT_TRUE(MetricsUtils::GetMetricsValue(json_store_, kStateMetrics,
                                            &state_metrics));

  auto state_it = state_metrics.find(static_cast<int>(state_case));
  EXPECT_NE(state_it, state_metrics.end());
  EXPECT_DOUBLE_EQ(state_it->second.setup_timestamp, kTestStateSetupTimestamp);

  // Invalid timestamp: timestamp should be incremented each time.
  EXPECT_FALSE(MetricsUtils::UpdateStateMetricsOnStateTransition(
      json_store_, state_case, RmadState::StateCase::STATE_NOT_SET,
      kTestStateSetupTimestamp - 1));
}

TEST_F(MetricsUtilsTest, UpdateStateMetricsOnAbort) {
  EXPECT_TRUE(
      CreateInputFile(kEmptyMetricsJson, std::size(kEmptyMetricsJson) - 1));

  RmadState::StateCase state_case = RmadState::StateCase::kRestock;
  EXPECT_TRUE(MetricsUtils::UpdateStateMetricsOnStateTransition(
      json_store_, RmadState::StateCase::STATE_NOT_SET, state_case,
      kTestStateSetupTimestamp));

  std::map<int, StateMetricsData> state_metrics;
  EXPECT_TRUE(MetricsUtils::GetMetricsValue(json_store_, kStateMetrics,
                                            &state_metrics));

  auto state_it = state_metrics.find(static_cast<int>(state_case));
  EXPECT_NE(state_it, state_metrics.end());
  EXPECT_DOUBLE_EQ(state_it->second.setup_timestamp, kTestStateSetupTimestamp);

  EXPECT_TRUE(MetricsUtils::UpdateStateMetricsOnAbort(
      json_store_, state_case, kTestStateLeaveTimestamp));

  EXPECT_TRUE(MetricsUtils::GetMetricsValue(json_store_, kStateMetrics,
                                            &state_metrics));
  state_it = state_metrics.find(static_cast<int>(state_case));
  EXPECT_NE(state_it, state_metrics.end());
  EXPECT_DOUBLE_EQ(state_it->second.setup_timestamp, kTestStateLeaveTimestamp);
  EXPECT_DOUBLE_EQ(state_it->second.overall_time, kTestStateOverallTime);
  EXPECT_EQ(state_it->second.is_aborted, true);
}

TEST_F(MetricsUtilsTest, UpdateStateMetricsOnGetLog) {
  EXPECT_TRUE(
      CreateInputFile(kEmptyMetricsJson, std::size(kEmptyMetricsJson) - 1));

  RmadState::StateCase state_case = RmadState::StateCase::kRestock;
  EXPECT_TRUE(
      MetricsUtils::UpdateStateMetricsOnGetLog(json_store_, state_case));

  std::map<int, StateMetricsData> state_metrics;
  EXPECT_TRUE(MetricsUtils::GetMetricsValue(json_store_, kStateMetrics,
                                            &state_metrics));
  auto state_it = state_metrics.find(static_cast<int>(state_case));
  EXPECT_NE(state_it, state_metrics.end());
  EXPECT_EQ(state_it->second.get_log_count, 1);

  EXPECT_TRUE(
      MetricsUtils::UpdateStateMetricsOnGetLog(json_store_, state_case));

  EXPECT_TRUE(MetricsUtils::GetMetricsValue(json_store_, kStateMetrics,
                                            &state_metrics));
  state_it = state_metrics.find(static_cast<int>(state_case));
  EXPECT_NE(state_it, state_metrics.end());
  EXPECT_EQ(state_it->second.get_log_count, 2);
}

TEST_F(MetricsUtilsTest, UpdateStateMetricsOnSaveLog) {
  EXPECT_TRUE(
      CreateInputFile(kEmptyMetricsJson, std::size(kEmptyMetricsJson) - 1));

  RmadState::StateCase state_case = RmadState::StateCase::kRestock;
  EXPECT_TRUE(
      MetricsUtils::UpdateStateMetricsOnSaveLog(json_store_, state_case));

  std::map<int, StateMetricsData> state_metrics;
  EXPECT_TRUE(MetricsUtils::GetMetricsValue(json_store_, kStateMetrics,
                                            &state_metrics));
  auto state_it = state_metrics.find(static_cast<int>(state_case));
  EXPECT_NE(state_it, state_metrics.end());
  EXPECT_EQ(state_it->second.save_log_count, 1);

  EXPECT_TRUE(
      MetricsUtils::UpdateStateMetricsOnSaveLog(json_store_, state_case));

  EXPECT_TRUE(MetricsUtils::GetMetricsValue(json_store_, kStateMetrics,
                                            &state_metrics));
  state_it = state_metrics.find(static_cast<int>(state_case));
  EXPECT_NE(state_it, state_metrics.end());
  EXPECT_EQ(state_it->second.save_log_count, 2);
}

TEST_F(MetricsUtilsTest, GetMetricsSummaryAsString) {
  EXPECT_TRUE(
      CreateInputFile(kDefaultMetricsJson, std::size(kDefaultMetricsJson) - 1));

  EXPECT_EQ(MetricsUtils::GetMetricsSummaryAsString(json_store_),
            kDefaultMetricsSummaryJson);
}

TEST_F(MetricsUtilsTest, GetMetricsSummaryAsString_NoData) {
  EXPECT_TRUE(
      CreateInputFile(kEmptyMetricsJson, std::size(kEmptyMetricsJson) - 1));

  EXPECT_EQ(MetricsUtils::GetMetricsSummaryAsString(json_store_), "");
}

class MetricsUtilsImplTest : public testing::Test {
 public:
  MetricsUtilsImplTest() = default;

  void SetupShimlessRmaReportValues(bool first_timestamp = true,
                                    bool timestamp = true,
                                    bool is_complete = true,
                                    bool ro_verified = true,
                                    bool returning_owner = true,
                                    bool mlb_replacement = true,
                                    bool wp_method = true) {
    double current_timestamp = base::Time::Now().ToDoubleT();
    if (first_timestamp) {
      EXPECT_TRUE(MetricsUtils::SetMetricsValue(
          json_store_, kMetricsFirstSetupTimestamp, current_timestamp));
    }

    if (timestamp) {
      EXPECT_TRUE(MetricsUtils::SetMetricsValue(
          json_store_, kMetricsSetupTimestamp, current_timestamp));
    }

    if (is_complete) {
      EXPECT_TRUE(
          MetricsUtils::SetMetricsValue(json_store_, kMetricsIsComplete, true));
    }

    if (ro_verified) {
      EXPECT_TRUE(MetricsUtils::SetMetricsValue(
          json_store_, kMetricsRoFirmwareVerified,
          RoVerificationStatus_Name(RMAD_RO_VERIFICATION_PASS)));
    }

    if (returning_owner) {
      EXPECT_TRUE(MetricsUtils::SetMetricsValue(
          json_store_, kMetricsReturningOwner,
          ReturningOwner_Name(
              ReturningOwner::RMAD_RETURNING_OWNER_DIFFERENT_OWNER)));
    }

    if (mlb_replacement) {
      EXPECT_TRUE(MetricsUtils::SetMetricsValue(json_store_,
                                                kMetricsMlbReplacement, true));
    }

    if (wp_method) {
      EXPECT_TRUE(MetricsUtils::SetMetricsValue(
          json_store_, kMetricsWpDisableMethod,
          WpDisableMethod_Name(WpDisableMethod::RMAD_WP_DISABLE_METHOD_RSU)));
    }
  }

  void SetupMetricsValues(bool is_report_valid = true,
                          bool is_replaced_components_valid = true,
                          bool is_occurred_errors_valid = true,
                          bool is_additional_activities_valid = true,
                          bool is_state_reports_valid = true) {
    if (is_report_valid) {
      SetupShimlessRmaReportValues();
    } else {
      SetupShimlessRmaReportValues(false);
    }

    if (is_replaced_components_valid) {
      EXPECT_TRUE(MetricsUtils::SetMetricsValue(
          json_store_, kMetricsReplacedComponents,
          std::vector<std::string>(
              {RmadComponent_Name(RMAD_COMPONENT_AUDIO_CODEC),
               RmadComponent_Name(RMAD_COMPONENT_BATTERY)})));
    } else {
      EXPECT_TRUE(
          MetricsUtils::SetMetricsValue(json_store_, kMetricsReplacedComponents,
                                        std::vector<std::string>({"test"})));
    }

    if (is_occurred_errors_valid) {
      EXPECT_TRUE(MetricsUtils::SetMetricsValue(
          json_store_, kMetricsOccurredErrors,
          std::vector<std::string>(
              {RmadErrorCode_Name(RMAD_ERROR_CANNOT_CANCEL_RMA),
               RmadErrorCode_Name(RMAD_ERROR_CANNOT_GET_LOG)})));
    } else {
      EXPECT_TRUE(
          MetricsUtils::SetMetricsValue(json_store_, kMetricsOccurredErrors,
                                        std::vector<std::string>({"test"})));
    }

    if (is_additional_activities_valid) {
      EXPECT_TRUE(MetricsUtils::SetMetricsValue(
          json_store_, kMetricsAdditionalActivities,
          std::vector<std::string>(
              {AdditionalActivity_Name(RMAD_ADDITIONAL_ACTIVITY_REBOOT),
               AdditionalActivity_Name(RMAD_ADDITIONAL_ACTIVITY_SHUTDOWN)})));
    } else {
      EXPECT_TRUE(MetricsUtils::SetMetricsValue(
          json_store_, kMetricsAdditionalActivities,
          std::vector<std::string>({"test"})));
    }

    if (is_state_reports_valid) {
      std::map<int, StateMetricsData> test_data;
      test_data[1] = StateMetricsData();
      // The transition count is always >= 1.
      test_data[1].transition_count = 1;
      EXPECT_TRUE(
          MetricsUtils::SetMetricsValue(json_store_, kStateMetrics, test_data));
    } else {
      std::map<int, StateMetricsData> test_data;
      test_data[1] = StateMetricsData();
      // The transition count should be >= 1.
      test_data[1].transition_count = 0;
      EXPECT_TRUE(
          MetricsUtils::SetMetricsValue(json_store_, kStateMetrics, test_data));
    }
  }

 protected:
  void SetUp() override {
    ASSERT_TRUE(temp_dir_.CreateUniqueTempDir());
    base::FilePath file_path =
        temp_dir_.GetPath().AppendASCII(kTestJsonStoreFilename);
    json_store_ = base::MakeRefCounted<JsonStore>(file_path);
  }

  base::ScopedTempDir temp_dir_;
  scoped_refptr<JsonStore> json_store_;
};

TEST_F(MetricsUtilsImplTest, RecordShimlessRmaReport_Success) {
  auto metrics_utils = std::make_unique<MetricsUtilsImpl>(false);
  SetupShimlessRmaReportValues();

  EXPECT_TRUE(metrics_utils->RecordShimlessRmaReport(json_store_));
}

TEST_F(MetricsUtilsImplTest,
       RecordShimlessRmaReport_FirstSetupTimestampMissed) {
  auto metrics_utils = std::make_unique<MetricsUtilsImpl>(false);
  SetupShimlessRmaReportValues(false);

  EXPECT_FALSE(metrics_utils->RecordShimlessRmaReport(json_store_));
}

TEST_F(MetricsUtilsImplTest, RecordShimlessRmaReport_SetupTimestampMissed) {
  auto metrics_utils = std::make_unique<MetricsUtilsImpl>(false);
  SetupShimlessRmaReportValues(true, false);

  EXPECT_FALSE(metrics_utils->RecordShimlessRmaReport(json_store_));
}

TEST_F(MetricsUtilsImplTest, RecordShimlessRmaReport_Abort_Success) {
  auto metrics_utils = std::make_unique<MetricsUtilsImpl>(false);
  SetupShimlessRmaReportValues(true, true, false);

  EXPECT_TRUE(metrics_utils->RecordShimlessRmaReport(json_store_));
}

TEST_F(MetricsUtilsImplTest,
       RecordShimlessRmaReport_RoVerifiedUnsupported_Success) {
  auto metrics_utils = std::make_unique<MetricsUtilsImpl>(false);
  SetupShimlessRmaReportValues();
  EXPECT_TRUE(MetricsUtils::SetMetricsValue(
      json_store_, kMetricsRoFirmwareVerified,
      RoVerificationStatus_Name(RMAD_RO_VERIFICATION_UNSUPPORTED)));

  EXPECT_TRUE(metrics_utils->RecordShimlessRmaReport(json_store_));
}

TEST_F(MetricsUtilsImplTest,
       RecordShimlessRmaReport_UnknownRoVerified_Success) {
  auto metrics_utils = std::make_unique<MetricsUtilsImpl>(false);
  SetupShimlessRmaReportValues(true, true, true, false);

  EXPECT_TRUE(metrics_utils->RecordShimlessRmaReport(json_store_));
}

TEST_F(MetricsUtilsImplTest, RecordShimlessRmaReport_SameOnwer_Success) {
  auto metrics_utils = std::make_unique<MetricsUtilsImpl>(false);
  SetupShimlessRmaReportValues();
  EXPECT_TRUE(MetricsUtils::SetMetricsValue(
      json_store_, kMetricsReturningOwner,
      ReturningOwner_Name(ReturningOwner::RMAD_RETURNING_OWNER_SAME_OWNER)));

  EXPECT_TRUE(metrics_utils->RecordShimlessRmaReport(json_store_));
}

TEST_F(MetricsUtilsImplTest, RecordShimlessRmaReport_DifferentOnwer_Success) {
  auto metrics_utils = std::make_unique<MetricsUtilsImpl>(false);
  SetupShimlessRmaReportValues();
  EXPECT_TRUE(MetricsUtils::SetMetricsValue(
      json_store_, kMetricsReturningOwner,
      ReturningOwner_Name(
          ReturningOwner::RMAD_RETURNING_OWNER_DIFFERENT_OWNER)));

  EXPECT_TRUE(metrics_utils->RecordShimlessRmaReport(json_store_));
}

TEST_F(MetricsUtilsImplTest, RecordShimlessRmaReport_UnknownOnwer_Success) {
  auto metrics_utils = std::make_unique<MetricsUtilsImpl>(false);
  SetupShimlessRmaReportValues(true, true, true, true, false);

  EXPECT_TRUE(metrics_utils->RecordShimlessRmaReport(json_store_));
}

TEST_F(MetricsUtilsImplTest, RecordShimlessRmaReport_MlbReplaced_Success) {
  auto metrics_utils = std::make_unique<MetricsUtilsImpl>(false);
  SetupShimlessRmaReportValues();
  EXPECT_TRUE(MetricsUtils::SetMetricsValue(
      json_store_, kMetricsMlbReplacement,
      MainboardReplacement_Name(
          MainboardReplacement::RMAD_MLB_REPLACEMENT_REPLACED)));

  EXPECT_TRUE(metrics_utils->RecordShimlessRmaReport(json_store_));
}

TEST_F(MetricsUtilsImplTest, RecordShimlessRmaReport_MlbOriginal_Success) {
  auto metrics_utils = std::make_unique<MetricsUtilsImpl>(false);
  SetupShimlessRmaReportValues();
  EXPECT_TRUE(MetricsUtils::SetMetricsValue(
      json_store_, kMetricsMlbReplacement,
      MainboardReplacement_Name(
          MainboardReplacement::RMAD_MLB_REPLACEMENT_ORIGINAL)));

  EXPECT_TRUE(metrics_utils->RecordShimlessRmaReport(json_store_));
}

TEST_F(MetricsUtilsImplTest, RecordShimlessRmaReport_MlbUnknown_Success) {
  auto metrics_utils = std::make_unique<MetricsUtilsImpl>(false);
  SetupShimlessRmaReportValues(true, true, true, true, true, false);

  EXPECT_TRUE(metrics_utils->RecordShimlessRmaReport(json_store_));
}

TEST_F(MetricsUtilsImplTest, RecordShimlessRmaReport_WpDisableMethod_Success) {
  auto metrics_utils = std::make_unique<MetricsUtilsImpl>(false);
  SetupShimlessRmaReportValues(true, true, true, true, true, true, false);
  // The write protect disable method hasn't been set yet.
  EXPECT_TRUE(metrics_utils->RecordShimlessRmaReport(json_store_));

  std::array<WpDisableMethod, 5> methods = {
      RMAD_WP_DISABLE_METHOD_UNKNOWN, RMAD_WP_DISABLE_METHOD_SKIPPED,
      RMAD_WP_DISABLE_METHOD_RSU,
      RMAD_WP_DISABLE_METHOD_PHYSICAL_ASSEMBLE_DEVICE,
      RMAD_WP_DISABLE_METHOD_PHYSICAL_KEEP_DEVICE_OPEN};
  for (auto wp_disable_method : methods) {
    EXPECT_TRUE(
        MetricsUtils::SetMetricsValue(json_store_, kMetricsWpDisableMethod,
                                      WpDisableMethod_Name(wp_disable_method)));
    EXPECT_TRUE(
        MetricsUtils::SetMetricsValue(json_store_, kMetricsIsComplete, true));
    EXPECT_TRUE(metrics_utils->RecordShimlessRmaReport(json_store_));
  }
}

TEST_F(MetricsUtilsImplTest, RecordReplacedComponents_Success) {
  auto metrics_utils = std::make_unique<MetricsUtilsImpl>(false);
  EXPECT_TRUE(MetricsUtils::SetMetricsValue(
      json_store_, kMetricsReplacedComponents,
      std::vector<std::string>({RmadComponent_Name(RMAD_COMPONENT_AUDIO_CODEC),
                                RmadComponent_Name(RMAD_COMPONENT_BATTERY)})));

  EXPECT_TRUE(metrics_utils->RecordReplacedComponents(json_store_));
}

TEST_F(MetricsUtilsImplTest,
       RecordReplacedComponents_UnknownReplacedComponent) {
  auto metrics_utils = std::make_unique<MetricsUtilsImpl>(false);
  EXPECT_TRUE(
      MetricsUtils::SetMetricsValue(json_store_, kMetricsReplacedComponents,
                                    std::vector<std::string>({"test"})));

  EXPECT_FALSE(metrics_utils->RecordReplacedComponents(json_store_));
}

TEST_F(MetricsUtilsImplTest, RecordOccurredErrors_Success) {
  auto metrics_utils = std::make_unique<MetricsUtilsImpl>(false);
  EXPECT_TRUE(MetricsUtils::SetMetricsValue(
      json_store_, kMetricsOccurredErrors,
      std::vector<std::string>(
          {RmadErrorCode_Name(RMAD_ERROR_CANNOT_CANCEL_RMA),
           RmadErrorCode_Name(RMAD_ERROR_CANNOT_GET_LOG)})));

  EXPECT_TRUE(metrics_utils->RecordOccurredErrors(json_store_));
}

TEST_F(MetricsUtilsImplTest, RecordOccurredErrors_UnknownOccurredError) {
  auto metrics_utils = std::make_unique<MetricsUtilsImpl>(false);
  EXPECT_TRUE(MetricsUtils::SetMetricsValue(
      json_store_, kMetricsOccurredErrors, std::vector<std::string>({"test"})));

  EXPECT_FALSE(metrics_utils->RecordOccurredErrors(json_store_));
}

TEST_F(MetricsUtilsImplTest, RecordAdditionalActivities_Success) {
  auto metrics_utils = std::make_unique<MetricsUtilsImpl>(false);
  EXPECT_TRUE(MetricsUtils::SetMetricsValue(
      json_store_, kMetricsAdditionalActivities,
      std::vector<std::string>(
          {AdditionalActivity_Name(RMAD_ADDITIONAL_ACTIVITY_REBOOT),
           AdditionalActivity_Name(RMAD_ADDITIONAL_ACTIVITY_SHUTDOWN)})));

  EXPECT_TRUE(metrics_utils->RecordAdditionalActivities(json_store_));
}

TEST_F(MetricsUtilsImplTest,
       RecordAdditionalActivities_UnknownAdditionalActivity) {
  auto metrics_utils = std::make_unique<MetricsUtilsImpl>(false);
  EXPECT_TRUE(
      MetricsUtils::SetMetricsValue(json_store_, kMetricsAdditionalActivities,
                                    std::vector<std::string>({"test"})));

  EXPECT_FALSE(metrics_utils->RecordAdditionalActivities(json_store_));
}

TEST_F(MetricsUtilsImplTest, RecordShimlessRmaStateReport_Success) {
  auto metrics_utils = std::make_unique<MetricsUtilsImpl>(false);
  std::map<int, StateMetricsData> test_data;
  // The transition count should be >= 1.
  test_data[1] = {.transition_count = 1};
  EXPECT_TRUE(
      MetricsUtils::SetMetricsValue(json_store_, kStateMetrics, test_data));

  EXPECT_TRUE(metrics_utils->RecordShimlessRmaStateReport(json_store_));
}

TEST_F(MetricsUtilsImplTest, RecordShimlessRmaStateReport_WrongOverallTime) {
  auto metrics_utils = std::make_unique<MetricsUtilsImpl>(false);
  std::map<int, StateMetricsData> test_data;
  // The transition count should be >= 1; The overall time should be >= 0.
  test_data[1] = {.overall_time = -1, .transition_count = 1};
  EXPECT_TRUE(
      MetricsUtils::SetMetricsValue(json_store_, kStateMetrics, test_data));

  EXPECT_FALSE(metrics_utils->RecordShimlessRmaStateReport(json_store_));
}

TEST_F(MetricsUtilsImplTest,
       RecordShimlessRmaStateReport_WrongTransitionCount) {
  auto metrics_utils = std::make_unique<MetricsUtilsImpl>(false);
  std::map<int, StateMetricsData> test_data;
  // The transition count should be >= 1.
  test_data[1] = {.transition_count = 0};
  EXPECT_TRUE(
      MetricsUtils::SetMetricsValue(json_store_, kStateMetrics, test_data));

  EXPECT_FALSE(metrics_utils->RecordShimlessRmaStateReport(json_store_));
}

TEST_F(MetricsUtilsImplTest, RecordShimlessRmaStateReport_WrongGetLogCount) {
  auto metrics_utils = std::make_unique<MetricsUtilsImpl>(false);
  std::map<int, StateMetricsData> test_data;
  // The transition count should be >= 1; The get log count should be >= 0.
  test_data[1] = {.transition_count = 1, .get_log_count = -1};
  EXPECT_TRUE(
      MetricsUtils::SetMetricsValue(json_store_, kStateMetrics, test_data));

  EXPECT_FALSE(metrics_utils->RecordShimlessRmaStateReport(json_store_));
}

TEST_F(MetricsUtilsImplTest, RecordShimlessRmaStateReport_WrongSaveLogCount) {
  auto metrics_utils = std::make_unique<MetricsUtilsImpl>(false);
  std::map<int, StateMetricsData> test_data;
  // The transition count should be >= 1; The save log count should be >= 0.
  test_data[1] = {.transition_count = 1, .save_log_count = -1};
  EXPECT_TRUE(
      MetricsUtils::SetMetricsValue(json_store_, kStateMetrics, test_data));

  EXPECT_FALSE(metrics_utils->RecordShimlessRmaStateReport(json_store_));
}

TEST_F(MetricsUtilsImplTest, RecordAll_Success) {
  auto metrics_utils = std::make_unique<MetricsUtilsImpl>(false);
  SetupMetricsValues();

  EXPECT_TRUE(metrics_utils->RecordAll(json_store_));
}

TEST_F(MetricsUtilsImplTest, RecordAll_RecordShimleeRmaReportFailed) {
  auto metrics_utils = std::make_unique<MetricsUtilsImpl>(false);
  SetupMetricsValues(false);

  EXPECT_FALSE(metrics_utils->RecordAll(json_store_));
}

TEST_F(MetricsUtilsImplTest, RecordAll_RecordReplacedComponentsFailed) {
  auto metrics_utils = std::make_unique<MetricsUtilsImpl>(false);
  SetupMetricsValues(true, false);

  EXPECT_FALSE(metrics_utils->RecordAll(json_store_));
}

TEST_F(MetricsUtilsImplTest, RecordAll_RecordOccurredErrorsFailed) {
  auto metrics_utils = std::make_unique<MetricsUtilsImpl>(false);
  SetupMetricsValues(true, true, false);

  EXPECT_FALSE(metrics_utils->RecordAll(json_store_));
}

TEST_F(MetricsUtilsImplTest, RecordAll_RecordAdditionalActivitiesFailed) {
  auto metrics_utils = std::make_unique<MetricsUtilsImpl>(false);
  SetupMetricsValues(true, true, true, false);

  EXPECT_FALSE(metrics_utils->RecordAll(json_store_));
}

TEST_F(MetricsUtilsImplTest, RecordAll_RecordShimlessRmaStateReportFailed) {
  auto metrics_utils = std::make_unique<MetricsUtilsImpl>(false);
  SetupMetricsValues(true, true, true, true, false);

  EXPECT_FALSE(metrics_utils->RecordAll(json_store_));
}

}  // namespace rmad
