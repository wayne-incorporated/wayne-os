// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "rmad/state_handler/base_state_handler.h"

#include <map>
#include <set>
#include <string>
#include <vector>

#include <base/base64.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_util.h>
#include <base/time/time.h>
#include <brillo/file_utils.h>

#include "rmad/constants.h"
#include "rmad/logs/logs_utils.h"
#include "rmad/metrics/metrics_constants.h"
#include "rmad/metrics/metrics_utils.h"

namespace {

constexpr char kPowerwashCountPath[] = "powerwash_count";

bool ReadFileToInt(const base::FilePath& path, int* value) {
  std::string str;
  if (!base::ReadFileToString(path, &str)) {
    LOG(ERROR) << "Failed to read from path " << path;
    return false;
  }
  base::TrimWhitespaceASCII(str, base::TRIM_ALL, &str);
  return base::StringToInt(str, value);
}

}  // namespace

namespace rmad {

BaseStateHandler::BaseStateHandler(
    scoped_refptr<JsonStore> json_store,
    scoped_refptr<DaemonCallback> daemon_callback)
    : json_store_(json_store), daemon_callback_(daemon_callback) {}

const RmadState& BaseStateHandler::GetState(bool do_task) const {
  if (do_task) {
    OnGetStateTask();
  }
  return state_;
}

bool BaseStateHandler::StoreState() {
  std::map<int, std::string> state_map;
  json_store_->GetValue(kStateMap, &state_map);

  int key = GetStateCase();
  std::string serialized_string, serialized_string_base64;
  state_.SerializeToString(&serialized_string);
  base::Base64Encode(serialized_string, &serialized_string_base64);

  state_map[key] = serialized_string_base64;
  return json_store_->SetValue(kStateMap, state_map);
}

bool BaseStateHandler::RetrieveState() {
  if (std::map<int, std::string> state_map;
      json_store_->GetValue(kStateMap, &state_map)) {
    int key = GetStateCase();
    auto it = state_map.find(key);
    if (it != state_map.end()) {
      std::string serialized_string;
      CHECK(base::Base64Decode(it->second, &serialized_string));
      return state_.ParseFromString(serialized_string);
    }
  }
  return false;
}

BaseStateHandler::GetNextStateCaseReply BaseStateHandler::NextStateCaseWrapper(
    RmadState::StateCase state_case,
    RmadErrorCode error,
    AdditionalActivity activity) {
  if (!StoreErrorCode(state_case, error)) {
    LOG(ERROR) << "Failed to store the error code to |json_store_|.";
  }

  if (!StoreAdditionalActivity(activity)) {
    LOG(ERROR) << "Failed to store the additional activity to |json_store_|.";
  }

  return {.error = error, .state_case = state_case};
}

BaseStateHandler::GetNextStateCaseReply BaseStateHandler::NextStateCaseWrapper(
    RmadState::StateCase state_case) {
  return NextStateCaseWrapper(state_case, RMAD_ERROR_OK,
                              RMAD_ADDITIONAL_ACTIVITY_NOTHING);
}

BaseStateHandler::GetNextStateCaseReply BaseStateHandler::NextStateCaseWrapper(
    RmadErrorCode error) {
  return NextStateCaseWrapper(GetStateCase(), error,
                              RMAD_ADDITIONAL_ACTIVITY_NOTHING);
}

bool BaseStateHandler::StoreErrorCode(RmadState::StateCase state_case,
                                      RmadErrorCode error) {
  // If this is expected, then we do nothing.
  if (std::find(kExpectedErrorCodes.begin(), kExpectedErrorCodes.end(),
                error) != kExpectedErrorCodes.end()) {
    return true;
  }

  std::vector<std::string> occurred_errors;
  // Ignore the return value, since it may not have been set yet.
  MetricsUtils::GetMetricsValue(json_store_, kMetricsOccurredErrors,
                                &occurred_errors);
  occurred_errors.push_back(RmadErrorCode_Name(error));

  return MetricsUtils::SetMetricsValue(json_store_, kMetricsOccurredErrors,
                                       occurred_errors) &&
         RecordOccurredErrorToLogs(json_store_, state_case, error);
}

bool BaseStateHandler::StoreAdditionalActivity(AdditionalActivity activity) {
  if (RMAD_ADDITIONAL_ACTIVITY_NOTHING == activity) {
    return true;
  }

  std::vector<std::string> additional_activities;
  // Ignore the return value, since it may not have been set yet.
  MetricsUtils::GetMetricsValue(json_store_, kMetricsAdditionalActivities,
                                &additional_activities);
  additional_activities.push_back(AdditionalActivity_Name(activity));

  // For those expected power cycle events, we calculate running time and append
  // it to the |json_store_| for metrics.
  if (std::find(kExpectedPowerCycleActivities.begin(),
                kExpectedPowerCycleActivities.end(),
                activity) != kExpectedPowerCycleActivities.end()) {
    double current_timestamp = base::Time::Now().ToDoubleT();
    double setup_timestamp;
    if (!MetricsUtils::GetMetricsValue(json_store_, kMetricsSetupTimestamp,
                                       &setup_timestamp)) {
      LOG(ERROR) << "Failed to get setup timestamp for measuring "
                    "running time.";
      return false;
    }

    double running_time = 0;
    // Ignore the return value, since it may not have been set yet.
    MetricsUtils::GetMetricsValue(json_store_, kMetricsRunningTime,
                                  &running_time);
    running_time += current_timestamp - setup_timestamp;
    // Once we increase the running time, we should also update the timestamp to
    // prevent double counting issues.
    if (!MetricsUtils::SetMetricsValue(json_store_, kMetricsRunningTime,
                                       running_time) ||
        !MetricsUtils::SetMetricsValue(json_store_, kMetricsSetupTimestamp,
                                       current_timestamp)) {
      LOG(ERROR) << "Failed to set running time for metrics.";
      return false;
    }
  }

  return MetricsUtils::SetMetricsValue(
      json_store_, kMetricsAdditionalActivities, additional_activities);
}

bool BaseStateHandler::IsPowerwashDisabled(
    const base::FilePath& working_dir_path) const {
  // |kDisablePowerwashFilePath| is a file for testing convenience. Manually
  // touch this file if we want to avoid powerwash during testing. Powerwash is
  // also disabled when the test mode directory exists.
  return CanDisablePowerwash() &&
         (base::PathExists(
              working_dir_path.AppendASCII(kDisablePowerwashFilePath)) ||
          base::PathExists(working_dir_path.AppendASCII(kTestDirPath)));
}

bool BaseStateHandler::StorePowerwashCount(
    const base::FilePath& unencrypted_preserve_path) {
  // Record the current powerwash count to |json_store_|. If the file doesn't
  // exist, set the value to 0. This file counter is incremented by one after
  // every powerwash. See platform2/init/clobber_state.cc for mor detail.
  int powerwash_count = 0;
  ReadFileToInt(unencrypted_preserve_path.AppendASCII(kPowerwashCountPath),
                &powerwash_count);
  return json_store_->SetValue(kPowerwashCount, powerwash_count);
}

bool BaseStateHandler::IsPowerwashComplete(
    const base::FilePath& unencrypted_preserve_path) const {
  int stored_powerwash_count, current_powerwash_count;
  if (!json_store_->GetValue(kPowerwashCount, &stored_powerwash_count)) {
    LOG(ERROR) << "Key " << kPowerwashCount << " should exist in |json_store|";
    return false;
  }
  if (!ReadFileToInt(unencrypted_preserve_path.AppendASCII(kPowerwashCountPath),
                     &current_powerwash_count)) {
    return false;
  }
  return current_powerwash_count > stored_powerwash_count;
}

bool BaseStateHandler::IsCalibrationDisabled(
    const base::FilePath& working_dir_path) const {
  // |kDisableCalibrationFilePath| is a file for testing convenience. Manually
  // touch this file if we want to skip calibration steps during testing.
  return base::PathExists(
      working_dir_path.AppendASCII(kDisableCalibrationFilePath));
}

}  // namespace rmad
