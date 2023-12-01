// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "rmad/metrics/state_metrics.h"

#include <map>
#include <utility>

#include <base/logging.h>
#include <base/values.h>

#include "rmad/constants.h"
#include "rmad/metrics/metrics_constants.h"
#include "rmad/proto_bindings/rmad.pb.h"
#include "rmad/utils/type_conversions.h"

namespace rmad {

namespace {

// TODO(chenghan): Define this in a common header, e.g. common.h.
const char* GetStateName(RmadState::StateCase state) {
  auto it = kStateNames.find(state);
  CHECK(it != kStateNames.end());
  return it->second.data();
}

}  // namespace

bool StateMetricsData::operator==(const StateMetricsData& other) const {
  return state_case == other.state_case && is_aborted == other.is_aborted &&
         setup_timestamp == other.setup_timestamp &&
         overall_time == other.overall_time &&
         transition_count == other.transition_count &&
         get_log_count == other.get_log_count &&
         save_log_count == other.save_log_count;
}

base::Value StateMetricsData::ToValue() const {
  base::Value::Dict dict;
  dict.Set(kStateCase, static_cast<int>(state_case));
  dict.Set(kStateIsAborted, is_aborted);
  dict.Set(kStateSetupTimestamp, setup_timestamp);
  dict.Set(kStateOverallTime, overall_time);
  dict.Set(kStateTransitionsCount, transition_count);
  dict.Set(kStateGetLogCount, get_log_count);
  dict.Set(kStateSaveLogCount, save_log_count);
  return base::Value(std::move(dict));
}

bool StateMetricsData::FromValue(const base::Value* value) {
  if (!value || !value->is_dict()) {
    return false;
  }
  const base::Value::Dict& dict = value->GetDict();

  StateMetricsData data;
  if (auto state_case_it = dict.FindInt(kStateCase)) {
    data.state_case = static_cast<RmadState::StateCase>(*state_case_it);
  } else {
    return false;
  }
  if (auto is_aborted_it = dict.FindBool(kStateIsAborted)) {
    data.is_aborted = *is_aborted_it;
  } else {
    return false;
  }
  if (auto setup_timestamp_it = dict.FindDouble(kStateSetupTimestamp)) {
    data.setup_timestamp = *setup_timestamp_it;
  } else {
    return false;
  }
  if (auto overall_time_it = dict.FindDouble(kStateOverallTime)) {
    data.overall_time = *overall_time_it;
  } else {
    return false;
  }
  if (auto transition_count_it = dict.FindInt(kStateTransitionsCount)) {
    data.transition_count = *transition_count_it;
  } else {
    return false;
  }
  if (auto get_log_count_it = dict.FindInt(kStateGetLogCount)) {
    data.get_log_count = *get_log_count_it;
  } else {
    return false;
  }
  if (auto save_log_count_it = dict.FindInt(kStateSaveLogCount)) {
    data.save_log_count = *save_log_count_it;
  } else {
    return false;
  }

  *this = std::move(data);
  return true;
}

base::Value ConvertToValue(const StateMetricsData& data) {
  return data.ToValue();
}

bool ConvertFromValue(const base::Value* value, StateMetricsData* data) {
  if (!value) {
    return false;
  }
  return !data || data->FromValue(value);
}

StateMetricsMap::StateMetricsMap(
    const std::map<int, StateMetricsData>& state_metrics_map)
    : state_metrics_map_(state_metrics_map) {}

bool StateMetricsMap::InitializeState(RmadState::StateCase state_case,
                                      double setup_timestamp) {
  if (state_case == RmadState::STATE_NOT_SET) {
    return true;
  }

  int key = static_cast<int>(state_case);
  state_metrics_map_[key].setup_timestamp = setup_timestamp;
  state_metrics_map_[key].state_case = state_case;
  return true;
}

bool StateMetricsMap::UpdateStateOverallTime(RmadState::StateCase state_case,
                                             double leave_timestamp) {
  if (state_case == RmadState::STATE_NOT_SET) {
    return true;
  }

  int key = static_cast<int>(state_case);
  if (state_metrics_map_.find(key) == state_metrics_map_.end()) {
    LOG(ERROR) << GetStateName(state_case)
               << ": Failed to get state metrics to calculate.";
    return false;
  }

  if (state_metrics_map_[key].setup_timestamp < 0.0) {
    LOG(ERROR) << GetStateName(state_case) << ": Invalid setup timestamp: "
               << state_metrics_map_[key].setup_timestamp << " is less than 0.";
    return false;
  }

  double time_spent_sec =
      (state_case == kInitialStateCase)
          ? 0
          : leave_timestamp - state_metrics_map_[key].setup_timestamp;
  if (time_spent_sec < 0) {
    LOG(ERROR) << GetStateName(state_case)
               << ": Failed to calculate time spent.";
    return false;
  }

  state_metrics_map_[key].overall_time += time_spent_sec;
  state_metrics_map_[key].setup_timestamp = leave_timestamp;

  return true;
}

base::Value ConvertToValue(const StateMetricsMap& data) {
  // ConvertToValue(std::map<int, T>) is defined in utils/type_conversions.h.
  return ConvertToValue(data.GetRawMap());
}

bool ConvertFromValue(const base::Value* value, StateMetricsMap* data) {
  if (!value) {
    return false;
  }
  std::map<int, StateMetricsData> state_metrics_map;
  if (!ConvertFromValue(value, &state_metrics_map)) {
    return false;
  }
  if (data) {
    *data = StateMetricsMap(std::move(state_metrics_map));
  }
  return true;
}

}  // namespace rmad
