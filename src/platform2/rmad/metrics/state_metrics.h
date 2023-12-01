// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RMAD_METRICS_STATE_METRICS_H_
#define RMAD_METRICS_STATE_METRICS_H_

#include <map>

#include <base/values.h>

#include "rmad/proto_bindings/rmad.pb.h"

namespace rmad {

// Internal structure for storing metrics of a state.
struct StateMetricsData {
 public:
  bool operator==(const StateMetricsData& other) const;
  base::Value ToValue() const;
  bool FromValue(const base::Value* value);

  RmadState::StateCase state_case;
  bool is_aborted;
  double setup_timestamp;
  double overall_time;
  int transition_count;
  int get_log_count;
  int save_log_count;
};

base::Value ConvertToValue(const StateMetricsData& data);
bool ConvertFromValue(const base::Value* value, StateMetricsData* data);

// Internal structure for storing metrics of all states.
class StateMetricsMap {
 public:
  StateMetricsMap() = default;
  explicit StateMetricsMap(
      const std::map<int, StateMetricsData>& state_metrics_map);
  ~StateMetricsMap() = default;

  StateMetricsData& operator[](RmadState::StateCase state_case) {
    return state_metrics_map_[static_cast<int>(state_case)];
  }
  const StateMetricsData& operator[](RmadState::StateCase state_case) const {
    return state_metrics_map_.at(static_cast<int>(state_case));
  }
  bool operator==(const StateMetricsMap& other) const {
    return GetRawMap() == other.GetRawMap();
  }

  std::map<int, StateMetricsData> GetRawMap() const {
    return state_metrics_map_;
  }

  bool InitializeState(RmadState::StateCase state_case, double setup_timestamp);
  bool UpdateStateOverallTime(RmadState::StateCase state_case,
                              double leave_timestamp);

 private:
  std::map<int, StateMetricsData> state_metrics_map_;
};

base::Value ConvertToValue(const StateMetricsMap& data);
bool ConvertFromValue(const base::Value* value, StateMetricsMap* data);

}  // namespace rmad

#endif  // RMAD_METRICS_STATE_METRICS_H_
