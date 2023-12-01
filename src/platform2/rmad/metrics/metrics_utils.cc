// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "rmad/metrics/metrics_utils.h"

#include <base/check.h>
#include <base/json/json_string_value_serializer.h>
#include <base/logging.h>
#include <base/memory/scoped_refptr.h>

#include "rmad/constants.h"
#include "rmad/metrics/state_metrics.h"
#include "rmad/proto_bindings/rmad.pb.h"
#include "rmad/utils/json_store.h"

namespace rmad {

namespace {

// TODO(chenghan): Define this in a common header, e.g. common.h.
const char* GetStateName(RmadState::StateCase state) {
  auto it = kStateNames.find(state);
  CHECK(it != kStateNames.end());
  return it->second.data();
}

}  // namespace

bool MetricsUtils::UpdateStateMetricsOnAbort(
    scoped_refptr<JsonStore> json_store,
    RmadState::StateCase state_case,
    double timestamp) {
  if (!UpdateStateMetricsOnStateTransition(
          json_store, state_case, RmadState::STATE_NOT_SET, timestamp)) {
    LOG(ERROR) << "Failed to calculate metrics for state "
               << GetStateName(state_case);
    return false;
  }

  StateMetricsMap state_metrics;
  GetMetricsValue(json_store, kStateMetrics, &state_metrics);
  state_metrics[state_case].is_aborted = true;
  return SetMetricsValue(json_store, kStateMetrics, state_metrics);
}

bool MetricsUtils::UpdateStateMetricsOnStateTransition(
    scoped_refptr<JsonStore> json_store,
    RmadState::StateCase from,
    RmadState::StateCase to,
    double timestamp) {
  StateMetricsMap state_metrics;
  // At the beginning, we may have no data, so ignore the return value.
  GetMetricsValue(json_store, kStateMetrics, &state_metrics);

  // Update the global setup time and first setup time if needed.
  if (!SetMetricsValue(json_store, kMetricsSetupTimestamp, timestamp)) {
    LOG(ERROR) << "Could not store global setup time";
    return false;
  }
  if (double first_setup_time;
      to != kInitialStateCase &&
      !GetMetricsValue(json_store, kMetricsFirstSetupTimestamp,
                       &first_setup_time) &&
      !SetMetricsValue(json_store, kMetricsFirstSetupTimestamp, timestamp)) {
    LOG(ERROR) << "Could not store global first setup time";
    return false;
  }

  if (from != RmadState::STATE_NOT_SET && to != RmadState::STATE_NOT_SET) {
    state_metrics[to].transition_count++;
  }

  if (!state_metrics.UpdateStateOverallTime(from, timestamp) ||
      !state_metrics.InitializeState(to, timestamp)) {
    return false;
  }

  return SetMetricsValue(json_store, kStateMetrics, state_metrics);
}

bool MetricsUtils::UpdateStateMetricsOnGetLog(
    scoped_refptr<JsonStore> json_store, RmadState::StateCase state_case) {
  StateMetricsMap state_metrics;
  // At the beginning, we may have no data, so ignore the return value.
  GetMetricsValue(json_store, kStateMetrics, &state_metrics);

  state_metrics[state_case].get_log_count++;
  return SetMetricsValue(json_store, kStateMetrics, state_metrics);
}

bool MetricsUtils::UpdateStateMetricsOnSaveLog(
    scoped_refptr<JsonStore> json_store, RmadState::StateCase state_case) {
  StateMetricsMap state_metrics;
  // At the beginning, we may have no data, so ignore the return value.
  GetMetricsValue(json_store, kStateMetrics, &state_metrics);

  state_metrics[state_case].save_log_count++;
  return SetMetricsValue(json_store, kStateMetrics, state_metrics);
}

std::string MetricsUtils::GetMetricsSummaryAsString(
    scoped_refptr<JsonStore> json_store) {
  base::Value metrics;
  if (!json_store->GetValue(kMetrics, &metrics)) {
    return "";
  }

  // Since the type might change if we successfully get the value from the json
  // store, we need to check here.
  CHECK(metrics.is_dict());
  // Remove timestamps for the entire process.
  metrics.GetDict().Remove(kMetricsFirstSetupTimestamp);
  metrics.GetDict().Remove(kMetricsSetupTimestamp);

  // Refine readability of state metrics for better understanding.
  const base::Value* original_state_metrics =
      metrics.GetDict().Find(kStateMetrics);
  if (original_state_metrics && original_state_metrics->is_dict()) {
    metrics.GetDict().Set(
        kStateMetrics,
        RefineStateMetricsReadability(original_state_metrics->GetDict()));
  }

  std::string output;
  JSONStringValueSerializer serializer(&output);
  serializer.set_pretty_print(true);
  serializer.Serialize(metrics);

  return output;
}

base::Value::Dict MetricsUtils::RefineStateMetricsReadability(
    const base::Value::Dict& original_state_metrics) {
  base::Value::Dict new_state_metrics;
  for (const auto& [state_case_str, metrics_data] : original_state_metrics) {
    // For each state, we should have a dict to store metrics data.
    CHECK(metrics_data.is_dict());
    auto it = kStateNames.end();
    if (int state_case; base::StringToInt(state_case_str, &state_case)) {
      it = kStateNames.find(static_cast<RmadState::StateCase>(state_case));
      if (it != kStateNames.end()) {
        // Remap state_cases to names and remove timestamps for all states.
        auto new_metrics_data = metrics_data.Clone();
        new_metrics_data.GetDict().Remove(kStateSetupTimestamp);
        new_state_metrics.Set(it->second, std::move(new_metrics_data));
      }
    }
  }
  return new_state_metrics;
}

}  // namespace rmad
