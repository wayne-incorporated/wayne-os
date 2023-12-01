// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "rmad/metrics/metrics_utils_impl.h"

#include <map>
#include <string>
#include <vector>

#include <base/logging.h>
#include <base/memory/scoped_refptr.h>
#include <base/time/time.h>
#include <metrics/structured_events.h>

#include "rmad/constants.h"
#include "rmad/metrics/metrics_constants.h"
#include "rmad/metrics/state_metrics.h"
#include "rmad/utils/json_store.h"

using StructuredShimlessRmaReport =
    metrics::structured::events::rmad::ShimlessRmaReport;
using StructuredReplacedComponent =
    metrics::structured::events::rmad::ReplacedComponent;
using StructuredOccurredError =
    metrics::structured::events::rmad::OccurredError;
using StructuredAdditionalActivity =
    metrics::structured::events::rmad::AdditionalActivity;
using StructuredShimlessRmaStateReport =
    metrics::structured::events::rmad::ShimlessRmaStateReport;

namespace rmad {

MetricsUtilsImpl::MetricsUtilsImpl(bool record_to_system)
    : record_to_system_(record_to_system) {}

bool MetricsUtilsImpl::RecordShimlessRmaReport(
    scoped_refptr<JsonStore> json_store) {
  auto report = StructuredShimlessRmaReport();
  double current_timestamp = base::Time::Now().ToDoubleT();
  double first_setup_timestamp;
  if (!GetMetricsValue(json_store, kMetricsFirstSetupTimestamp,
                       &first_setup_timestamp)) {
    LOG(ERROR) << "Failed to get timestamp of the first setup.";
    return false;
  }
  report.SetOverallTime(current_timestamp - first_setup_timestamp);

  double setup_timestamp;
  if (!GetMetricsValue(json_store, kMetricsSetupTimestamp, &setup_timestamp) ||
      !SetMetricsValue(json_store, kMetricsSetupTimestamp, current_timestamp)) {
    LOG(ERROR) << "Failed to get and reset setup timestamp for measuring "
                  "running time.";
    return false;
  }
  double running_time = 0.0;
  // It could be the first time we have calculated the running time, thus the
  // return value is ignored.
  GetMetricsValue(json_store, kMetricsRunningTime, &running_time);
  running_time += current_timestamp - setup_timestamp;
  report.SetRunningTime(running_time);

  if (bool is_complete;
      GetMetricsValue(json_store, kMetricsIsComplete, &is_complete)) {
    report.SetIsComplete(is_complete);
  } else {
    report.SetIsComplete(false);
  }

  RoVerificationStatus ro_verification;
  if (std::string ro_verification_str;
      GetMetricsValue(json_store, kMetricsRoFirmwareVerified,
                      &ro_verification_str) &&
      RoVerificationStatus_Parse(ro_verification_str, &ro_verification)) {
    report.SetRoVerificationStatus(ro_verification);
  } else {
    report.SetRoVerificationStatus(RMAD_RO_VERIFICATION_UNKNOWN);
  }

  ReturningOwner returning_owner;
  if (std::string returning_owner_str;
      GetMetricsValue(json_store, kMetricsReturningOwner,
                      &returning_owner_str) &&
      ReturningOwner_Parse(returning_owner_str, &returning_owner)) {
    report.SetReturningOwner(returning_owner);
  } else {
    report.SetReturningOwner(RMAD_RETURNING_OWNER_UNKNOWN);
  }

  MainboardReplacement mlb_replacement;
  if (std::string mlb_replacement_str;
      GetMetricsValue(json_store, kMetricsMlbReplacement,
                      &mlb_replacement_str) &&
      MainboardReplacement_Parse(mlb_replacement_str, &mlb_replacement)) {
    report.SetMainboardReplacement(mlb_replacement);
  } else {
    report.SetMainboardReplacement(RMAD_MLB_REPLACEMENT_UNKNOWN);
  }

  WpDisableMethod wp_disable_method;
  if (std::string wp_disable_method_str;
      GetMetricsValue(json_store, kMetricsWpDisableMethod,
                      &wp_disable_method_str) &&
      WpDisableMethod_Parse(wp_disable_method_str, &wp_disable_method)) {
    report.SetWriteProtectDisableMethod(wp_disable_method);
  } else {
    report.SetWriteProtectDisableMethod(RMAD_WP_DISABLE_METHOD_UNKNOWN);
  }

  if (record_to_system_ && !report.Record()) {
    LOG(ERROR) << "Failed to record shimless rma report to metrics.";
    return false;
  }

  return true;
}

bool MetricsUtilsImpl::RecordReplacedComponents(
    scoped_refptr<JsonStore> json_store) {
  // Ignore the else part, because we may not replace anything.
  if (std::vector<std::string> replace_component_names;
      MetricsUtils::GetMetricsValue(json_store, kMetricsReplacedComponents,
                                    &replace_component_names)) {
    for (const std::string& component_name : replace_component_names) {
      if (RmadComponent component;
          RmadComponent_Parse(component_name, &component)) {
        auto structured_replace_component = StructuredReplacedComponent();
        structured_replace_component.SetComponentCategory(component);
        if (record_to_system_ && !structured_replace_component.Record()) {
          LOG(ERROR) << "Failed to record replaced component to metrics.";
          return false;
        }
      } else {
        LOG(ERROR) << "Failed to parse [" << component_name
                   << "] as component to append to metrics.";
        return false;
      }
    }
  }
  return true;
}

bool MetricsUtilsImpl::RecordOccurredErrors(
    scoped_refptr<JsonStore> json_store) {
  // Ignore the else part, because we may have no errors.
  if (std::vector<std::string> occurred_errors;
      GetMetricsValue(json_store, kMetricsOccurredErrors, &occurred_errors)) {
    for (const std::string& occurred_error : occurred_errors) {
      if (RmadErrorCode error_code;
          RmadErrorCode_Parse(occurred_error, &error_code)) {
        auto structured_occurred_error = StructuredOccurredError();
        structured_occurred_error.SetErrorType(error_code);
        if (record_to_system_ && !structured_occurred_error.Record()) {
          LOG(ERROR) << "Failed to record error code to metrics.";
          return false;
        }
      } else {
        LOG(ERROR) << "Failed to parse [" << occurred_error
                   << "] as error code to append to metrics.";
        return false;
      }
    }
  }
  return true;
}

bool MetricsUtilsImpl::RecordAdditionalActivities(
    scoped_refptr<JsonStore> json_store) {
  // Ignore the else part, because we may have no additional activities.
  if (std::vector<std::string> additional_activities; GetMetricsValue(
          json_store, kMetricsAdditionalActivities, &additional_activities)) {
    for (std::string activity_name : additional_activities) {
      AdditionalActivity additional_activity;
      if (AdditionalActivity_Parse(activity_name, &additional_activity) &&
          additional_activity != RMAD_ADDITIONAL_ACTIVITY_NOTHING) {
        auto structured_additional_activity = StructuredAdditionalActivity();
        structured_additional_activity.SetActivityType(additional_activity);
        if (record_to_system_ && !structured_additional_activity.Record()) {
          LOG(ERROR) << "Failed to record additional activity to metrics.";
          return false;
        }
      } else {
        LOG(ERROR) << "Failed to parse [" << activity_name
                   << "] as additional activity to append to metrics.";
        return false;
      }
    }
  }
  return true;
}

bool MetricsUtilsImpl::RecordShimlessRmaStateReport(
    scoped_refptr<JsonStore> json_store) {
  std::map<int, StateMetricsData> state_metrics;

  if (GetMetricsValue(json_store, kStateMetrics, &state_metrics)) {
    for (auto [state_case, data] : state_metrics) {
      auto structured_state_report = StructuredShimlessRmaStateReport();

      structured_state_report.SetStateCase(state_case);

      structured_state_report.SetIsAborted(data.is_aborted);

      if (data.overall_time < 0) {
        LOG(ERROR) << state_case
                   << ": Invalid overall time: " << data.overall_time;
        return false;
      }
      structured_state_report.SetOverallTime(data.overall_time);

      if (data.transition_count <= 0) {
        LOG(ERROR) << state_case
                   << ": Invalid transition count: " << data.transition_count;
        return false;
      }
      structured_state_report.SetTransitionCount(data.transition_count);

      if (data.get_log_count < 0) {
        LOG(ERROR) << state_case
                   << ": Invalid GetLog count: " << data.get_log_count;
        return false;
      }
      structured_state_report.SetGetLogCount(data.get_log_count);

      if (data.save_log_count < 0) {
        LOG(ERROR) << state_case
                   << ": Invalid SaveLog count: " << data.save_log_count;
        return false;
      }
      structured_state_report.SetSaveLogCount(data.save_log_count);

      if (record_to_system_ && !structured_state_report.Record()) {
        LOG(ERROR) << state_case
                   << ": Failed to record state report to metrics.";
        return false;
      }
    }
  }

  return true;
}

bool MetricsUtilsImpl::RecordAll(scoped_refptr<JsonStore> json_store) {
  return RecordShimlessRmaReport(json_store) &&
         RecordOccurredErrors(json_store) &&
         RecordReplacedComponents(json_store) &&
         RecordAdditionalActivities(json_store) &&
         RecordShimlessRmaStateReport(json_store);
}

}  // namespace rmad
