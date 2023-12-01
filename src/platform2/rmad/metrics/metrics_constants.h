// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RMAD_METRICS_METRICS_CONSTANTS_H_
#define RMAD_METRICS_METRICS_CONSTANTS_H_

#include <array>

#include "rmad/proto_bindings/rmad.pb.h"

namespace rmad {

// JsonStore additional keys for metrics usage.
inline constexpr char kMetrics[] = "metrics";

inline constexpr char kMetricsFirstSetupTimestamp[] = "first_setup_timestamp";
inline constexpr char kMetricsSetupTimestamp[] = "setup_timestamp";
inline constexpr char kMetricsRunningTime[] = "running_time";
inline constexpr char kMetricsIsComplete[] = "is_complete";
inline constexpr char kMetricsRoFirmwareVerified[] = "ro_firmware_verified";
inline constexpr char kMetricsReturningOwner[] = "returning_owner";
inline constexpr char kMetricsMlbReplacement[] = "mainboard_replacement";
inline constexpr char kMetricsWpDisableMethod[] = "wp_disable_method";

inline constexpr char kMetricsReplacedComponents[] = "replaced_components";
inline constexpr char kMetricsOccurredErrors[] = "occurred_errors";
inline constexpr char kMetricsAdditionalActivities[] = "additional_activities";

// This is a dict of dicts for states store info by |state_case|.
inline constexpr char kStateMetrics[] = "state_metrics";

// The part should be under kStateMetrics[state_case].
// Only used when converting from StateMetricsData to base::Value.
inline constexpr char kStateCase[] = "state_case";
inline constexpr char kStateIsAborted[] = "state_is_aborted";
inline constexpr char kStateSetupTimestamp[] = "state_setup_timestamp";
inline constexpr char kStateOverallTime[] = "state_overall_time";
inline constexpr char kStateTransitionsCount[] = "state_transition_count";
inline constexpr char kStateGetLogCount[] = "state_get_log_count";
inline constexpr char kStateSaveLogCount[] = "state_save_log_count";

constexpr std::array<AdditionalActivity, 3> kExpectedPowerCycleActivities = {
    RMAD_ADDITIONAL_ACTIVITY_SHUTDOWN, RMAD_ADDITIONAL_ACTIVITY_REBOOT,
    RMAD_ADDITIONAL_ACTIVITY_BATTERY_CUTOFF};

constexpr std::array<RmadErrorCode, 6> kExpectedErrorCodes = {
    RMAD_ERROR_NOT_SET,
    RMAD_ERROR_OK,
    RMAD_ERROR_WAIT,
    RMAD_ERROR_EXPECT_REBOOT,
    RMAD_ERROR_EXPECT_SHUTDOWN,
    RMAD_ERROR_RMA_NOT_REQUIRED};

}  // namespace rmad

#endif  // RMAD_METRICS_METRICS_CONSTANTS_H_
