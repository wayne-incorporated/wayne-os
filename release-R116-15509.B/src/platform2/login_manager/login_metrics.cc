// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This file handles the details of reporting user metrics related to login.

#include "login_manager/login_metrics.h"

#include <string>

#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/system/sys_info.h>
#include <base/time/default_clock.h>
#include <base/time/default_tick_clock.h>
#include <metrics/bootstat.h>
#include <metrics/metrics_library.h>

#include "login_manager/cumulative_use_time_metric.h"

namespace login_manager {
namespace {
// Uptime stats file created when session_manager executes Chrome.
// For any case of reload after crash no stats are recorded.
// For any signout stats are recorded.
const char kChromeUptimeFile[] = "/tmp/uptime-chrome-exec";

// A metric to track the time between when SIGTERM is sent to the browser
// process and when the browser process group exits (or killed via SIGABRT).
const char kLoginBrowserShutdownTimeMetric[] = "Login.BrowserShutdownTime";

// A metric to track the time taken to execute arc-boot-continue impulse.
const char kArcContinueBootImpulseTime3Metric[] =
    "Login.ArcContinueBootImpulseTime3";
const char kArcContinueBootImpulseStatus[] =
    "Login.ArcContinueBootImpulseStatus";

const char kLoginStateKeyGenerationStatus[] = "Login.StateKeyGenerationStatus";
const char kSessionExitTypeMetric[] = "Login.SessionExitType";
const char kLoginDevicePolicyStateMetric[] = "Login.DevicePolicyState";
// |OwnershipState| * |PolicyFileState| ^ 2
const int kMaxDevicePolicyStateValue = 45;
const char kInvalidDevicePolicyFilesStatus[] =
    "Enterprise.InvalidDevicePolicyFilesStatus";
const char kLoginMetricsFlagFile[] = "per_boot_flag";
const char kMetricsDir[] = "/var/lib/metrics";

const char kArcCumulativeUseTimeMetric[] = "Arc.CumulativeUseTime";
const char kLoginMountNamespaceMetric[] = "Login.MountNamespaceCreationSuccess";

const char kSwitchToFeatureFlagMappingStatus[] =
    "Login.SwitchToFeatureFlagMappingStatus";

const char kLivenessPingResponseTimeMetric[] =
    "ChromeOS.Liveness.PingResponseTime";

const char kLivenessPingResultMetric[] = "ChromeOS.Liveness.PingResult";

}  // namespace

LoginMetrics::LoginMetrics(const base::FilePath& per_boot_flag_dir)
    : per_boot_flag_file_(per_boot_flag_dir.Append(kLoginMetricsFlagFile)) {
  if (metrics_lib_.AreMetricsEnabled()) {
    arc_cumulative_use_time_.reset(new CumulativeUseTimeMetric(
        kArcCumulativeUseTimeMetric, &metrics_lib_, base::FilePath(kMetricsDir),
        std::make_unique<base::DefaultClock>(),
        std::make_unique<base::DefaultTickClock>()));
    std::string version;
    base::SysInfo::GetLsbReleaseValue("CHROMEOS_RELEASE_VERSION", &version);
    arc_cumulative_use_time_->Init(version);
  }
}

LoginMetrics::~LoginMetrics() {}

void LoginMetrics::SendNamespaceCreationResult(bool status) {
  metrics_lib_.SendBoolToUMA(kLoginMountNamespaceMetric, status);
}

void LoginMetrics::SendStateKeyGenerationStatus(
    StateKeyGenerationStatus status) {
  metrics_lib_.SendEnumToUMA(kLoginStateKeyGenerationStatus, status,
                             STATE_KEY_STATUS_COUNT);
}

void LoginMetrics::RecordStats(const char* tag) {
  bootstat::BootStat().LogEvent(tag);
}

bool LoginMetrics::HasRecordedChromeExec() {
  return base::PathExists(base::FilePath(kChromeUptimeFile));
}

void LoginMetrics::StartTrackingArcUseTime() {
  if (arc_cumulative_use_time_)
    arc_cumulative_use_time_->Start();
}

void LoginMetrics::StopTrackingArcUseTime() {
  if (arc_cumulative_use_time_)
    arc_cumulative_use_time_->Stop();
}

void LoginMetrics::SendInvalidPolicyFilesStatus(
    InvalidDevicePolicyFilesStatus result) {
  metrics_lib_.SendEnumToUMA(
      kInvalidDevicePolicyFilesStatus, static_cast<int>(result),
      static_cast<int>(InvalidDevicePolicyFilesStatus::NUM_VALUES));
}

void LoginMetrics::SendSessionExitType(SessionExitType session_exit_type) {
  metrics_lib_.SendEnumToUMA(kSessionExitTypeMetric,
                             static_cast<int>(session_exit_type),
                             static_cast<int>(SessionExitType::NUM_VALUES));
}

void LoginMetrics::SendBrowserShutdownTime(
    base::TimeDelta browser_shutdown_time) {
  // Browser shutdown time is between 0 - 12s and split it up into 50 buckets.
  metrics_lib_.SendToUMA(
      kLoginBrowserShutdownTimeMetric,
      static_cast<int>(browser_shutdown_time.InMilliseconds()),
      static_cast<int>(base::Milliseconds(1).InMilliseconds()),
      static_cast<int>(base::Seconds(12).InMilliseconds()), 50);
}

void LoginMetrics::SendArcContinueBootImpulseStatus(
    ArcContinueBootImpulseStatus status) {
  metrics_lib_.SendEnumToUMA(
      kArcContinueBootImpulseStatus, static_cast<int>(status),
      static_cast<int>(ArcContinueBootImpulseStatus::kMaxValue));
}

void LoginMetrics::SendArcContinueBootImpulseTime(
    base::TimeDelta arc_continue_boot_impulse_time) {
  // ARC continue-arc-boot impulse time is between 0 - 60s and split it up into
  // 50 buckets.
  metrics_lib_.SendToUMA(
      kArcContinueBootImpulseTime3Metric,
      static_cast<int>(arc_continue_boot_impulse_time.InMilliseconds()),
      static_cast<int>(base::Milliseconds(1).InMilliseconds()),
      static_cast<int>(base::Seconds(40).InMilliseconds()), 50);
}

void LoginMetrics::SendSwitchToFeatureFlagMappingStatus(
    SwitchToFeatureFlagMappingStatus status) {
  metrics_lib_.SendEnumToUMA(
      kSwitchToFeatureFlagMappingStatus, static_cast<int>(status),
      static_cast<int>(
          SwitchToFeatureFlagMappingStatus::NUM_SWITCHES_STATUSES));
}

void LoginMetrics::SendLivenessPingResponseTime(base::TimeDelta response_time) {
  metrics_lib_.SendToUMA(
      kLivenessPingResponseTimeMetric,
      static_cast<int>(response_time.InMilliseconds()),
      static_cast<int>(base::Milliseconds(1).InMilliseconds()),
      static_cast<int>(base::Seconds(60).InMilliseconds()), 50);
}

void LoginMetrics::SendLivenessPingResult(bool success) {
  metrics_lib_.SendBoolToUMA(kLivenessPingResultMetric, success);
}

void LoginMetrics::ReportCrosEvent(const std::string& event) {
  metrics_lib_.SendCrosEventToUMA(event);
}

void LoginMetrics::SendDevicePolicyFilesMetrics(
    DevicePolicyFilesStatus status) {
  metrics_lib_.SendEnumToUMA(kLoginDevicePolicyStateMetric,
                             DevicePolicyStatusCode(status),
                             kMaxDevicePolicyStateValue);
}

// static
// Code for incognito, owner and any other user are 0, 1 and 2
// respectively in normal mode. In developer mode they are 3, 4 and 5.
int LoginMetrics::LoginUserTypeCode(bool dev_mode, bool guest, bool owner) {
  if (!dev_mode) {
    if (guest)
      return GUEST;
    if (owner)
      return OWNER;
    return OTHER;
  }
  // If we get here, we're in dev mode.
  if (guest)
    return DEV_GUEST;
  if (owner)
    return DEV_OWNER;
  return DEV_OTHER;
}

// static
int LoginMetrics::DevicePolicyStatusCode(
    const DevicePolicyFilesStatus& status) {
  return status.owner_key_file_state * 1 + status.policy_file_state * 3 +
         status.ownership_state * 9;
}

}  // namespace login_manager
