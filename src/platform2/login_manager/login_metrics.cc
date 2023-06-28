// Copyright (c) 2012 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This file handles the details of reporting user metrics related to login.

#include "login_manager/login_metrics.h"

#include <string>

#include <base/files/file_util.h>
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

// A metric to track the time taken to backup ARC bug report.
const char kArcBugReportBackupTimeMetric[] = "Login.ArcBugReportBackupTime";

// A metric to track the time taken to execute arc-boot-continue impulse.
const char kArcContinueBootImpulseTimeMetric[] =
    "Login.ArcContinueBootImpulseTime";

const char kLoginConsumerAllowsNewUsersMetric[] =
    "Login.ConsumerNewUsersAllowed";
const char kLoginPolicyFilesMetric[] = "Login.PolicyFilesStatePerBoot";
const char kLoginUserTypeMetric[] = "Login.UserType";
const char kLoginStateKeyGenerationStatus[] = "Login.StateKeyGenerationStatus";
const char kSessionExitTypeMetric[] = "Login.SessionExitType";
const char kInvalidDevicePolicyFilesStatus[] =
    "Enterprise.InvalidDevicePolicyFilesStatus";
const int kMaxPolicyFilesValue = 64;
const char kLoginMetricsFlagFile[] = "per_boot_flag";
const char kMetricsDir[] = "/var/lib/metrics";

const char kArcCumulativeUseTimeMetric[] = "Arc.CumulativeUseTime";
const char kLoginMountNamespaceMetric[] = "Login.MountNamespaceCreationSuccess";

const char kSwitchToFeatureFlagMappingStatus[] =
    "Login.SwitchToFeatureFlagMappingStatus";

}  // namespace

// static
int LoginMetrics::PolicyFilesStatusCode(const PolicyFilesStatus& status) {
  return (status.owner_key_file_state * 16 /*    4^2 */ +
          status.policy_file_state * 4 /*        4^1 */ +
          status.defunct_prefs_file_state * 1 /* 4^0 */);
}

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

void LoginMetrics::SendConsumerAllowsNewUsers(bool allowed) {
  int uma_code = allowed ? ANY_USER_ALLOWED : ONLY_ALLOWLISTED;
  metrics_lib_.SendEnumToUMA(kLoginConsumerAllowsNewUsersMetric, uma_code, 2);
}

void LoginMetrics::SendLoginUserType(bool dev_mode,
                                     bool incognito,
                                     bool owner) {
  int uma_code = LoginUserTypeCode(dev_mode, incognito, owner);
  metrics_lib_.SendEnumToUMA(kLoginUserTypeMetric, uma_code, NUM_TYPES);
}

bool LoginMetrics::SendPolicyFilesStatus(const PolicyFilesStatus& status) {
  if (!base::PathExists(per_boot_flag_file_)) {
    metrics_lib_.SendEnumToUMA(kLoginPolicyFilesMetric,
                               LoginMetrics::PolicyFilesStatusCode(status),
                               kMaxPolicyFilesValue);
    bool created = base::WriteFile(per_boot_flag_file_, "", 0) == 0;
    PLOG_IF(WARNING, !created) << "Can't touch " << per_boot_flag_file_.value();
    return true;
  }
  return false;
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
      static_cast<int>(base::TimeDelta::FromMilliseconds(1).InMilliseconds()),
      static_cast<int>(base::TimeDelta::FromSeconds(12).InMilliseconds()), 50);
}

void LoginMetrics::SendArcBugReportBackupTime(
    base::TimeDelta arc_bug_report_backup_time) {
  // ARC bug report back-up time is between 0 - 60s and split it up into 50
  // buckets.
  metrics_lib_.SendToUMA(
      kArcBugReportBackupTimeMetric,
      static_cast<int>(arc_bug_report_backup_time.InMilliseconds()),
      static_cast<int>(base::TimeDelta::FromMilliseconds(1).InMilliseconds()),
      static_cast<int>(base::TimeDelta::FromSeconds(60).InMilliseconds()), 50);
}

void LoginMetrics::SendArcContinueBootImpulseTime(
    base::TimeDelta arc_continue_boot_impulse_time) {
  // ARC continue-arc-boot impulse time is between 0 - 30s and split it up into
  // 30 buckets.
  metrics_lib_.SendToUMA(
      kArcContinueBootImpulseTimeMetric,
      static_cast<int>(arc_continue_boot_impulse_time.InMilliseconds()),
      static_cast<int>(base::TimeDelta::FromMilliseconds(1).InMilliseconds()),
      static_cast<int>(base::TimeDelta::FromSeconds(30).InMilliseconds()), 30);
}

void LoginMetrics::SendSwitchToFeatureFlagMappingStatus(
    SwitchToFeatureFlagMappingStatus status) {
  metrics_lib_.SendEnumToUMA(
      kSwitchToFeatureFlagMappingStatus, static_cast<int>(status),
      static_cast<int>(
          SwitchToFeatureFlagMappingStatus::NUM_SWITCHES_STATUSES));
}

void LoginMetrics::ReportCrosEvent(const std::string& event) {
  metrics_lib_.SendCrosEventToUMA(event);
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

}  // namespace login_manager
