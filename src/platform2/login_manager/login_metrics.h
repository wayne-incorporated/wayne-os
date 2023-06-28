// Copyright (c) 2012 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LOGIN_MANAGER_LOGIN_METRICS_H_
#define LOGIN_MANAGER_LOGIN_METRICS_H_

#include <memory>
#include <string>

#include <base/files/file_path.h>
#include <base/macros.h>
#include <base/time/time.h>
#include <metrics/metrics_library.h>

namespace login_manager {

class CumulativeUseTimeMetric;

class LoginMetrics {
 public:
  // Do we believe the session exited due to a login crash loop?
  // These values are persisted to metrics server. Entries (other than
  // NUM_VALUES) should not be renumbered and numeric values should never be
  // reused. If you update this enum, also update Chrome's enums.xml.
  enum class SessionExitType {
    NORMAL_EXIT = 0,
    LOGIN_CRASH_LOOP = 1,

    NUM_VALUES  // Keep last
  };
  enum AllowedUsersState { ANY_USER_ALLOWED = 0, ONLY_ALLOWLISTED = 1 };
  enum PolicyFileState {
    GOOD = 0,
    MALFORMED = 1,
    NOT_PRESENT = 2,
    NUM_STATES = 3
  };
  enum UserType {
    GUEST = 0,
    OWNER = 1,
    OTHER = 2,
    DEV_GUEST = 3,
    DEV_OWNER = 4,
    DEV_OTHER = 5,
    NUM_TYPES = 6
  };
  enum StateKeyGenerationStatus {
    STATE_KEY_STATUS_GENERATION_METHOD_IDENTIFIER_HASH = 0,
    STATE_KEY_STATUS_GENERATION_METHOD_HMAC_DEVICE_SECRET = 1,
    STATE_KEY_STATUS_MISSING_IDENTIFIERS = 2,
    STATE_KEY_STATUS_BAD_DEVICE_SECRET = 3,
    STATE_KEY_STATUS_HMAC_INIT_FAILURE = 4,
    STATE_KEY_STATUS_HMAC_SIGN_FAILURE = 5,
    STATE_KEY_STATUS_COUNT  // must be last.
  };
  enum InvalidDevicePolicyFilesStatus {
    ALL_VALID = 0,
    SOME_INVALID = 1,
    ALL_INVALID = 2,
    NUM_VALUES = 3
  };
  enum SwitchToFeatureFlagMappingStatus {
    SWITCHES_ABSENT = 0,
    SWITCHES_VALID = 1,
    SWITCHES_INVALID = 2,
    NUM_SWITCHES_STATUSES = 3,
  };
  // Holds the state of several policy-related files on disk.
  // We leave an extra bit for future state-space expansion.
  // Treat as, essentially, a base-4 number that we encode in decimal before
  // sending to chrome as a metric.
  // Digits are in this order:
  // Key file state - policy file state - old prefs file state.
  //
  // Some codes of interest:
  // CODE | Key | Policy | Prefs
  // -----+-----+--------+-------
  //  0   |  G  |   G    |  G     (Healthy, long-running users)
  //  2   |  G  |   G    |  N     (Healthy, newer users)
  //  8   |  G  |   N    |  G     (http://crosbug.com/24361)
  //  42  |  N  |   N    |  N     (As-yet unowned devices)
  //
  // Also, codes in the 9-17 range indicate a horked owner key with other files
  // in various states.  3-5, 12-14, and 21-23 indicate broken policy files.
  struct PolicyFilesStatus {
   public:
    PolicyFilesStatus()
        : owner_key_file_state(NOT_PRESENT),
          policy_file_state(NOT_PRESENT),
          defunct_prefs_file_state(NOT_PRESENT) {}
    virtual ~PolicyFilesStatus() {}

    PolicyFileState owner_key_file_state;
    PolicyFileState policy_file_state;
    PolicyFileState defunct_prefs_file_state;
  };

  explicit LoginMetrics(const base::FilePath& per_boot_flag_dir);
  LoginMetrics(const LoginMetrics&) = delete;
  LoginMetrics& operator=(const LoginMetrics&) = delete;

  virtual ~LoginMetrics();

  // Sends metric reporting whether the mount namespace creation succeeded or
  // failed.
  virtual void SendNamespaceCreationResult(bool status);

  // Sends metric reporting whether the Owner of this non-enrolled device has
  // chosen to allow arbitrary users to sign in or not.
  virtual void SendConsumerAllowsNewUsers(bool allowed);

  // Sends the type of user that logs in (guest, owner or other) and the mode
  // (developer or normal) to UMA by using the metrics library.
  virtual void SendLoginUserType(bool dev_mode, bool guest, bool owner);

  // Sends info about the state of the Owner key, device policy, and legacy
  // prefs file to UMA using the metrics library.
  // Returns true if stats are sent.
  virtual bool SendPolicyFilesStatus(const PolicyFilesStatus& status);

  // Writes a histogram indicating the state key generation method used.
  virtual void SendStateKeyGenerationStatus(StateKeyGenerationStatus status);

  // Record a stat called |tag| via the bootstat library.
  virtual void RecordStats(const char* tag);

  // Return true if we have already recorded that Chrome has exec'd.
  virtual bool HasRecordedChromeExec();

  // Starts tracking cumulative ARC usage time. Should be called when ARC
  // container is started.
  virtual void StartTrackingArcUseTime();

  // Stops tracking cumulative ARC usage time. Should be called when ARC
  // container is stopped.
  virtual void StopTrackingArcUseTime();

  // Submits to UMA the result of invalid policy checks.
  virtual void SendInvalidPolicyFilesStatus(
      InvalidDevicePolicyFilesStatus result);

  // Submits to UMA whether or not the session exited due to a login crash loop.
  virtual void SendSessionExitType(SessionExitType session_exit_type);

  // Submits to UMA the browser shutdown time of normal exit.
  virtual void SendBrowserShutdownTime(base::TimeDelta browser_shutdown_time);

  // Submits to UMA the time to backup ARC bug report.
  virtual void SendArcBugReportBackupTime(
      base::TimeDelta arc_bug_report_backup_time);

  // Submits to UMA the time to execute continue-arc-boot impulse.
  virtual void SendArcContinueBootImpulseTime(
      base::TimeDelta arc_continue_boot_impulse_time);

  // Submits a UMA sample indicating compatibility feature flag mapping status.
  virtual void SendSwitchToFeatureFlagMappingStatus(
      SwitchToFeatureFlagMappingStatus status);

  // CrOS events are translated to an enum and reported to the generic
  // "Platform.CrOSEvent" enum histogram. The |event| string must be registered
  // in metrics/metrics_library.cc:kCrosEventNames.
  virtual void ReportCrosEvent(const std::string& event);

 private:
  friend class LoginMetricsTest;
  friend class UserTypeTest;

  // Returns code to send to the metrics library based on the state of
  // several policy-related files on disk.
  // As each file has three possible states, treat as a base-3 number and
  // convert to decimal.
  static int PolicyFilesStatusCode(const PolicyFilesStatus& status);

  // Returns code to send to the metrics library based on the type of user
  // (owner, guest or other) and the mode (normal or developer).
  static int LoginUserTypeCode(bool dev_mode, bool guest, bool owner);

  const base::FilePath per_boot_flag_file_;
  MetricsLibrary metrics_lib_;
  std::unique_ptr<CumulativeUseTimeMetric> arc_cumulative_use_time_;
};
}  // namespace login_manager

#endif  // LOGIN_MANAGER_LOGIN_METRICS_H_
