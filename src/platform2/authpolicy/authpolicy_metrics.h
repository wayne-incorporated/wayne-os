// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef AUTHPOLICY_AUTHPOLICY_METRICS_H_
#define AUTHPOLICY_AUTHPOLICY_METRICS_H_

#include <metrics/metrics_library.h>
#include <metrics/timer.h>

#include "authpolicy/proto_bindings/active_directory_info.pb.h"

namespace chromeos_metrics {
class TimerReporter;
}  // namespace chromeos_metrics

namespace authpolicy {

// Timer metrics. Measure execution time of certain commands or functions. Keep
// in sync with kTimerHistogramParams!
enum TimerType {
  TIMER_NET_ADS_GPO_LIST,         // net ads gpo list.
  TIMER_NET_ADS_INFO,             // net ads info.
  TIMER_NET_ADS_JOIN,             // net ads join.
  TIMER_NET_ADS_SEARCH,           // net ads search.
  TIMER_NET_ADS_WORKGROUP,        // net ads workgroup.
  TIMER_KINIT,                    // kinit.
  TIMER_KLIST,                    // klist.
  TIMER_KPASSWD,                  // kpasswd.
  TIMER_SMBCLIENT,                // smbclient.
  TIMER_AUTHENTICATE_USER,        // User authentication D-Bus call.
  TIMER_GET_USER_STATUS,          // User status query D-Bus call.
  TIMER_GET_USER_KERBEROS_FILES,  // User kerberos files query D-Bus call.
  TIMER_JOIN_AD_DOMAIN,           // Domain join D-Bus call.
  TIMER_REFRESH_USER_POLICY,      // User/device policy fetch D-Bus calls,
  TIMER_REFRESH_DEVICE_POLICY,    //   including the Session Manager calls.
  TIMER_COUNT,                    // Total number of timers.
  TIMER_NONE,                     // Invalid/no timer.
};

// Normal exponential metrics. Keep in sync with kMetricHistogramParams!
enum MetricType {
  METRIC_KINIT_FAILED_TRY_COUNT,      // Number of failed kinit tries.
  METRIC_SMBCLIENT_FAILED_TRY_COUNT,  // Number of failed smbclient tries.
  METRIC_DOWNLOAD_GPO_COUNT,          // Number of GPOs to download.
  METRIC_COUNT,                       // Total number of metrics.
};

// Enum metric for error types returned from D-Bus calls and scheduled
// operations. Should contain all D-Bus calls in authpolicy::AuthPolicy. Keep in
// sync with kErrorTypeMetricParams!
enum ErrorMetricType {
  ERROR_OF_AUTHENTICATE_USER,             // D-Bus call AuthenticateUser.
  ERROR_OF_GET_USER_STATUS,               // D-Bus call GetUserStatus.
  ERROR_OF_GET_USER_KERBEROS_FILES,       // D-Bus call GetUserKerberosFiles.
  ERROR_OF_JOIN_AD_DOMAIN,                // D-Bus call JoinAdDomain.
  ERROR_OF_REFRESH_USER_POLICY,           // D-Bus call RefreshUserPolicy.
  ERROR_OF_REFRESH_DEVICE_POLICY,         // D-Bus call RefreshDevicePolicy.
  ERROR_OF_AUTO_TGT_RENEWAL,              // Automatic TGT renewal.
  ERROR_OF_AUTO_MACHINE_PASSWORD_CHANGE,  // Automatic machine password change.
  ERROR_OF_COUNT,
};

// Enum metric for encryption types used during user authentication or domain
// join. Keep in sync with kEncryptionMetricParams!
enum EncryptionMetricType {
  ENC_TYPES_OF_AUTHENTICATE_USER,  // Encryption types used to authenticate
                                   // user.
  ENC_TYPES_OF_JOIN_AD_DOMAIN,     // Encryption types used to join AD domain.
  ENC_METRIC_COUNT,                // Total number of encryption metrics.
};

class AuthPolicyMetrics;

// Simpler wrapper around |chromeos_metrics::TimerReporter| that starts the
// timer at construction and stops it and reports the total time at destruction.
class ScopedTimerReporter {
 public:
  explicit ScopedTimerReporter(TimerType timer_type);
  ScopedTimerReporter(const ScopedTimerReporter&) = delete;
  ScopedTimerReporter& operator=(const ScopedTimerReporter&) = delete;
  ~ScopedTimerReporter();

 private:
  // Internal fudging to make sure the range of |timer_type| is checked before
  // the array of timer parameters is accessed.
  struct CheckedTimerType {
    explicit CheckedTimerType(TimerType value);
    TimerType value_;
  };
  explicit ScopedTimerReporter(CheckedTimerType timer_type);

  chromeos_metrics::TimerReporter timer_;
};

// Submits UMA metrics for authpolicy. Some methods are virtual for tests.
class AuthPolicyMetrics {
 public:
  AuthPolicyMetrics();
  AuthPolicyMetrics(const AuthPolicyMetrics&) = delete;
  AuthPolicyMetrics& operator=(const AuthPolicyMetrics&) = delete;

  virtual ~AuthPolicyMetrics();

  // Report a |sample| for the given |metric_type|.
  virtual void Report(MetricType metric_type, int sample);

  // Report an |ErrorType| return value from a D-Bus query or a scheduled
  // operation.
  virtual void ReportError(ErrorMetricType metric_type, ErrorType error);

  // Report the |KerberosEncryptionTypes| used during user authentication or
  // domain join.
  virtual void ReportEncryptionType(EncryptionMetricType metric_type,
                                    KerberosEncryptionTypes encryption_types);

 private:
  MetricsLibrary metrics_;
};

}  // namespace authpolicy

#endif  // AUTHPOLICY_AUTHPOLICY_METRICS_H_
