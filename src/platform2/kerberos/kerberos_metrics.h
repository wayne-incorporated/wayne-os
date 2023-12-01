// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef KERBEROS_KERBEROS_METRICS_H_
#define KERBEROS_KERBEROS_METRICS_H_

#include <memory>
#include <string>

#include <base/files/file_path.h>
#include <metrics/metrics_library.h>
#include <metrics/timer.h>

#include "kerberos/proto_bindings/kerberos_service.pb.h"

namespace base {
class Clock;
}

namespace kerberos {

// These values are persisted to logs. Entries should not be renumbered and
// numeric values should never be reused.
enum class KerberosEncryptionTypes {
  kAll = 0,
  kStrong = 1,
  kLegacy = 2,
  kCount = 3,
};

// Submits UMA metrics. Some methods are virtual for tests.
class KerberosMetrics {
 public:
  explicit KerberosMetrics(const base::FilePath& storage_dir);
  KerberosMetrics(const KerberosMetrics&) = delete;
  KerberosMetrics& operator=(const KerberosMetrics&) = delete;

  virtual ~KerberosMetrics();

  // Starts timing Kerberos ticket acquisition.
  virtual void StartAcquireTgtTimer();

  // Stops timing Kerberos ticket acquisition and reports the time.
  virtual void StopAcquireTgtTimerAndReport();

  // Sends |error| to the UMA stat for Kerberos.Result.|method_name|, where
  // |method_name| should be a Kerberos D-Bus method (e.g. 'AddAccount').
  // crbug.com/991316: Use std::string as workaround for ASAN.
  virtual void ReportDBusCallResult(const std::string& method_name,
                                    ErrorType error);

  // Sends |code| to the UMA stat for Kerberos.ValidateConfigErrorCode.
  virtual void ReportValidateConfigErrorCode(ConfigErrorCode code);

  // Send |types| to UMA stat for Kerberos.EncryptionTypesAcquireKerberosTgt.
  virtual void ReportKerberosEncryptionTypes(KerberosEncryptionTypes types);

  // Returns true if at least a day has passed since the last time this method
  // returned true.
  virtual bool ShouldReportDailyUsageStats();

  // Sends UMA stats for various usage counters. |total_count| is the total
  // number of accounts. |managed_count| is the number of managed accounts.
  // Similarly, |unmanaged_count|. |remembered_password_count| is the number of
  // accounts with a remembered password. |use_login_password_count| is the
  // number of accounts that use the login password.
  virtual void ReportDailyUsageStats(int total_count,
                                     int managed_count,
                                     int unmanaged_count,
                                     int remembered_password_count,
                                     int use_login_password_count);

  // Overrides the clock used for rate limiting reporting daily usage stats.
  void SetClockForTesting(std::unique_ptr<base::Clock> clock);

  base::Clock* clock() { return clock_.get(); }

 private:
  // Sends count to the Kerberos.NumberOfAccounts.|name| stat.
  void SendAccountCount(const char* name, int count);

  // UMA prefix ("Kerberos."). For easy concatenation.
  const std::string kerberos_;

  // Low level metrics library.
  MetricsLibrary metrics_lib_;

  // Timer for reporting the time of acquiring a Kerberos ticket.
  chromeos_metrics::TimerReporter acquire_tgt_timer_;

  // File path where the timestamp of the last daily UMA report is stored.
  const base::FilePath daily_report_time_path_;

  // Clock to rate-limit daily events, can be overridden for tests.
  std::unique_ptr<base::Clock> clock_;
};

}  // namespace kerberos

#endif  // KERBEROS_KERBEROS_METRICS_H_
