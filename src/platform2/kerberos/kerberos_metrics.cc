// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "kerberos/kerberos_metrics.h"

#include <utility>

#include <base/check.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/strings/stringprintf.h>
#include <base/time/clock.h>
#include "base/time/default_clock.h"

namespace kerberos {

namespace {

// Prefix for all UMA stats.
constexpr char kKerberos[] = "Kerberos.";

// Prefix for Kerberos.Result.<method name> stats.
constexpr char kResult[] = "Result.";

// Stat for the result of a ValidateConfig call.
constexpr char kValidateConfigErrorCode[] = "ValidateConfigErrorCode";

// Stat for the encryption types used on Kerberos TGT creation.
constexpr char kEncryptionTypesAcquireKerberosTgt[] =
    "EncryptionTypesAcquireKerberosTgt";

// Stat for counting user types, see |UserType|.
constexpr char kDailyActiveUsers[] = "DailyActiveUsers";

// Prefix for UMA stats that are counting accounts.
constexpr char kNumberOfAccounts[] = "NumberOfAccounts.";

// Stat names for counting accounts, prefixed by "Kerberos.NumberOfAccounts.".
constexpr char kTotal[] = "Total";
constexpr char kManaged[] = "Managed";
constexpr char kUnmanaged[] = "Unmanaged";
constexpr char kRememberedPassword[] = "RememberedPassword";
constexpr char kUseLoginPassword[] = "UseLoginPassword";

// Max number of accounts for UMA stats.
constexpr int kMaxAccounts = 10;

// Used to rate limit some UMA stats to once a day.
constexpr char kDailyReportTimeFile[] = "daily_report_timestamp";

// User type to be sent to Kerberos.DailyActiveUsers. These values (except
// UserType::kCount, which should be last) are persisted to logs. Entries should
// not be renumbered and numeric values should never be reused.
enum class UserType { kManaged = 0, kUnmanaged = 1, kCount = 2 };

}  // namespace

KerberosMetrics::KerberosMetrics(const base::FilePath& storage_dir)
    : kerberos_(kKerberos),
      acquire_tgt_timer_(kerberos_ + "AcquireKerberosTgtTime",
                         1 /* min 1 millisecond */,
                         20000 /* max 20 seconds */,
                         50 /* bucket count */),
      daily_report_time_path_(storage_dir.Append(kDailyReportTimeFile)),
      clock_(std::make_unique<base::DefaultClock>()) {
  chromeos_metrics::TimerReporter::set_metrics_lib(&metrics_lib_);
}

KerberosMetrics::~KerberosMetrics() {
  chromeos_metrics::TimerReporter::set_metrics_lib(nullptr);
}

void KerberosMetrics::StartAcquireTgtTimer() {
  DCHECK(!acquire_tgt_timer_.HasStarted());
  acquire_tgt_timer_.Start();
}

void KerberosMetrics::StopAcquireTgtTimerAndReport() {
  DCHECK(acquire_tgt_timer_.HasStarted());
  acquire_tgt_timer_.Stop();
  acquire_tgt_timer_.ReportMilliseconds();
}

void KerberosMetrics::ReportDBusCallResult(const std::string& method_name,
                                           ErrorType error) {
  metrics_lib_.SendEnumToUMA(kerberos_ + kResult + method_name,
                             static_cast<int>(error),
                             static_cast<int>(ERROR_COUNT));
}

void KerberosMetrics::ReportValidateConfigErrorCode(ConfigErrorCode code) {
  metrics_lib_.SendEnumToUMA(kerberos_ + kValidateConfigErrorCode,
                             static_cast<int>(code),
                             static_cast<int>(CONFIG_ERROR_COUNT));
}

void KerberosMetrics::ReportKerberosEncryptionTypes(
    KerberosEncryptionTypes types) {
  metrics_lib_.SendEnumToUMA(kerberos_ + kEncryptionTypesAcquireKerberosTgt,
                             static_cast<int>(types),
                             static_cast<int>(KerberosEncryptionTypes::kCount));
}

bool KerberosMetrics::ShouldReportDailyUsageStats() {
  const base::Time now = clock_->Now();

  base::File::Info info;
  if (!base::GetFileInfo(daily_report_time_path_, &info)) {
    // Create the file. Don't skew stats if something goes wrong. Note that
    // base::TouchFile bails if the file doesn't exist!
    const bool res =
        base::WriteFile(daily_report_time_path_, nullptr, 0) == 0 &&
        base::TouchFile(daily_report_time_path_, now, now);
    if (!res)
      LOG(WARNING) << "Failed to touch " << daily_report_time_path_.value();
    return res;
  }

  // Be sure to gracefully handle the case when the clock is moved backwards.
  const base::Time last_file_time = info.last_modified;
  int days_elapsed = (now - last_file_time).InDays();
  if (days_elapsed == 0)
    return false;

  // Don't set the new file time to |now|. This would result in an average
  // frequency of less than one day.
  base::Time new_time = last_file_time + days_elapsed * base::Days(1);
  const bool res = base::TouchFile(daily_report_time_path_, new_time, new_time);
  if (!res)
    LOG(WARNING) << "Failed to touch " << daily_report_time_path_.value();

  // Don't report if time goes backwards (but do reset the file time!).
  return days_elapsed > 0;
}

void KerberosMetrics::ReportDailyUsageStats(int total_count,
                                            int managed_count,
                                            int unmanaged_count,
                                            int remembered_password_count,
                                            int use_login_password_count) {
  // TODO(b/259178132): Send the proper user type once unmanaged users can use
  // this feature.
  metrics_lib_.SendEnumToUMA(kerberos_ + kDailyActiveUsers,
                             static_cast<int>(UserType::kManaged),
                             static_cast<int>(UserType::kCount));

  SendAccountCount(kTotal, total_count);
  SendAccountCount(kManaged, managed_count);
  SendAccountCount(kUnmanaged, unmanaged_count);
  SendAccountCount(kRememberedPassword, remembered_password_count);
  SendAccountCount(kUseLoginPassword, use_login_password_count);
}

void KerberosMetrics::SetClockForTesting(std::unique_ptr<base::Clock> clock) {
  clock_ = std::move(clock);
}

void KerberosMetrics::SendAccountCount(const char* name, int count) {
  metrics_lib_.SendToUMA(kerberos_ + kNumberOfAccounts + name, count, 1,
                         kMaxAccounts, kMaxAccounts + 1);
}

}  // namespace kerberos
