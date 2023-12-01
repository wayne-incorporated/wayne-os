// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "kerberos/tgt_renewal_scheduler.h"

#include <algorithm>

#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/strings/stringprintf.h>
#include <base/task/single_thread_task_runner.h>
#include <base/time/time.h>

#include "bindings/kerberos_containers.pb.h"
#include "kerberos/error_strings.h"
#include "kerberos/krb5_interface.h"

namespace kerberos {
namespace {

// Nice marker for TGT renewal related logs, for easy grepping.
constexpr char kLogHeader[] = "TGT RENEWAL - ";

// Don't try to renew TGTs more often than this interval.
constexpr int kMinTgtRenewDelaySeconds = 60;
static_assert(kMinTgtRenewDelaySeconds > 0, "");

// Formats a time delta in 1h 2m 3s format.
std::string FormatTimeDelta(int64_t delta_seconds) {
  int h = delta_seconds / 3600;
  int m = (delta_seconds / 60) % 60;
  int s = delta_seconds % 60;

  std::string str;
  if (h > 0)
    str += base::StringPrintf("%ih ", h);
  if (h > 0 || m > 0)
    str += base::StringPrintf("%im ", m);
  str += base::StringPrintf("%is", s);
  return str;
}

std::ostream& operator<<(std::ostream& os,
                         const Krb5Interface::TgtStatus& tgt_status) {
  os << "(valid for " << FormatTimeDelta(tgt_status.validity_seconds)
     << ", renewable for " << FormatTimeDelta(tgt_status.renewal_seconds)
     << ")";
  return os;
}

}  // namespace

TgtRenewalScheduler::TgtRenewalScheduler(const std::string& principal_name,
                                         Delegate* delegate)
    : principal_name_(principal_name), delegate_(delegate) {}

void TgtRenewalScheduler::ScheduleRenewal(bool notify_expiration) {
  // Cancel an existing callback if there is any.
  if (!tgt_renewal_callback_.IsCancelled())
    tgt_renewal_callback_.Cancel();

  // If the TGT exists, but it's broken somehow, assume it's invalid.
  Krb5Interface::TgtStatus tgt_status;
  if (delegate_->GetTgtStatus(principal_name_, &tgt_status) != ERROR_NONE) {
    VLOG(1) << kLogHeader << "Failed to get TGT status";
    if (notify_expiration)
      delegate_->NotifyTgtExpiration(principal_name_, TgtExpiration::kExpired);
    return;
  }

  // Is the TGT expired?
  if (tgt_status.validity_seconds <= 0) {
    VLOG(1) << kLogHeader << "TGT about to expire or expired";
    if (notify_expiration)
      delegate_->NotifyTgtExpiration(principal_name_, TgtExpiration::kExpired);
    return;
  }

  // Is the TGT about to expire? At this point we already give up and show a
  // notification in Chrome, so the user can relog.
  if (tgt_status.validity_seconds <= kExpirationHeadsUpTimeSeconds) {
    VLOG(1) << kLogHeader << "TGT about to expire";
    if (notify_expiration)
      delegate_->NotifyTgtExpiration(principal_name_,
                                     TgtExpiration::kAboutToExpire);
    return;
  }

  // Note: Reschedule even if the ticket is not renewable anymore, i.e.
  // if tgt_status.validity_seconds >= tgt_status.renewal_seconds. The account
  // manager might have credentials stored for the account, which allows it to
  // auto-refresh the ticket without user input. If we didn't reschedule, we'd
  // miss the opportunity to auth-refresh the ticket.

  // Trigger the renewal somewhere in the validity lifetime of the TGT.
  int delay_seconds = static_cast<int>(tgt_status.validity_seconds *
                                       kTgtRenewValidityLifetimeFraction);

  // Make sure we don't trigger excessively often in case the renewal
  // fails and we're getting close to the end of the validity lifetime.
  delay_seconds = std::max(delay_seconds, kMinTgtRenewDelaySeconds);

  VLOG(1) << kLogHeader << "Scheduling renewal in "
          << FormatTimeDelta(delay_seconds) << " " << tgt_status;

  tgt_renewal_callback_.Reset(base::BindOnce(
      &TgtRenewalScheduler::RunScheduledTgtRenewal, base::Unretained(this)));
  base::SingleThreadTaskRunner::GetCurrentDefault()->PostDelayedTask(
      FROM_HERE, tgt_renewal_callback_.callback(),
      base::Seconds(delay_seconds));
}

void TgtRenewalScheduler::RunScheduledTgtRenewal() {
  VLOG(1) << kLogHeader << "Running scheduled TGT renewal";

  ErrorType error = delegate_->RenewTgt(principal_name_);

  // No matter if it worked or not, reschedule auto-renewal. We might be offline
  // and want to try again later.
  ScheduleRenewal(true /* notify_expiration */);

  if (error == ERROR_NONE)
    VLOG(1) << kLogHeader << "Succeeded";
  else
    LOG(ERROR) << kLogHeader << "Failed with error " << GetErrorString(error);
}

}  // namespace kerberos
