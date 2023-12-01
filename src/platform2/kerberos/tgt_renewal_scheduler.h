// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef KERBEROS_TGT_RENEWAL_SCHEDULER_H_
#define KERBEROS_TGT_RENEWAL_SCHEDULER_H_

#include <string>

#include <base/cancelable_callback.h>
#include <base/files/file_path.h>

#include "kerberos/krb5_interface.h"
#include "kerberos/proto_bindings/kerberos_service.pb.h"

namespace kerberos {

// Schedules tasks for automatic Kerberos ticket-granting-ticket (TGT) renewal.
// If the ticket lifetime is 10 hours, schedules calls to delegate_->RenewTgt()
// after, 6h 0m, 8h 24m, 9h 21m, 9h 44m, 9h 53m and 9h 57m.
//
// After that, the class calls delegate_->NotifyTgtExpiration() with
// TgtExpiration::kAboutToExpire. If the device was turned off and the scheduled
// tasks could not be run and the ticket is already expired, calls
// delegate_->NotifyTgtExpiration() with TgtExpiration::kExpired.
class TgtRenewalScheduler {
 public:
  enum class TgtExpiration { kExpired, kAboutToExpire };

  // Exposed for testing.

  // If a TGT is about to expire in less than this interval, notify Chrome about
  // the expiration.
  static constexpr int kExpirationHeadsUpTimeSeconds = 180;
  static_assert(kExpirationHeadsUpTimeSeconds > 0, "");

  // Fraction of the TGT validity lifetime to schedule automatic TGT renewal.
  // For instance, if the TGT is valid for another 1000 seconds and the factor
  // is 0.8, the TGT would be renewed after 800 seconds. Must be strictly
  // between 0 and 1.
  static constexpr float kTgtRenewValidityLifetimeFraction = 0.6f;
  static_assert(kTgtRenewValidityLifetimeFraction > 0.0f, "");
  static_assert(kTgtRenewValidityLifetimeFraction < 1.0f, "");

  class Delegate {
   public:
    virtual ~Delegate() = default;

    // Called by ScheduleRenewal() to query the lifetime of the TGT.
    virtual ErrorType GetTgtStatus(const std::string& principal_name,
                                   Krb5Interface::TgtStatus* tgt_status) = 0;

    // Called by RunScheduledTgtRenewal(). Should try to renew the ticket for
    // |principal_name|.
    virtual ErrorType RenewTgt(const std::string& principal_name) = 0;

    // Called when the TGT is expired or about to expire.
    virtual void NotifyTgtExpiration(const std::string& principal_name,
                                     TgtExpiration expiration) = 0;
  };

  TgtRenewalScheduler(const std::string& principal_name, Delegate* delegate);
  TgtRenewalScheduler(const TgtRenewalScheduler&) = delete;
  TgtRenewalScheduler& operator=(const TgtRenewalScheduler&) = delete;

  // If the ticket is valid and not about to expire soon, schedules
  // RunScheduledTgtRenewal() with a delay of a fraction of the TGT's remaining
  // lifetime. Otherwise, calls delegate_->NotifyTgtExpiration() if
  // |notify_expiration| is true.
  void ScheduleRenewal(bool notify_expiration);

 private:
  // Callback scheduled to renew the TGT. Calls |delegate_->RenewTgt()| and
  // reschedules.
  void RunScheduledTgtRenewal();

  // User principal name (user@EXAMPLE.COM) that corresponds to the TGT.
  const std::string principal_name_;

  // Delegate for TGT renewal and expiry notification. Not owned.
  Delegate* const delegate_;

  // Callback for scheduled renewal tasks.
  base::CancelableOnceClosure tgt_renewal_callback_;
};

}  // namespace kerberos

#endif  // KERBEROS_TGT_RENEWAL_SCHEDULER_H_
