// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "kerberos/tgt_renewal_scheduler.h"

#include <string>

#include <base/logging.h>
#include <base/memory/ref_counted.h>
#include <base/test/test_mock_time_task_runner.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "kerberos/krb5_interface.h"
#include "kerberos/proto_bindings/kerberos_service.pb.h"

using testing::_;
using testing::DoAll;
using testing::Mock;
using testing::Return;
using testing::SetArgPointee;

namespace kerberos {
namespace {

constexpr char kPrincipal[] = "user@EXAMPLE.COM";

// TgtStatus(validity_seconds, renewal_seconds)
constexpr Krb5Interface::TgtStatus kDefaultTgtStatus;
constexpr Krb5Interface::TgtStatus kExpiredTgtStatus(0, 0);
constexpr Krb5Interface::TgtStatus kAboutToExpireTgtStatus(
    TgtRenewalScheduler::kExpirationHeadsUpTimeSeconds, 7200);
constexpr Krb5Interface::TgtStatus kNotRenewableTgtStatus(3600, 0);
constexpr Krb5Interface::TgtStatus kValidTgtStatus(3600, 7200);

class MockTgtRenewalSchedulerDelegate : public TgtRenewalScheduler::Delegate {
 public:
  MockTgtRenewalSchedulerDelegate() = default;
  MockTgtRenewalSchedulerDelegate(const MockTgtRenewalSchedulerDelegate&) =
      delete;
  MockTgtRenewalSchedulerDelegate& operator=(
      const MockTgtRenewalSchedulerDelegate&) = delete;

  ~MockTgtRenewalSchedulerDelegate() override = default;

  MOCK_METHOD(ErrorType,
              GetTgtStatus,
              (const std::string&, Krb5Interface::TgtStatus*),
              (override));
  MOCK_METHOD(ErrorType, RenewTgt, (const std::string&), (override));
  MOCK_METHOD(void,
              NotifyTgtExpiration,
              (const std::string&, TgtRenewalScheduler::TgtExpiration),
              (override));
};

}  // namespace

class TgtRenewalSchedulerTest : public ::testing::Test {
 public:
  TgtRenewalSchedulerTest() : scheduler_(kPrincipal, &scheduler_delegate_) {}
  TgtRenewalSchedulerTest(const TgtRenewalSchedulerTest&) = delete;
  TgtRenewalSchedulerTest& operator=(const TgtRenewalSchedulerTest&) = delete;

  ~TgtRenewalSchedulerTest() override = default;

 protected:
  // Expects a call to |scheduler_delegate_.GetTgtStatus()|, returns
  // |returned_error| and sets tgt_status to |returned_tgt_status|.
  void ExpectGetTgtStatus(ErrorType returned_error,
                          const Krb5Interface::TgtStatus& returned_tgt_status) {
    EXPECT_CALL(scheduler_delegate_, GetTgtStatus(kPrincipal, _))
        .WillOnce(DoAll(SetArgPointee<1>(returned_tgt_status),
                        Return(returned_error)));
  }

  // Expects a call to |scheduler_delegate_.RenewTgt()| and returns
  // |returned_error|.
  void ExpectRenewTgt(ErrorType returned_error) {
    EXPECT_CALL(scheduler_delegate_, RenewTgt(kPrincipal))
        .WillOnce(Return(returned_error));
  }

  // Expects a call to |scheduler_delegate_.ExpectNotifyTgtExpiration()| with
  // given |expected_expiration|.
  void ExpectNotifyTgtExpiration(
      TgtRenewalScheduler::TgtExpiration expected_expiration) {
    EXPECT_CALL(scheduler_delegate_,
                NotifyTgtExpiration(kPrincipal, expected_expiration));
  }

  testing::StrictMock<MockTgtRenewalSchedulerDelegate> scheduler_delegate_;
  TgtRenewalScheduler scheduler_;

  scoped_refptr<base::TestMockTimeTaskRunner> task_runner_{
      new base::TestMockTimeTaskRunner()};
  base::TestMockTimeTaskRunner::ScopedContext scoped_context_{task_runner_};
};

// If GetTgtStatus() returns an error, there should be an expiry notification.
TEST_F(TgtRenewalSchedulerTest, GetTgtStatusErrorTriggersNotify) {
  ExpectGetTgtStatus(ERROR_UNKNOWN, kDefaultTgtStatus);
  ExpectNotifyTgtExpiration(TgtRenewalScheduler::TgtExpiration::kExpired);
  scheduler_.ScheduleRenewal(true /* notify_expiration */);
}

// If the TGT is expired, there should be an expiry notification.
TEST_F(TgtRenewalSchedulerTest, ExpiredTgtTriggersNotify) {
  ExpectGetTgtStatus(ERROR_NONE, kExpiredTgtStatus);
  ExpectNotifyTgtExpiration(TgtRenewalScheduler::TgtExpiration::kExpired);
  scheduler_.ScheduleRenewal(true /* notify_expiration */);
}

// If the TGT is about to expire, there should be an about-to-expire
// notification.
TEST_F(TgtRenewalSchedulerTest, AboutToExpiredTgtTriggersNotify) {
  ExpectGetTgtStatus(ERROR_NONE, kAboutToExpireTgtStatus);
  ExpectNotifyTgtExpiration(TgtRenewalScheduler::TgtExpiration::kAboutToExpire);
  scheduler_.ScheduleRenewal(true /* notify_expiration */);
}

// A valid TGT schedules a renewal task, even if the ticket is not renewable.
TEST_F(TgtRenewalSchedulerTest, NotRenewableTgtSchedulesTask) {
  ExpectGetTgtStatus(ERROR_NONE, kNotRenewableTgtStatus);
  scheduler_.ScheduleRenewal(true /* notify_expiration */);
  EXPECT_EQ(1, task_runner_->GetPendingTaskCount());
}

// A valid TGT schedules a series of renewal tasks until the lifetime drops
// below a threshold, where an about-to-expire notification is triggered.
TEST_F(TgtRenewalSchedulerTest, ValidTgtTriggersRescheduleAtSpecificDelays) {
  // Trigger initial reschedule with a valid TGT.
  Krb5Interface::TgtStatus tgt_status = kValidTgtStatus;
  ExpectGetTgtStatus(ERROR_NONE, tgt_status);
  scheduler_.ScheduleRenewal(true /* notify_expiration */);

  // To make sure there's not an excessive number of scheduled tasks.
  // Note: Currently, the sequence of delays is 2160s, 864s, 345s and 138s.
  constexpr int kHugelyExcessiveNumber = 10;

  // This should trigger a series of renewals with geometrically decreasing
  // delays until the heads up delay for expiring TGTs is hit.
  int count = 0;
  while (tgt_status.validity_seconds >
         TgtRenewalScheduler::kExpirationHeadsUpTimeSeconds) {
    EXPECT_GT(kHugelyExcessiveNumber, ++count);

    base::TimeDelta expected_delay = base::Seconds(static_cast<int>(
        tgt_status.validity_seconds *
        TgtRenewalScheduler::kTgtRenewValidityLifetimeFraction));

    LOG(INFO) << "Expecting delay of " << expected_delay;

    EXPECT_EQ(1, task_runner_->GetPendingTaskCount());
    EXPECT_EQ(expected_delay, task_runner_->NextPendingTaskDelay());
    ExpectRenewTgt(ERROR_NONE);

    // Simulate life time decay.
    tgt_status.validity_seconds -= expected_delay.InSeconds();
    ExpectGetTgtStatus(ERROR_NONE, tgt_status);

    // If the ticket lifetime drops below a threshold, there should be a
    // notification.
    if (tgt_status.validity_seconds <=
        TgtRenewalScheduler::kExpirationHeadsUpTimeSeconds) {
      ExpectNotifyTgtExpiration(
          TgtRenewalScheduler::TgtExpiration::kAboutToExpire);
    }

    task_runner_->FastForwardBy(expected_delay);
    Mock::VerifyAndClearExpectations(&scheduler_delegate_);
  }

  // The expiry notification ends the series of scheduled tasks.
  EXPECT_EQ(0, task_runner_->GetPendingTaskCount());
}

// Rescheduling in the middle of a task delay should reset the task delay.
TEST_F(TgtRenewalSchedulerTest, Reschedule) {
  ExpectGetTgtStatus(ERROR_NONE, kValidTgtStatus);
  scheduler_.ScheduleRenewal(true /* notify_expiration */);
  EXPECT_EQ(1, task_runner_->GetPendingTaskCount());
  Mock::VerifyAndClearExpectations(&scheduler_delegate_);

  // Wait for half of the task delay.
  const base::TimeDelta delay = task_runner_->NextPendingTaskDelay();
  task_runner_->FastForwardBy(delay / 2);

  ExpectGetTgtStatus(ERROR_NONE, kValidTgtStatus);
  scheduler_.ScheduleRenewal(true /* notify_expiration */);

  // Canceled pending tasks are pruned in TestMockTimeTaskRunner.
  EXPECT_EQ(1, task_runner_->GetPendingTaskCount());
  EXPECT_EQ(delay, task_runner_->NextPendingTaskDelay());

  // Fast forward to a time after the first callback and before the second.
  // This should NOT trigger RenewTgt() since the callback should have been
  // canceled.
  task_runner_->FastForwardBy(delay * 2 / 3);
  Mock::VerifyAndClearExpectations(&scheduler_delegate_);
  EXPECT_EQ(1, task_runner_->GetPendingTaskCount());
  EXPECT_EQ(delay / 3, task_runner_->NextPendingTaskDelay());

  // Fast forward after the second callback.
  ExpectRenewTgt(ERROR_NONE);
  ExpectGetTgtStatus(ERROR_NONE, kValidTgtStatus);
  task_runner_->FastForwardBy(delay);
}

}  // namespace kerberos
