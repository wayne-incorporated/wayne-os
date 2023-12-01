// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "kerberos/kerberos_metrics.h"

#include <memory>
#include <utility>

#include <base/check.h>
#include <base/files/scoped_temp_dir.h>
#include <base/test/simple_test_clock.h>
#include <gtest/gtest.h>

namespace kerberos {

class KerberosMetricsTest : public ::testing::Test {
 public:
  KerberosMetricsTest() {
    CHECK(storage_dir_.CreateUniqueTempDir());
    metrics_ = std::make_unique<KerberosMetrics>(storage_dir_.GetPath());

    // Start with a reasonable time. Some systems might not like timestamps from
    // the 17th century.
    auto clock = std::make_unique<base::SimpleTestClock>();
    base::Time time;
    CHECK(base::Time::FromString("1 Jan 2019", &time));
    clock->SetNow(time);
    metrics_->SetClockForTesting(std::move(clock));
  }
  KerberosMetricsTest(const KerberosMetricsTest&) = delete;
  KerberosMetricsTest& operator=(const KerberosMetricsTest&) = delete;

  ~KerberosMetricsTest() override = default;

 protected:
  base::SimpleTestClock* clock() {
    return static_cast<base::SimpleTestClock*>(metrics_->clock());
  }

  base::ScopedTempDir storage_dir_;

  std::unique_ptr<KerberosMetrics> metrics_;
};

// Tests whether ShouldReportDailyUsageStats only triggers once a day and works
// fine with resetting the clock.
TEST_F(KerberosMetricsTest, ShouldReportDailyUsageStats) {
  // At 0d 0h, the first call should always return true.
  EXPECT_TRUE(metrics_->ShouldReportDailyUsageStats());

  // At 0d 0h, another call should return false since a day hasn't passed.
  EXPECT_FALSE(metrics_->ShouldReportDailyUsageStats());

  // At 0d 23h, it should still return false.
  clock()->Advance(base::Hours(23));
  EXPECT_FALSE(metrics_->ShouldReportDailyUsageStats());

  // At 1d 0h, it should return true again.
  clock()->Advance(base::Hours(1));
  EXPECT_TRUE(metrics_->ShouldReportDailyUsageStats());

  // At 4d 0h, it should return true, then false, even though 3 days have
  // passed since the last call (missed days shouldn't accumulate).
  clock()->Advance(base::Hours(72));
  EXPECT_TRUE(metrics_->ShouldReportDailyUsageStats());
  EXPECT_FALSE(metrics_->ShouldReportDailyUsageStats());

  // At 5d 12h, it should return true (1.5 days passed)
  clock()->Advance(base::Hours(36));
  EXPECT_TRUE(metrics_->ShouldReportDailyUsageStats());

  // At 6d 0h, it should return true (shouldn't enforce 24h between 2 true's).
  clock()->Advance(base::Hours(12));
  EXPECT_TRUE(metrics_->ShouldReportDailyUsageStats());

  // Going backwards in time shouldn't throw it off.

  // At 2d 12h, it should return false (going backwards shouldn't trigger).
  clock()->Advance(base::Hours(-84));
  EXPECT_FALSE(metrics_->ShouldReportDailyUsageStats());

  // At 3d 0h, it should (surprisingly at first) still return false.
  clock()->Advance(base::Hours(12));
  EXPECT_FALSE(metrics_->ShouldReportDailyUsageStats());

  // At 3d 23h, still false.
  clock()->Advance(base::Hours(23));
  EXPECT_FALSE(metrics_->ShouldReportDailyUsageStats());

  // At 4d 0h, true again.
  clock()->Advance(base::Hours(1));
  EXPECT_TRUE(metrics_->ShouldReportDailyUsageStats());

  // A new instance should take over the result from the old instance.
  KerberosMetrics new_metrics(storage_dir_.GetPath());
  new_metrics.SetClockForTesting(std::make_unique<base::SimpleTestClock>());
  static_cast<base::SimpleTestClock*>(new_metrics.clock())
      ->SetNow(clock()->Now());
  EXPECT_FALSE(new_metrics.ShouldReportDailyUsageStats());
}

}  // namespace kerberos
