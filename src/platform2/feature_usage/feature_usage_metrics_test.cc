// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "feature_usage/feature_usage_metrics.h"

#include <base/logging.h>
#include <base/power_monitor/power_monitor.h>
#include <base/power_monitor/power_monitor_device_source.h>
#include <base/run_loop.h>
#include <base/test/task_environment.h>
#include <base/time/clock.h>
#include <base/time/time.h>
#include <gtest/gtest.h>
#include <metrics/metrics_library_mock.h>

namespace feature_usage {

namespace {

const char kTestFeature[] = "TestFeature";
const char kTestMetric[] = "ChromeOS.FeatureUsage.TestFeature";
const char kTestUsetimeMetric[] = "ChromeOS.FeatureUsage.TestFeature.Usetime";
constexpr base::TimeDelta kDefaultUseTime = base::Minutes(10);

}  // namespace

class FeatureUsageMetricsTest : public ::testing::Test,
                                public FeatureUsageMetrics::Delegate {
 public:
  FeatureUsageMetricsTest() {
    if (!base::PowerMonitor::IsInitialized()) {
      base::PowerMonitor::Initialize(
          std::make_unique<base::PowerMonitorDeviceSource>());
    }

    feature_usage_metrics_ = std::make_unique<FeatureUsageMetrics>(
        kTestFeature, this, env_.GetMockClock(), env_.GetMockTickClock());

    feature_usage_metrics_->SetMetricsLibraryForTesting(
        std::make_unique<MetricsLibraryMock>());
  }

  // FeatureUsageMetrics::Delegate:
  bool IsEligible() const override { return is_eligible_; }
  std::optional<bool> IsAccessible() const override { return is_accessible_; }
  bool IsEnabled() const override { return is_enabled_; }

 protected:
  base::test::TaskEnvironment env_{
      base::test::TaskEnvironment::TimeSource::MOCK_TIME};

  bool is_eligible_ = true;
  std::optional<bool> is_accessible_;
  bool is_enabled_ = true;

  MetricsLibraryMock* GetMetricsLibraryMock() {
    return static_cast<MetricsLibraryMock*>(
        feature_usage_metrics_->metrics_library_for_testing());
  }

  std::unique_ptr<FeatureUsageMetrics> feature_usage_metrics_;
};

TEST_F(FeatureUsageMetricsTest, RecordUsageWithSuccess) {
  EXPECT_CALL(
      *GetMetricsLibraryMock(),
      SendEnumToUMA(
          kTestMetric, static_cast<int>(FeatureUsageMetrics::Event::kEligible),
          static_cast<int>(FeatureUsageMetrics::Event::kMaxValue) + 1));
  EXPECT_CALL(
      *GetMetricsLibraryMock(),
      SendEnumToUMA(
          kTestMetric, static_cast<int>(FeatureUsageMetrics::Event::kEnabled),
          static_cast<int>(FeatureUsageMetrics::Event::kMaxValue) + 1));
  EXPECT_CALL(
      *GetMetricsLibraryMock(),
      SendEnumToUMA(
          kTestMetric,
          static_cast<int>(FeatureUsageMetrics::Event::kUsedWithSuccess),
          static_cast<int>(FeatureUsageMetrics::Event::kMaxValue) + 1));
  feature_usage_metrics_->RecordUsage(/*success=*/true);
}

TEST_F(FeatureUsageMetricsTest, RecordUsageWithFailure) {
  EXPECT_CALL(
      *GetMetricsLibraryMock(),
      SendEnumToUMA(
          kTestMetric, static_cast<int>(FeatureUsageMetrics::Event::kEligible),
          static_cast<int>(FeatureUsageMetrics::Event::kMaxValue) + 1));
  EXPECT_CALL(
      *GetMetricsLibraryMock(),
      SendEnumToUMA(
          kTestMetric, static_cast<int>(FeatureUsageMetrics::Event::kEnabled),
          static_cast<int>(FeatureUsageMetrics::Event::kMaxValue) + 1));
  EXPECT_CALL(
      *GetMetricsLibraryMock(),
      SendEnumToUMA(
          kTestMetric,
          static_cast<int>(FeatureUsageMetrics::Event::kUsedWithFailure),
          static_cast<int>(FeatureUsageMetrics::Event::kMaxValue) + 1));
  feature_usage_metrics_->RecordUsage(/*success=*/false);
}

TEST_F(FeatureUsageMetricsTest, RecordUsetime) {
  EXPECT_CALL(
      *GetMetricsLibraryMock(),
      SendEnumToUMA(
          kTestMetric, static_cast<int>(FeatureUsageMetrics::Event::kEligible),
          static_cast<int>(FeatureUsageMetrics::Event::kMaxValue) + 1));
  EXPECT_CALL(
      *GetMetricsLibraryMock(),
      SendEnumToUMA(
          kTestMetric, static_cast<int>(FeatureUsageMetrics::Event::kEnabled),
          static_cast<int>(FeatureUsageMetrics::Event::kMaxValue) + 1));
  EXPECT_CALL(
      *GetMetricsLibraryMock(),
      SendEnumToUMA(
          kTestMetric,
          static_cast<int>(FeatureUsageMetrics::Event::kUsedWithSuccess),
          static_cast<int>(FeatureUsageMetrics::Event::kMaxValue) + 1));
  EXPECT_CALL(*GetMetricsLibraryMock(),
              SendToUMA(kTestUsetimeMetric, kDefaultUseTime.InMilliseconds(),
                        base::Milliseconds(1).InMilliseconds(),
                        base::Hours(1).InMilliseconds(), 100));
  feature_usage_metrics_->RecordUsage(/*success=*/true);
  feature_usage_metrics_->StartSuccessfulUsage();
  env_.FastForwardBy(kDefaultUseTime);
  feature_usage_metrics_->StopSuccessfulUsage();
}

TEST_F(FeatureUsageMetricsTest, RecordLongUsetime) {
  size_t repeated_periods = 4;
  const base::TimeDelta extra_small_use_time = base::Minutes(3);
  EXPECT_CALL(
      *GetMetricsLibraryMock(),
      SendEnumToUMA(
          kTestMetric, static_cast<int>(FeatureUsageMetrics::Event::kEligible),
          static_cast<int>(FeatureUsageMetrics::Event::kMaxValue) + 1))
      .Times(repeated_periods + 1);
  EXPECT_CALL(
      *GetMetricsLibraryMock(),
      SendEnumToUMA(
          kTestMetric, static_cast<int>(FeatureUsageMetrics::Event::kEnabled),
          static_cast<int>(FeatureUsageMetrics::Event::kMaxValue) + 1))
      .Times(repeated_periods + 1);
  EXPECT_CALL(
      *GetMetricsLibraryMock(),
      SendEnumToUMA(
          kTestMetric,
          static_cast<int>(FeatureUsageMetrics::Event::kUsedWithSuccess),
          static_cast<int>(FeatureUsageMetrics::Event::kMaxValue) + 1));
  EXPECT_CALL(*GetMetricsLibraryMock(),
              SendToUMA(kTestUsetimeMetric,
                        FeatureUsageMetrics::kRepeatedInterval.InMilliseconds(),
                        base::Milliseconds(1).InMilliseconds(),
                        base::Hours(1).InMilliseconds(), 100))
      .Times(repeated_periods);
  EXPECT_CALL(
      *GetMetricsLibraryMock(),
      SendToUMA(kTestUsetimeMetric, extra_small_use_time.InMilliseconds(),
                base::Milliseconds(1).InMilliseconds(),
                base::Hours(1).InMilliseconds(), 100));
  const base::TimeDelta use_time =
      FeatureUsageMetrics::kRepeatedInterval * repeated_periods +
      extra_small_use_time;

  feature_usage_metrics_->RecordUsage(/*success=*/true);
  feature_usage_metrics_->StartSuccessfulUsage();
  env_.FastForwardBy(use_time);
  feature_usage_metrics_->StopSuccessfulUsage();
}

TEST_F(FeatureUsageMetricsTest, PeriodicMetricsTest) {
  EXPECT_CALL(
      *GetMetricsLibraryMock(),
      SendEnumToUMA(
          kTestMetric, static_cast<int>(FeatureUsageMetrics::Event::kEligible),
          static_cast<int>(FeatureUsageMetrics::Event::kMaxValue) + 1))
      .Times(2);
  EXPECT_CALL(
      *GetMetricsLibraryMock(),
      SendEnumToUMA(
          kTestMetric, static_cast<int>(FeatureUsageMetrics::Event::kEnabled),
          static_cast<int>(FeatureUsageMetrics::Event::kMaxValue) + 1));

  // Trigger initial periodic metrics report.
  env_.FastForwardBy(FeatureUsageMetrics::kInitialInterval);

  is_enabled_ = false;
  // Trigger repeated periodic metrics report.
  env_.FastForwardBy(FeatureUsageMetrics::kRepeatedInterval);

  is_eligible_ = false;
  // Trigger repeated periodic metrics report.
  env_.FastForwardBy(FeatureUsageMetrics::kRepeatedInterval);
}

TEST_F(FeatureUsageMetricsTest, PeriodicWithAccessibleMetricsTest) {
  EXPECT_CALL(
      *GetMetricsLibraryMock(),
      SendEnumToUMA(
          kTestMetric, static_cast<int>(FeatureUsageMetrics::Event::kEligible),
          static_cast<int>(FeatureUsageMetrics::Event::kMaxValue) + 1))
      .Times(3);
  EXPECT_CALL(*GetMetricsLibraryMock(),
              SendEnumToUMA(
                  kTestMetric,
                  static_cast<int>(FeatureUsageMetrics::Event::kAccessible),
                  static_cast<int>(FeatureUsageMetrics::Event::kMaxValue) + 1))
      .Times(2);
  EXPECT_CALL(
      *GetMetricsLibraryMock(),
      SendEnumToUMA(
          kTestMetric, static_cast<int>(FeatureUsageMetrics::Event::kEnabled),
          static_cast<int>(FeatureUsageMetrics::Event::kMaxValue) + 1));
  is_accessible_ = true;
  // Trigger initial periodic metrics report.
  env_.FastForwardBy(FeatureUsageMetrics::kInitialInterval);

  is_enabled_ = false;
  // Trigger repeated periodic metrics report.
  env_.FastForwardBy(FeatureUsageMetrics::kRepeatedInterval);

  is_accessible_ = false;
  // Trigger repeated periodic metrics report.
  env_.FastForwardBy(FeatureUsageMetrics::kRepeatedInterval);

  is_eligible_ = false;
  // Trigger repeated periodic metrics report.
  env_.FastForwardBy(FeatureUsageMetrics::kRepeatedInterval);
}

TEST_F(FeatureUsageMetricsTest, ReportUseTimeOnShutdown) {
  EXPECT_CALL(
      *GetMetricsLibraryMock(),
      SendEnumToUMA(
          kTestMetric, static_cast<int>(FeatureUsageMetrics::Event::kEligible),
          static_cast<int>(FeatureUsageMetrics::Event::kMaxValue) + 1));
  EXPECT_CALL(
      *GetMetricsLibraryMock(),
      SendEnumToUMA(
          kTestMetric, static_cast<int>(FeatureUsageMetrics::Event::kEnabled),
          static_cast<int>(FeatureUsageMetrics::Event::kMaxValue) + 1));
  EXPECT_CALL(
      *GetMetricsLibraryMock(),
      SendEnumToUMA(
          kTestMetric,
          static_cast<int>(FeatureUsageMetrics::Event::kUsedWithSuccess),
          static_cast<int>(FeatureUsageMetrics::Event::kMaxValue) + 1));
  EXPECT_CALL(*GetMetricsLibraryMock(),
              SendToUMA(kTestUsetimeMetric, kDefaultUseTime.InMilliseconds(),
                        base::Milliseconds(1).InMilliseconds(),
                        base::Hours(1).InMilliseconds(), 100));
  feature_usage_metrics_->RecordUsage(/*success=*/true);
  feature_usage_metrics_->StartSuccessfulUsage();
  env_.FastForwardBy(kDefaultUseTime);
  feature_usage_metrics_.reset();
}

TEST_F(FeatureUsageMetricsTest, ReportPeriodicOnSuspend) {
  EXPECT_CALL(
      *GetMetricsLibraryMock(),
      SendEnumToUMA(
          kTestMetric, static_cast<int>(FeatureUsageMetrics::Event::kEligible),
          static_cast<int>(FeatureUsageMetrics::Event::kMaxValue) + 1));
  EXPECT_CALL(
      *GetMetricsLibraryMock(),
      SendEnumToUMA(
          kTestMetric, static_cast<int>(FeatureUsageMetrics::Event::kEnabled),
          static_cast<int>(FeatureUsageMetrics::Event::kMaxValue) + 1));
  base::PowerMonitorDeviceSource::HandleSystemSuspending();
  base::RunLoop().RunUntilIdle();

  // Undo global changes.
  base::PowerMonitorDeviceSource::HandleSystemResumed();
}

TEST_F(FeatureUsageMetricsTest, ReportUseTimeOnSuspend) {
  EXPECT_CALL(
      *GetMetricsLibraryMock(),
      SendEnumToUMA(
          kTestMetric, static_cast<int>(FeatureUsageMetrics::Event::kEligible),
          static_cast<int>(FeatureUsageMetrics::Event::kMaxValue) + 1))
      .Times(2);
  EXPECT_CALL(
      *GetMetricsLibraryMock(),
      SendEnumToUMA(
          kTestMetric, static_cast<int>(FeatureUsageMetrics::Event::kEnabled),
          static_cast<int>(FeatureUsageMetrics::Event::kMaxValue) + 1))
      .Times(2);
  EXPECT_CALL(
      *GetMetricsLibraryMock(),
      SendEnumToUMA(
          kTestMetric,
          static_cast<int>(FeatureUsageMetrics::Event::kUsedWithSuccess),
          static_cast<int>(FeatureUsageMetrics::Event::kMaxValue) + 1));
  EXPECT_CALL(*GetMetricsLibraryMock(),
              SendToUMA(kTestUsetimeMetric, kDefaultUseTime.InMilliseconds(),
                        base::Milliseconds(1).InMilliseconds(),
                        base::Hours(1).InMilliseconds(), 100));
  EXPECT_CALL(
      *GetMetricsLibraryMock(),
      SendToUMA(kTestUsetimeMetric, 0, base::Milliseconds(1).InMilliseconds(),
                base::Hours(1).InMilliseconds(), 100));
  feature_usage_metrics_->RecordUsage(/*success=*/true);
  feature_usage_metrics_->StartSuccessfulUsage();
  env_.FastForwardBy(kDefaultUseTime);

  base::PowerMonitorDeviceSource::HandleSystemSuspending();
  base::RunLoop().RunUntilIdle();

  // Undo global changes.
  base::PowerMonitorDeviceSource::HandleSystemResumed();
}

TEST_F(FeatureUsageMetricsTest, SuspensionTimeNotReported) {
  EXPECT_CALL(
      *GetMetricsLibraryMock(),
      SendEnumToUMA(
          kTestMetric, static_cast<int>(FeatureUsageMetrics::Event::kEligible),
          static_cast<int>(FeatureUsageMetrics::Event::kMaxValue) + 1))
      .Times(3);
  EXPECT_CALL(
      *GetMetricsLibraryMock(),
      SendEnumToUMA(
          kTestMetric, static_cast<int>(FeatureUsageMetrics::Event::kEnabled),
          static_cast<int>(FeatureUsageMetrics::Event::kMaxValue) + 1))
      .Times(3);
  EXPECT_CALL(
      *GetMetricsLibraryMock(),
      SendEnumToUMA(
          kTestMetric,
          static_cast<int>(FeatureUsageMetrics::Event::kUsedWithSuccess),
          static_cast<int>(FeatureUsageMetrics::Event::kMaxValue) + 1));
  EXPECT_CALL(*GetMetricsLibraryMock(),
              SendToUMA(kTestUsetimeMetric, kDefaultUseTime.InMilliseconds(),
                        base::Milliseconds(1).InMilliseconds(),
                        base::Hours(1).InMilliseconds(), 100));
  EXPECT_CALL(*GetMetricsLibraryMock(),
              SendToUMA(kTestUsetimeMetric,
                        FeatureUsageMetrics::kInitialInterval.InMilliseconds(),
                        base::Milliseconds(1).InMilliseconds(),
                        base::Hours(1).InMilliseconds(), 100));
  EXPECT_CALL(
      *GetMetricsLibraryMock(),
      SendToUMA(kTestUsetimeMetric,
                kDefaultUseTime.InMilliseconds() -
                    FeatureUsageMetrics::kInitialInterval.InMilliseconds(),
                base::Milliseconds(1).InMilliseconds(),
                base::Hours(1).InMilliseconds(), 100));
  feature_usage_metrics_->RecordUsage(/*success=*/true);
  feature_usage_metrics_->StartSuccessfulUsage();
  env_.FastForwardBy(kDefaultUseTime);
  base::PowerMonitorDeviceSource::HandleSystemSuspending();
  base::RunLoop().RunUntilIdle();

  // Time during suspension must not be reported.
  env_.AdvanceClock(FeatureUsageMetrics::kRepeatedInterval * 1.33);

  base::PowerMonitorDeviceSource::HandleSystemResumed();
  base::RunLoop().RunUntilIdle();

  env_.FastForwardBy(kDefaultUseTime);
  feature_usage_metrics_->StopSuccessfulUsage();
}

}  // namespace feature_usage
