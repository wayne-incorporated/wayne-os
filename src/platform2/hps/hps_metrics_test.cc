// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <vector>

#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/test/task_environment.h>
#include <base/test/scoped_chromeos_version_info.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <metrics/metrics_library_mock.h>

#include "hps/hps_metrics.h"

using ::testing::_;
using ::testing::Ge;
using ::testing::Le;

namespace hps {

const char kLsbRelease[] =
    "CHROMEOS_RELEASE_NAME=Chrome OS\n"
    "CHROMEOS_RELEASE_VERSION=1.2.3.4\n"
    "CHROMEOS_RELEASE_TRACK=testimage-channel\n";

class HpsMetricsTest : public testing::Test {
 protected:
  HpsMetricsTest() {}
  void SetUp() override {
    ASSERT_TRUE(temp_dir.CreateUniqueTempDir());
    const base::FilePath cumulative_metric_path =
        temp_dir.GetPath().Append("cumulative");
    ASSERT_TRUE(base::CreateDirectory(cumulative_metric_path));
    hps_metrics_ = std::make_unique<HpsMetrics>(cumulative_metric_path);
    hps_metrics_->SetMetricsLibraryForTesting(
        std::make_unique<MetricsLibraryMock>());
  }
  HpsMetricsTest(const HpsMetricsTest&) = delete;
  HpsMetricsTest& operator=(const HpsMetricsTest&) = delete;

  ~HpsMetricsTest() override = default;

  MetricsLibraryMock* GetMetricsLibraryMock() {
    return static_cast<MetricsLibraryMock*>(
        hps_metrics_->metrics_library_for_testing());
  }
  base::test::ScopedChromeOSVersionInfo version{kLsbRelease, base::Time()};
  base::test::SingleThreadTaskEnvironment task_environment_{
      base::test::TaskEnvironment::TimeSource::MOCK_TIME};
  base::ScopedTempDir temp_dir;
  std::unique_ptr<HpsMetrics> hps_metrics_;
};

TEST_F(HpsMetricsTest, SendHpsTurnOnResult) {
  std::vector<HpsTurnOnResult> all_results = {
      HpsTurnOnResult::kSuccess,
      HpsTurnOnResult::kMcuVersionMismatch,
      HpsTurnOnResult::kSpiNotVerified,
      HpsTurnOnResult::kMcuNotVerified,
      HpsTurnOnResult::kStage1NotStarted,
      HpsTurnOnResult::kApplNotStarted,
      HpsTurnOnResult::kNoResponse,
      HpsTurnOnResult::kTimeout,
      HpsTurnOnResult::kBadMagic,
      HpsTurnOnResult::kFault,
      HpsTurnOnResult::kMcuUpdateFailure,
      HpsTurnOnResult::kSpiUpdateFailure,
      HpsTurnOnResult::kMcuUpdatedThenFailed,
      HpsTurnOnResult::kSpiUpdatedThenFailed,
      HpsTurnOnResult::kPowerOnRecoverySucceeded,
      HpsTurnOnResult::kPowerOnRecoveryFailed,
  };
  // Check that we have all the values of the enum
  ASSERT_EQ(all_results.size(),
            static_cast<int>(HpsTurnOnResult::kMaxValue) + 1);

  constexpr int kDuration = 49;
  for (auto result : all_results) {
    switch (result) {
      case HpsTurnOnResult::kSuccess:
        EXPECT_CALL(*GetMetricsLibraryMock(),
                    SendToUMA(kHpsBootSuccessDuration, kDuration, _, _, _))
            .Times(1);
        break;
      case HpsTurnOnResult::kMcuVersionMismatch:
      case HpsTurnOnResult::kSpiNotVerified:
      case HpsTurnOnResult::kMcuNotVerified:
      case HpsTurnOnResult::kPowerOnRecoverySucceeded:
        break;
      case HpsTurnOnResult::kStage1NotStarted:
      case HpsTurnOnResult::kApplNotStarted:
      case HpsTurnOnResult::kNoResponse:
      case HpsTurnOnResult::kTimeout:
      case HpsTurnOnResult::kBadMagic:
      case HpsTurnOnResult::kFault:
      case HpsTurnOnResult::kMcuUpdateFailure:
      case HpsTurnOnResult::kSpiUpdateFailure:
      case HpsTurnOnResult::kMcuUpdatedThenFailed:
      case HpsTurnOnResult::kSpiUpdatedThenFailed:
      case HpsTurnOnResult::kPowerOnRecoveryFailed:
        EXPECT_CALL(*GetMetricsLibraryMock(),
                    SendToUMA(kHpsBootFailedDuration, kDuration, _, _, _))
            .Times(1);
        break;
    }
    EXPECT_CALL(*GetMetricsLibraryMock(),
                SendEnumToUMA(kHpsTurnOnResult, static_cast<int>(result), _))
        .Times(1);
    hps_metrics_->SendHpsTurnOnResult(result, base::Milliseconds(kDuration));
  }
}

// Without a SendImageValidity call, no metric is sent
TEST_F(HpsMetricsTest, ValidityNopTest) {
  task_environment_.FastForwardBy(kAccumulatePeriod);
}

// Test with 50% valid images
TEST_F(HpsMetricsTest, ValidityTest) {
  for (int i = 0; i < 15; ++i) {
    hps_metrics_->SendImageValidity(true);
    hps_metrics_->SendImageValidity(false);
  }
  EXPECT_CALL(*GetMetricsLibraryMock(),
              SendToUMA(kHpsImageInvalidity, 500, _, _, _))
      .Times(1);
  task_environment_.FastForwardBy(kAccumulatePeriod);
}

// Test with 1 invalid image
// We want the output to be one, not 0.
TEST_F(HpsMetricsTest, ValidityOneTest) {
  hps_metrics_->SendImageValidity(false);
  for (int i = 0; i < 1000; ++i) {
    hps_metrics_->SendImageValidity(true);
  }
  EXPECT_CALL(*GetMetricsLibraryMock(),
              SendToUMA(kHpsImageInvalidity, 1, _, _, _))
      .Times(1);
  task_environment_.FastForwardBy(kAccumulatePeriod);
}

}  // namespace hps
