// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "arc_setup_metrics.h"  // NOLINT - TODO(b/32971714): fix it properly.

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <metrics/metrics_library_mock.h>

using ::testing::_;

namespace arc {
namespace {

class ArcSetupMetricsTest : public testing::Test {
 protected:
  ArcSetupMetricsTest() {
    arc_setup_metrics_.SetMetricsLibraryForTesting(
        std::make_unique<MetricsLibraryMock>());
  }
  ArcSetupMetricsTest(const ArcSetupMetricsTest&) = delete;
  ArcSetupMetricsTest& operator=(const ArcSetupMetricsTest&) = delete;

  ~ArcSetupMetricsTest() override = default;

  MetricsLibraryMock* GetMetricsLibraryMock() {
    return static_cast<MetricsLibraryMock*>(
        arc_setup_metrics_.metrics_library_for_testing());
  }

  ArcSetupMetrics arc_setup_metrics_;
};

TEST_F(ArcSetupMetricsTest, SendSdkVersionUpgradeType) {
  EXPECT_CALL(
      *GetMetricsLibraryMock(),
      SendEnumToUMA(_, static_cast<int>(ArcSdkVersionUpgradeType::N_TO_P), _))
      .Times(1);
  arc_setup_metrics_.SendSdkVersionUpgradeType(
      ArcSdkVersionUpgradeType::N_TO_P);
}

}  // namespace
}  // namespace arc
