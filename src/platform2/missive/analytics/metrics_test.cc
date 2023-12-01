// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "missive/analytics/metrics.h"

#include <base/test/task_environment.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "missive/analytics/metrics_test_util.h"

namespace reporting::analytics {

class MetricsTest : public ::testing::Test {
 protected:
  base::test::TaskEnvironment task_environment_;
  Metrics::TestEnvironment metrics_test_environment_;
};

TEST_F(MetricsTest, SendToUMA) {
  static constexpr const char* kName = "test";
  static constexpr int sample = 10;
  static constexpr int min = 0;
  static constexpr int max = 20;
  static constexpr int nbuckets = 50;
  EXPECT_CALL(Metrics::TestEnvironment::GetMockMetricsLibrary(),
              SendToUMA(kName, sample, min, max, nbuckets))
      .Times(1);
  Metrics::SendToUMA(kName, sample, min, max, nbuckets);
  task_environment_.RunUntilIdle();
}

TEST_F(MetricsTest, SendBoolToUMA) {
  static constexpr const char* kName = "test";
  static constexpr bool sample = true;
  EXPECT_CALL(Metrics::TestEnvironment::GetMockMetricsLibrary(),
              SendBoolToUMA(kName, sample))
      .Times(1);
  Metrics::SendBoolToUMA(kName, sample);
  task_environment_.RunUntilIdle();
}

TEST_F(MetricsTest, SendSparseToUMA) {
  static constexpr const char* kName = "test";
  static constexpr int sample = 12345;
  EXPECT_CALL(Metrics::TestEnvironment::GetMockMetricsLibrary(),
              SendSparseToUMA(kName, sample))
      .Times(1);
  Metrics::SendSparseToUMA(kName, sample);
  task_environment_.RunUntilIdle();
}

TEST_F(MetricsTest, SendEnumToUMA) {
  enum Test {
    Unknown = 0,
    Innermost,
    Inner,
    Outer,
    Outermost,
  };
  static constexpr const char* kName = "test";
  static constexpr Test sample = Test::Inner;
  static constexpr int kExclusiveMax = static_cast<int>(Test::Outermost) + 1;
  EXPECT_CALL(Metrics::TestEnvironment::GetMockMetricsLibrary(),
              SendEnumToUMA(kName, static_cast<int>(sample), kExclusiveMax))
      .Times(1);
  Metrics::SendEnumToUMA(kName, static_cast<int>(sample), kExclusiveMax);
  task_environment_.RunUntilIdle();
}

TEST_F(MetricsTest, SendEnumToUMAEnumVariant) {
  enum class Test {
    Unknown = 0,
    Innermost,
    Inner,
    Outer,
    Outermost,
    kMaxValue
  };
  static constexpr const char* kName = "test";
  static constexpr Test sample = Test::Inner;
  EXPECT_CALL(Metrics::TestEnvironment::GetMockMetricsLibrary(),
              SendEnumToUMA(kName, static_cast<int>(sample),
                            static_cast<int>(Test::kMaxValue)))
      .Times(1);
  Metrics::SendEnumToUMA(kName, sample);
  task_environment_.RunUntilIdle();
}

TEST_F(MetricsTest, SendLinearToUMA) {
  static constexpr const char* kName = "test";
  static constexpr int sample = 30;
  static constexpr int max = 50;
  EXPECT_CALL(Metrics::TestEnvironment::GetMockMetricsLibrary(),
              SendLinearToUMA(kName, sample, max))
      .Times(1);
  Metrics::SendLinearToUMA(kName, sample, max);
  task_environment_.RunUntilIdle();
}

TEST_F(MetricsTest, SendPercentageToUMA) {
  static constexpr const char* kName = "test";
  static constexpr int sample = 30;
  EXPECT_CALL(Metrics::TestEnvironment::GetMockMetricsLibrary(),
              SendPercentageToUMA(kName, sample))
      .Times(1);
  Metrics::SendPercentageToUMA(kName, sample);
  task_environment_.RunUntilIdle();
}
}  // namespace reporting::analytics
