// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <utility>
#include <vector>

#include "base/test/bind.h"
#include "gtest/gtest.h"
#include "hps/daemon/filters/average_filter.h"
#include "hps/daemon/filters/consecutive_results_filter.h"
#include "hps/daemon/filters/filter.h"
#include "hps/daemon/filters/filter_factory.h"
#include "hps/daemon/filters/filter_watcher.h"
#include "hps/daemon/filters/threshold_filter.h"
#include "hps/proto_bindings/hps_service.pb.h"

namespace hps {
namespace {

constexpr int kThreshold = 5;

}  // namespace

TEST(HpsFilterTest, ThresholdFilterTest) {
  ThresholdFilter filter(kThreshold);

  EXPECT_EQ(filter.ProcessResult(kThreshold - 1, true), HpsResult::NEGATIVE);
  EXPECT_EQ(filter.ProcessResult(kThreshold + 1, true), HpsResult::POSITIVE);
  EXPECT_EQ(filter.ProcessResult(kThreshold + 1, false), HpsResult::UNKNOWN);
}

TEST(HpsFilterTest, FilterWatcherTest) {
  HpsResult cb_result;
  StatusCallback callback =
      base::BindLambdaForTesting([&](HpsResult result) { cb_result = result; });

  auto filter = std::make_unique<ThresholdFilter>(kThreshold);
  FilterWatcher watcher(std::move(filter), callback,
                        /*passthrough_mode=*/false);

  EXPECT_EQ(watcher.ProcessResult(kThreshold - 1, true), HpsResult::NEGATIVE);
  EXPECT_EQ(watcher.ProcessResult(kThreshold + 1, true), HpsResult::POSITIVE);
  EXPECT_EQ(cb_result, HpsResult::POSITIVE);
  EXPECT_EQ(watcher.ProcessResult(kThreshold - 1, true), HpsResult::NEGATIVE);
  EXPECT_EQ(cb_result, HpsResult::NEGATIVE);

  EXPECT_EQ(watcher.ProcessResult(kThreshold - 1, false), HpsResult::UNKNOWN);
  EXPECT_EQ(cb_result, HpsResult::UNKNOWN);
}

TEST(HpsFilterTest, FilterWatcherPassthroughTest) {
  HpsResult cb_result;
  StatusCallback callback =
      base::BindLambdaForTesting([&](HpsResult result) { cb_result = result; });

  auto filter = std::make_unique<ThresholdFilter>(kThreshold);
  FilterWatcher watcher(std::move(filter), callback, /*passthrough_mode=*/true);

  EXPECT_EQ(watcher.ProcessResult(kThreshold - 1, true), HpsResult::NEGATIVE);
  EXPECT_EQ(watcher.ProcessResult(kThreshold + 1, true), HpsResult::POSITIVE);
  EXPECT_EQ(cb_result, HpsResult::POSITIVE);
  cb_result = HpsResult::UNKNOWN;
  EXPECT_EQ(watcher.ProcessResult(kThreshold + 1, true), HpsResult::POSITIVE);
  EXPECT_EQ(cb_result, HpsResult::POSITIVE);
}

TEST(HpsFilterTest, ConsecutiveResultsFilterTest) {
  FeatureConfig::ConsecutiveResultsFilterConfig config;

  config.set_positive_score_threshold(10);
  config.set_negative_score_threshold(4);

  config.set_positive_count_threshold(1);
  config.set_negative_count_threshold(2);
  config.set_uncertain_count_threshold(3);

  ConsecutiveResultsFilter filter(config);

  const int positive_score = 10;
  const int negative_score = 3;
  const int uncertain_score = 5;

  // Only need one positive value to change the state.
  EXPECT_EQ(filter.ProcessResult(positive_score, true), HpsResult::POSITIVE);

  // One negative value will not change the state.
  EXPECT_EQ(filter.ProcessResult(negative_score, true), HpsResult::POSITIVE);
  // Two negative values will change the state.
  EXPECT_EQ(filter.ProcessResult(negative_score, true), HpsResult::NEGATIVE);

  // One uncertain value will not change the state.
  EXPECT_EQ(filter.ProcessResult(uncertain_score, true), HpsResult::NEGATIVE);
  // Two uncertain values will not change the state.
  EXPECT_EQ(filter.ProcessResult(uncertain_score, true), HpsResult::NEGATIVE);
  // Three uncertain values will change the state.
  EXPECT_EQ(filter.ProcessResult(uncertain_score, true), HpsResult::UNKNOWN);

  // Only need one positive value to change the state.
  EXPECT_EQ(filter.ProcessResult(positive_score, true), HpsResult::POSITIVE);

  // Alternating between negative_scores and uncertain_scores without reaching
  // count_threshold will not change the state.
  const std::vector<int> scores = {negative_score,  uncertain_score,
                                   uncertain_score, negative_score,
                                   uncertain_score, uncertain_score};
  for (const int score : scores) {
    EXPECT_EQ(filter.ProcessResult(score, true), HpsResult::POSITIVE);
  }

  // This resets the internal consecutive_count_.
  EXPECT_EQ(filter.ProcessResult(positive_score, true), HpsResult::POSITIVE);

  // One uncertain value will not change the state.
  EXPECT_EQ(filter.ProcessResult(uncertain_score, true), HpsResult::POSITIVE);
  // Invalid value is treated as uncertain.
  EXPECT_EQ(filter.ProcessResult(negative_score, false), HpsResult::POSITIVE);
  // Invalid value is treated as uncertain and three uncertain changes the state
  EXPECT_EQ(filter.ProcessResult(negative_score, false), HpsResult::UNKNOWN);
}

TEST(HpsFilterTest, AverageFilter) {
  FeatureConfig::AverageFilterConfig config;
  config.set_average_window_size(3);
  config.set_positive_score_threshold(10);
  config.set_negative_score_threshold(4);
  config.set_default_uncertain_score(8);

  AverageFilter filter(config);

  // Average is 10;
  EXPECT_EQ(filter.ProcessResult(10, true), HpsResult::POSITIVE);
  // Average is 5;
  EXPECT_EQ(filter.ProcessResult(0, true), HpsResult::UNKNOWN);
  // Average is 3;
  EXPECT_EQ(filter.ProcessResult(0, true), HpsResult::NEGATIVE);
  // Average is 5;
  EXPECT_EQ(filter.ProcessResult(15, true), HpsResult::UNKNOWN);
  // Average is 7;
  EXPECT_EQ(filter.ProcessResult(6, true), HpsResult::UNKNOWN);
  // Average is 10;
  EXPECT_EQ(filter.ProcessResult(9, true), HpsResult::POSITIVE);
  // Average is 7, not 12; since default_uncertain_score is used if invalid.
  EXPECT_EQ(filter.ProcessResult(21, false), HpsResult::UNKNOWN);
}

}  // namespace hps
