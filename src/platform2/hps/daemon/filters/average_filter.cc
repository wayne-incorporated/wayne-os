// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "hps/daemon/filters/average_filter.h"

namespace hps {

AverageFilter::AverageFilter(const FeatureConfig::AverageFilterConfig& config)
    : config_(config) {}

HpsResult AverageFilter::ProcessResultImpl(int result, bool valid) {
  // If invalid, use the default value instead of the provided value.
  if (!valid) {
    result = config_.default_uncertain_score();
  }
  // Pop first element if there is already `average_window_size` results in the
  // queue.
  if (static_cast<int32_t>(last_n_results_.size()) ==
      config_.average_window_size()) {
    sum_result_ -= last_n_results_.front();
    last_n_results_.pop();
  }

  // Add new result in the queue.
  sum_result_ += result;
  last_n_results_.push(result);

  // Get the average.
  int average = sum_result_ / static_cast<int>(last_n_results_.size());

  // Compare the average with two thresholds.
  if (average >= config_.positive_score_threshold()) {
    return HpsResult::POSITIVE;
  } else if (average < config_.negative_score_threshold()) {
    return HpsResult::NEGATIVE;
  }

  return HpsResult::UNKNOWN;
}

}  // namespace hps
