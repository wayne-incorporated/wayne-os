// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "hps/daemon/filters/consecutive_results_filter.h"

namespace hps {

ConsecutiveResultsFilter::ConsecutiveResultsFilter(
    const FeatureConfig::ConsecutiveResultsFilterConfig& config)
    : config_(config) {}

HpsResult ConsecutiveResultsFilter::ProcessResultImpl(int result, bool valid) {
  HpsResult inference_result = HpsResult::UNKNOWN;
  if (valid && result >= config_.positive_score_threshold()) {
    // If result is valid and above the positive threshold, then
    // inference_result
    // is positive.
    inference_result = HpsResult::POSITIVE;
  } else if (valid && result < config_.negative_score_threshold()) {
    // If result is valid and below the negative threshold, then
    // inference_result
    // is positive.
    inference_result = HpsResult::NEGATIVE;
  }

  // If current inference_result is the same as consecutive_result_; then
  // increment the counter; otherwise restart the counter.
  if (inference_result == consecutive_result_) {
    consecutive_count_++;
  } else {
    consecutive_result_ = inference_result;
    consecutive_count_ = 1;
  }

  // Compare consecutive_count_ with each of the count_threshold.
  if (consecutive_result_ == HpsResult::POSITIVE &&
      consecutive_count_ >= config_.positive_count_threshold()) {
    return HpsResult::POSITIVE;
  } else if (consecutive_result_ == HpsResult::NEGATIVE &&
             consecutive_count_ >= config_.negative_count_threshold()) {
    return HpsResult::NEGATIVE;
  } else if (consecutive_result_ == HpsResult::UNKNOWN &&
             consecutive_count_ >= config_.uncertain_count_threshold()) {
    return HpsResult::UNKNOWN;
  }

  return GetCurrentResult();
}

}  // namespace hps
