// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef HPS_DAEMON_FILTERS_CONSECUTIVE_RESULTS_FILTER_H_
#define HPS_DAEMON_FILTERS_CONSECUTIVE_RESULTS_FILTER_H_

#include "hps/daemon/filters/filter.h"
#include "hps/proto_bindings/hps_service.pb.h"

namespace hps {

// A filter that compares the inference result against a fixed threshold.
class ConsecutiveResultsFilter : public Filter {
 public:
  explicit ConsecutiveResultsFilter(
      const FeatureConfig::ConsecutiveResultsFilterConfig& config);
  ConsecutiveResultsFilter(const ConsecutiveResultsFilter&) = delete;
  ConsecutiveResultsFilter& operator=(const ConsecutiveResultsFilter&) = delete;
  ~ConsecutiveResultsFilter() override = default;

 private:
  // Metehods for Filter
  HpsResult ProcessResultImpl(int result, bool valid) override;

  HpsResult consecutive_result_ = HpsResult::UNKNOWN;
  int consecutive_count_ = 0;
  FeatureConfig::ConsecutiveResultsFilterConfig config_;
};

}  // namespace hps

#endif  // HPS_DAEMON_FILTERS_CONSECUTIVE_RESULTS_FILTER_H_
