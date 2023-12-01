// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef HPS_DAEMON_FILTERS_AVERAGE_FILTER_H_
#define HPS_DAEMON_FILTERS_AVERAGE_FILTER_H_

#include <queue>

#include "hps/daemon/filters/filter.h"
#include "hps/proto_bindings/hps_service.pb.h"

namespace hps {

// A filter that compares the average result from the last n rounds against two
// fixed thresholds.
class AverageFilter : public Filter {
 public:
  explicit AverageFilter(const FeatureConfig::AverageFilterConfig& config);
  AverageFilter(const AverageFilter&) = delete;
  AverageFilter& operator=(const AverageFilter&) = delete;
  ~AverageFilter() override = default;

 private:
  // Metehods for Filter
  HpsResult ProcessResultImpl(int result, bool valid) override;

  std::queue<int> last_n_results_;
  int sum_result_ = 0;
  const FeatureConfig::AverageFilterConfig config_;
};

}  // namespace hps

#endif  // HPS_DAEMON_FILTERS_AVERAGE_FILTER_H_
