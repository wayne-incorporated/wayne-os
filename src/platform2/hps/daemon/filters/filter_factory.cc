// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "hps/daemon/filters/filter_factory.h"

#include <memory>
#include <utility>

#include <base/logging.h>

#include "hps/daemon/filters/average_filter.h"
#include "hps/daemon/filters/consecutive_results_filter.h"
#include "hps/daemon/filters/filter_watcher.h"
#include "hps/daemon/filters/threshold_filter.h"

namespace hps {

// TODO(slangley): This needs confirming from MI team.
constexpr int kDefaultThreshold = 0;

std::unique_ptr<Filter> CreateFilter(const hps::FeatureConfig& config,
                                     StatusCallback signal) {
  std::unique_ptr<Filter> filter;

  switch (config.filter_config_case()) {
    case FeatureConfig::kBasicFilterConfig:
    case FeatureConfig::FILTER_CONFIG_NOT_SET:
      filter = std::make_unique<ThresholdFilter>(kDefaultThreshold);
      break;
    case FeatureConfig::kConsecutiveResultsFilterConfig:
      filter = std::make_unique<ConsecutiveResultsFilter>(
          config.consecutive_results_filter_config());
      break;
    case FeatureConfig::kAverageFilterConfig:
      filter = std::make_unique<AverageFilter>(config.average_filter_config());
      break;
  }
  return std::make_unique<FilterWatcher>(std::move(filter), std::move(signal),
                                         config.report_raw_results());
}

}  // namespace hps
