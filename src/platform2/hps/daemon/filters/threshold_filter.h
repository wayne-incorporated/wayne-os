// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef HPS_DAEMON_FILTERS_THRESHOLD_FILTER_H_
#define HPS_DAEMON_FILTERS_THRESHOLD_FILTER_H_

#include <memory>

#include "base/functional/callback.h"
#include "hps/daemon/filters/filter.h"

namespace hps {

// A filter that compares the inference result against a fixed threshold.
class ThresholdFilter : public Filter {
 public:
  explicit ThresholdFilter(int threshold);
  ThresholdFilter(const ThresholdFilter&) = delete;
  ThresholdFilter& operator=(const ThresholdFilter&) = delete;
  ~ThresholdFilter() override = default;

 private:
  // Metehods for Filter
  HpsResult ProcessResultImpl(int result, bool valid) override;

  const int threshold_;
};

}  // namespace hps

#endif  // HPS_DAEMON_FILTERS_THRESHOLD_FILTER_H_
