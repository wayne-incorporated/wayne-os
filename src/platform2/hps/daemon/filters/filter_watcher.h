// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef HPS_DAEMON_FILTERS_FILTER_WATCHER_H_
#define HPS_DAEMON_FILTERS_FILTER_WATCHER_H_

#include <memory>

#include "hps/daemon/filters/filter.h"
#include "hps/daemon/filters/status_callback.h"

namespace hps {

// FilterWatcher will invoke the StatusCallback whenever the composed filter
// changes state. If `passthrough_mode` is enabled, all filter results will be
// reported even if the state remains the same.
class FilterWatcher : public Filter {
 public:
  FilterWatcher(std::unique_ptr<Filter> wrapped_filter,
                StatusCallback signal,
                bool passthrough_mode);
  FilterWatcher(const FilterWatcher&) = delete;
  FilterWatcher& operator=(const FilterWatcher&) = delete;
  ~FilterWatcher() override = default;

 private:
  // Methods for Filter
  HpsResult ProcessResultImpl(int result, bool valid) override;

  std::unique_ptr<Filter> wrapped_filter_;
  StatusCallback status_changed_callback_;
  bool passthrough_mode_ = false;
};

}  // namespace hps

#endif  // HPS_DAEMON_FILTERS_FILTER_WATCHER_H_
