// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <utility>
#include <vector>

#include "hps/daemon/filters/filter_watcher.h"

namespace hps {

FilterWatcher::FilterWatcher(std::unique_ptr<Filter> wrapped_filter,
                             StatusCallback signal,
                             bool passthrough_mode)
    : wrapped_filter_(std::move(wrapped_filter)),
      status_changed_callback_(std::move(signal)),
      passthrough_mode_(passthrough_mode) {}

HpsResult FilterWatcher::ProcessResultImpl(int result, bool valid) {
  auto previous_filter_result = wrapped_filter_->GetCurrentResult();
  auto filter_result = wrapped_filter_->ProcessResult(result, valid);

  if (passthrough_mode_ || filter_result != previous_filter_result) {
    status_changed_callback_.Run(filter_result);
  }

  return filter_result;
}

}  // namespace hps
