// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef HPS_DAEMON_FILTERS_FILTER_H_
#define HPS_DAEMON_FILTERS_FILTER_H_

#include <memory>

#include "base/functional/callback.h"
#include "hps/proto_bindings/hps_service.pb.h"

namespace hps {
//
// Filter specifies an interface that can be specialized to provide advanced
// processing of HPS inferencing results.
//
class Filter {
 public:
  Filter() = default;
  explicit Filter(HpsResult initial_state);
  Filter(const Filter&) = delete;
  Filter& operator=(const Filter&) = delete;
  virtual ~Filter() = default;

  // Process an inference result from HPS. Will only be called when there is:
  // - a new inference has been performed.
  // Parameters:
  // - result: the most recent inference result from HPS
  // - valid: whether this inference result is valid.
  // Returns:
  // - HpsResult: the result of the filtered inference. Depending on the
  // filter, implementation this can be a cumulative result.
  HpsResult ProcessResult(int result, bool valid);

  // Returns the current inference result of the filter. This is the same as
  // the last result that was returned from ProcessResult.
  HpsResult GetCurrentResult(void) const;

 protected:
  // Called from ProcessResult, derived filters should implement their filtering
  // logic in this method.
  virtual HpsResult ProcessResultImpl(int result, bool valid) = 0;

 private:
  HpsResult current_result_ = HpsResult::UNKNOWN;
};

}  // namespace hps

#endif  // HPS_DAEMON_FILTERS_FILTER_H_
