// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "hps/daemon/filters/threshold_filter.h"

namespace hps {

ThresholdFilter::ThresholdFilter(int threshold) : threshold_(threshold) {}

HpsResult ThresholdFilter::ProcessResultImpl(int result, bool valid) {
  if (!valid) {
    return HpsResult::UNKNOWN;
  }

  return result > threshold_ ? HpsResult::POSITIVE : HpsResult::NEGATIVE;
}

}  // namespace hps
