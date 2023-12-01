// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "mist/metrics.h"

#include <base/logging.h>

namespace mist {

namespace {

enum SwitchResult {
  kSwitchResultSuccess,
  kSwitchResultFailure,
  kSwitchResultMaxValue
};

}  // namespace

Metrics::Metrics() {}

void Metrics::RecordSwitchResult(bool success) {
  if (!metrics_library_.SendEnumToUMA(
          "Mist.SwitchResult",
          success ? kSwitchResultSuccess : kSwitchResultFailure,
          kSwitchResultMaxValue))
    LOG(WARNING) << "Could not send switch result sample to UMA.";
}

}  // namespace mist
