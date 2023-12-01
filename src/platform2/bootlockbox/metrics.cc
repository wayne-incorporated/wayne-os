// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "bootlockbox/metrics.h"

namespace bootlockbox {

namespace {

// Record the SpaceAvailability when bootlockbox started.
constexpr char kAvailabilityAtStart[] =
    "Platform.Bootlockbox.AvailabilityAtStart";

}  // namespace

void Metrics::ReportSpaceAvailabilityAtStart(SpaceAvailability result) {
  metrics_library_->SendEnumToUMA(kAvailabilityAtStart, result);
}

}  // namespace bootlockbox
