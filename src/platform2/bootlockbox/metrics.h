// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BOOTLOCKBOX_METRICS_H_
#define BOOTLOCKBOX_METRICS_H_

#include <metrics/metrics_library.h>

namespace bootlockbox {

// The status of the the bootlockbox space.
enum class SpaceAvailability {
  // Can read & write.
  kAvailable = 0,
  // Can read.
  kWriteLocked = 1,
  // Need a power wash to make it available.
  kNeedPowerWash = 2,
  // Unknown status.
  kUnknown = 3,
  kMaxValue = kUnknown,
};

// This class provides wrapping functions for callers to report DA-related
// metrics without bothering to know all the constant declarations.
class Metrics : private MetricsLibrary {
 public:
  Metrics() = default;
  Metrics(const Metrics&) = delete;
  Metrics& operator=(const Metrics&) = delete;

  virtual ~Metrics() = default;

  virtual void ReportSpaceAvailabilityAtStart(SpaceAvailability status);

 private:
  MetricsLibraryInterface* metrics_library_{this};
};

}  // namespace bootlockbox

#endif  // BOOTLOCKBOX_METRICS_H_
