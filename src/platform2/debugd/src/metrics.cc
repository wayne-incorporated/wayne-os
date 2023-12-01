// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "debugd/src/metrics.h"

#include <memory>
#include <string>

#include <base/logging.h>
#include <base/time/time.h>
#include <metrics/metrics_library.h>

namespace debugd {

namespace {

// Histogram specifications
const char kMetricPrefix[] = "ChromeOS.Debugd.";
const base::TimeDelta kHistogramMin = base::Minutes(0);
const base::TimeDelta kHistogramMax = base::Minutes(2);
const int kNumBuckets = 50;

}  // namespace

Stopwatch::Stopwatch(const std::string& metric_postfix,
                     const bool local_logging,
                     const bool report_lap_to_uma)
    : local_logging_(local_logging), report_lap_to_uma_(report_lap_to_uma) {
  sw_start_ = base::TimeTicks::Now();
  lap_start_ = sw_start_;
  metric_name_ = kMetricPrefix + metric_postfix;
  metrics_library_ = std::make_unique<MetricsLibrary>();
}

void Stopwatch::Lap(const std::string& lap_name) {
  base::TimeTicks lap_end = base::TimeTicks::Now();
  if (local_logging_) {
    // Note, local logging logs the elapsed time starting from the beginning of
    // the stopwatch, not from the start time of the lap.
    base::TimeDelta lap_duration = lap_end - sw_start_;
    DLOG(INFO) << metric_name_ << ", " << lap_name << ": " << lap_duration;
  }

  if (report_lap_to_uma_) {
    SendToUMA(metric_name_ + "." + lap_name, lap_end - lap_start_);
  }
  lap_start_ = lap_end;
}

void Stopwatch::SendToUMA(const std::string& metric_name,
                          base::TimeDelta duration) {
  metrics_library_->SendToUMA(metric_name, duration.InMilliseconds(),
                              kHistogramMin.InMilliseconds(),
                              kHistogramMax.InMilliseconds(), kNumBuckets);
}

Stopwatch::~Stopwatch() {
  base::TimeDelta duration = base::TimeTicks::Now() - sw_start_;
  if (local_logging_)
    DLOG(INFO) << metric_name_ << ", total elapsed time: " << duration;
  // The total elapsed time is always reported to UMA.
  SendToUMA(metric_name_, duration);
}

}  // namespace debugd
