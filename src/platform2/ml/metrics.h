// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ML_METRICS_H_
#define ML_METRICS_H_

#include <memory>

#include <base/process/process_metrics.h>
#include <metrics/cumulative_metrics.h>
#include <metrics/metrics_library.h>

namespace ml {

// Performs UMA metrics logging for the ML Service daemon.
// Periodically gathers some process metrics (e.g. memory) and cumulative
// metrics (e.g. peak memory) itself.
// Threading: Create and use on a single sequence.
class Metrics {
 public:
  // These values are persisted to logs. Entries should not be renumbered and
  // numeric values should never be reused.
  // `kMaxValue` must equal to the maximum value in this enum.
  enum class MojoConnectionEvent {
    kBootstrapRequested = 0,
    kBootstrapSucceeded = 1,
    kConnectionClosed = 2,
    kMaxValue = kConnectionClosed
  };

  Metrics();
  Metrics(const Metrics&) = delete;
  Metrics& operator=(const Metrics&) = delete;

  // Starts periodic sampling of process metrics.
  void StartCollectingProcessMetrics();

  // Immediately samples & updates cumulative process metrics (i.e. peak RAM).
  // This does not change how often metrics are reported, but might increase the
  // accuracy of reported metrics.
  // Clients can call this manually in contexts where they know that e.g. memory
  // usage may have just increased, to help capture short-lived spikes that
  // might be missed by periodic sampling.
  void UpdateCumulativeMetricsNow();

  void RecordMojoConnectionEvent(MojoConnectionEvent event);

 private:
  // Fetches process metrics (e.g. RAM) and updates `cumulative_metrics`.
  // If `record_current_metrics` is true, also logs current process metrics.
  void UpdateAndRecordMetrics(
      bool record_current_metrics,
      chromeos_metrics::CumulativeMetrics* cumulative_metrics);

  const std::unique_ptr<base::ProcessMetrics> process_metrics_;

  MetricsLibrary metrics_library_;

  // Accumulator of process metrics (even across restarts).
  std::unique_ptr<chromeos_metrics::CumulativeMetrics> cumulative_metrics_;
};

}  // namespace ml

#endif  // ML_METRICS_H_
