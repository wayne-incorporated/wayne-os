// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DEBUGD_SRC_METRICS_H_
#define DEBUGD_SRC_METRICS_H_

#include <memory>
#include <string>

#include <base/time/time.h>
#include <metrics/metrics_library.h>

namespace debugd {

class Stopwatch {
 public:
  // Initializes an object for recording time metrics and optional reporting to
  // UMA. Records a point in time upon instantiation to keep track of time
  // passed. Receives the metric suffix as an input, which is appended to the
  // constant prefix to create the metric name used for logging and UMA
  // reporting.
  Stopwatch(const std::string& metric_name,
            const bool local_logging,
            const bool report_lap_to_uma);

  // Calculates the time delta between when the object was instantiated and when
  // the destructor is called and reports the duration to UMA.
  ~Stopwatch();

  // Similar to an actual stopwatch, the Lap function takes a snapshot of the
  // elapsed time at the moment the function is called. If local_logging_ is
  // active, this function logs the time, alongside the name of the lap received
  // as an argument. The lap duration will be reported to UMA if
  // report_lap_to_uma is true. The metric name for each task would be:
  // ChromeOS.Debugd.{metric_name}.{subtast_name} where the metrics should have
  // been defined in
  // https://crsrc.org/c/tools/metrics/histograms/metadata/chromeos/histograms.xml.
  void Lap(const std::string& lap_name);

 private:
  friend class StopwatchTest;

  // Send an UMA using |metrics_library_|.;
  void SendToUMA(const std::string& metric_name, base::TimeDelta duration);

  // Log the start time of the stopwatch.
  base::TimeTicks sw_start_;
  // Log the start time of next lap.
  base::TimeTicks lap_start_;
  std::string metric_name_;
  // Dictates whether the lap times are logged locally.
  const bool local_logging_;
  // Dictates whether the elapsed time of each lap is reported to UMA.
  const bool report_lap_to_uma_;
  std::unique_ptr<MetricsLibraryInterface> metrics_library_;
};

}  // namespace debugd

#endif  // DEBUGD_SRC_METRICS_H_
