// Copyright 2016 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LOGIN_MANAGER_CUMULATIVE_USE_TIME_METRIC_H_
#define LOGIN_MANAGER_CUMULATIVE_USE_TIME_METRIC_H_

#include <stdint.h>

#include <memory>
#include <string>

#include <base/files/file_path.h>
#include <base/memory/weak_ptr.h>
#include <base/time/clock.h>
#include <base/time/tick_clock.h>
#include <base/time/time.h>
#include <base/timer/timer.h>

class MetricsLibraryInterface;

namespace login_manager {

// Used to to track usage time metric. The tracked usage time is updated in
// regular intervals (and backed to a local file, to persist the value across
// reboots). The metric is sent to UMA at most once a day. It is ensured that
// sent usage time reflects only usage of the current OS version - on OS version
// update any accumulated time persisted for previous OS version will be
// discarded.
class CumulativeUseTimeMetric {
 public:
  // |metric_name|: The name for the metric.
  // |metrics_lib|: Metrics library used for sending metric value to UMA.
  // |metrics_files_dir|: Path to directory in which files backing the metric
  //     state should be stored.
  // |time_clock|: Clock used to track current time (and determining whether the
  //     stats should be uploaded).
  // |time_tick_clock|: Clock used to track elapsed time ticks since last value
  //     update and calculate the amount by which the metric value should be
  //     increased.
  CumulativeUseTimeMetric(const std::string& metric_name,
                          MetricsLibraryInterface* metrics_lib,
                          const base::FilePath& metrics_files_dir,
                          std::unique_ptr<base::Clock> time_clock,
                          std::unique_ptr<base::TickClock> time_tick_clock);
  CumulativeUseTimeMetric(const CumulativeUseTimeMetric&) = delete;
  CumulativeUseTimeMetric& operator=(const CumulativeUseTimeMetric&) = delete;

  ~CumulativeUseTimeMetric();

  // Initializes the metric state according to the last persisted value. The
  // value will be sent to UMA if sufficient time has passed.
  // |os_version_string|: Current OS version. If the version does not match the
  //     OS version of the last persistent metric value, the metric will be
  //     reset.
  void Init(const std::string& os_version_string);

  // Starts tracking usage time, increasing the usage metric value in regular
  // intervals.
  void Start();

  // Stops tracking usage time.
  void Stop();

  // Helper methods for exposing internal constants that define update and
  // upload intervals (useful for avoiding hard-coding of constants in tests).
  base::TimeDelta GetMetricsUpdateCycle() const;
  base::TimeDelta GetMetricsUploadCycle() const;
  base::FilePath GetMetricsFileForTest() const;

 private:
  // Representation of the cumulative usage metric value backed by a file on the
  // file system.
  class AccumulatedActiveTime;

  // Calculates the time elapsed since the last update and increases the usage
  // time metric (using |IncreaseActiveTimeAndSendUmaIfNeeded|).
  void UpdateStats();

  // Increases the usage time metric by |additional_time|, and sends the
  // new value to UMA if needed. Note that the metric value will be reset if it
  // is sent to UMA.
  void IncreaseActiveTimeAndSendUmaIfNeeded(
      const base::TimeDelta& additional_time);

  MetricsLibraryInterface* metrics_lib_;

  const std::string metric_name_;

  base::TimeTicks last_update_time_;
  std::unique_ptr<AccumulatedActiveTime> accumulated_active_time_;

  std::unique_ptr<base::Clock> time_clock_;
  std::unique_ptr<base::TickClock> time_tick_clock_;

  // Whether the usage time metric has been initialized.
  bool initialized_ = false;

  // Timer for scheduling tasks that update usage time metric.
  base::RepeatingTimer update_stats_timer_;
};

}  // namespace login_manager

#endif  // LOGIN_MANAGER_CUMULATIVE_USE_TIME_METRIC_H_
