// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef POWER_MANAGER_POWERD_SYSTEM_ROLLING_AVERAGE_H_
#define POWER_MANAGER_POWERD_SYSTEM_ROLLING_AVERAGE_H_

#include <queue>

#include <base/time/time.h>

namespace power_manager::system {

// This class tracks the rolling average from a continuous sequence of
// samples.
class RollingAverage {
 public:
  // Up to |window_size| samples will be held.
  explicit RollingAverage(size_t window_size);
  RollingAverage(const RollingAverage&) = delete;
  RollingAverage& operator=(const RollingAverage&) = delete;

  ~RollingAverage() = default;

  // Adds a sample of |value| collected at |time|. Negative values are allowed.
  void AddSample(double value, const base::TimeTicks& time);

  // Returns the current average.
  double GetAverage() const;

  // Returns the time difference between the first and last sample (i.e. last
  // minus first). The delta will be empty if there are fewer than two samples.
  base::TimeDelta GetTimeDelta() const;

  // Returns the value difference between the first and last sample (i.e. last
  // minus first). The value will be zero if there are fewer than two samples.
  double GetValueDelta() const;

  // Clears all samples.
  void Clear();

  // Returns True if size of |samples_| is equal to |window_size|.
  bool HasMaxSamples() const;

 private:
  // A timestamped data point.
  struct Sample {
    Sample(double value, const base::TimeTicks& time)
        : value(value), time(time) {}

    double value;
    base::TimeTicks time;
  };

  // Deletes the oldest sample.
  void DeleteSample();

  std::queue<Sample> samples_;

  // Sum of values in |samples_|.
  double running_total_ = 0.0;

  // Maximum number of samples to store.
  size_t window_size_;
};

}  // namespace power_manager::system

#endif  // POWER_MANAGER_POWERD_SYSTEM_ROLLING_AVERAGE_H_
