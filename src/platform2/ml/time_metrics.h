// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ML_TIME_METRICS_H_
#define ML_TIME_METRICS_H_

#include <string>

#include <base/time/time.h>

namespace ml {

// An RAII class to measure the wall time usage of a scope.
// The starting time is measured in constructor. And the ending time is measured
// and reported in destructor.
class WallTimeMetric {
 public:
  explicit WallTimeMetric(const std::string& name);
  ~WallTimeMetric();

 private:
  const std::string metric_name_;
  const base::Time start_time_;
};

// Records how long it takes to reap the worker process.
void RecordReapWorkerProcessWallTime(base::Time begin_time,
                                     base::Time end_time);

}  // namespace ml
#endif  // ML_TIME_METRICS_H_
