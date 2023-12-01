// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MIST_METRICS_H_
#define MIST_METRICS_H_

#include <metrics/metrics_library.h>

namespace mist {

// A class for collecting mist related UMA metrics.
class Metrics {
 public:
  Metrics();
  Metrics(const Metrics&) = delete;
  Metrics& operator=(const Metrics&) = delete;

  ~Metrics() = default;

  void RecordSwitchResult(bool success);

 private:
  MetricsLibrary metrics_library_;
};

}  // namespace mist

#endif  // MIST_METRICS_H_
