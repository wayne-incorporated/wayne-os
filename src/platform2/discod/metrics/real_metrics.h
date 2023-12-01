// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DISCOD_METRICS_REAL_METRICS_H_
#define DISCOD_METRICS_REAL_METRICS_H_

#include <memory>
#include <string>
#include <unordered_map>

#include <metrics/metrics_library.h>

#include "discod/metrics/metrics.h"

namespace discod {

class RealMetrics : public Metrics {
 public:
  static std::unique_ptr<RealMetrics> Create();

  explicit RealMetrics(std::unique_ptr<MetricsLibraryInterface> metrics);
  RealMetrics(const RealMetrics&) = delete;
  RealMetrics& operator=(const RealMetrics&) = delete;

  ~RealMetrics() override;

  void SendToUMA(const std::string& name,
                 int sample,
                 int min,
                 int max,
                 int nbuckets) override;
  void SendPercentageToUMA(const std::string& name, int sample) override;
  void SendEnumToUMA(const std::string& name,
                     int sample,
                     int exclusive_max) override;

 private:
  std::unique_ptr<MetricsLibraryInterface> metrics_;
};

}  // namespace discod

#endif  // DISCOD_METRICS_REAL_METRICS_H_
