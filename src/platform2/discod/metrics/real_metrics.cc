// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "discod/metrics/real_metrics.h"

#include <memory>
#include <string>
#include <utility>

#include <base/logging.h>
#include <metrics/metrics_library.h>

namespace discod {
std::unique_ptr<RealMetrics> RealMetrics::Create() {
  return std::make_unique<RealMetrics>(std::make_unique<MetricsLibrary>());
}

RealMetrics::RealMetrics(std::unique_ptr<MetricsLibraryInterface> metrics)
    : Metrics(), metrics_(std::move(metrics)) {}

RealMetrics::~RealMetrics() {}

void RealMetrics::SendToUMA(
    const std::string& name, int sample, int min, int max, int nbuckets) {
  if (!metrics_->SendToUMA(name, sample, min, max, nbuckets)) {
    PLOG(ERROR) << "Failed to send to UMA: " << name;
  }
}
void RealMetrics::SendPercentageToUMA(const std::string& name, int sample) {
  if (!metrics_->SendPercentageToUMA(name, sample)) {
    PLOG(ERROR) << "Failed to send to UMA: " << name;
  }
}
void RealMetrics::SendEnumToUMA(const std::string& name,
                                int sample,
                                int exclusive_max) {
  if (!metrics_->SendEnumToUMA(name, sample, exclusive_max)) {
    PLOG(ERROR) << "Failed to send to UMA: " << name;
  }
}

}  // namespace discod
