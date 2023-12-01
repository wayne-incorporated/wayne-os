// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "installer/metrics.h"

// This is a "stub" metrics implementation, which does nothing.
class MetricsStub : public MetricsInterface {
 public:
  bool SendMetric(const std::string& name,
                  int sample,
                  int min,
                  int max,
                  int num_buckets) override {
    return true;
  }
  bool SendLinearMetric(const std::string& name, int sample, int max) override {
    return true;
  }
  bool SendBooleanMetric(const std::string& name, bool sample) override {
    return true;
  }
  bool SendEnumMetric(const std::string& name, int sample, int max) override {
    return true;
  }
};

// Use our stub as the Metrics object.
std::unique_ptr<MetricsInterface> MetricsInterface::GetMetricsInstance() {
  return std::make_unique<MetricsStub>();
}
