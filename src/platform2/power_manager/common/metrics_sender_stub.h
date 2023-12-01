// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef POWER_MANAGER_COMMON_METRICS_SENDER_STUB_H_
#define POWER_MANAGER_COMMON_METRICS_SENDER_STUB_H_

#include <string>
#include <vector>

#include "power_manager/common/metrics_sender.h"

namespace power_manager {

// Stub implementation of MetricsSenderInterface that records calls for testing.
class MetricsSenderStub : public MetricsSenderInterface {
 public:
  // Information about a sent metric.
  struct Metric {
    enum class Type {
      EXPONENTIAL,
      ENUMERATION,
    };

    Metric();
    ~Metric() = default;

    // Returns a new exponential metric initialized to the passed-in values.
    static Metric CreateExp(
        const std::string& name, int sample, int min, int max, int num_buckets);

    // Returns a new enumerated metric initialized to the passed-in values.
    static Metric CreateEnum(const std::string& name, int sample, int max);

    // Returns a string describing the metric. Useful for comparisons in tests.
    std::string ToString() const;

    std::string name;
    Type type;
    int sample;
    int min;
    int max;
    int num_buckets;
  };

  // The c'tor and d'tor call SetInstance() to register and unregister this
  // instance.
  MetricsSenderStub();
  MetricsSenderStub(const MetricsSenderStub&) = delete;
  MetricsSenderStub& operator=(const MetricsSenderStub&) = delete;

  ~MetricsSenderStub() override;

  int num_metrics() const { return metrics_.size(); }
  void clear_metrics() { metrics_.clear(); }

  // Gets the Metric::ToString() form of the i-th metric from |metrics_|.
  // Returns an empty string if fewer than |i| metrics were sent.
  std::string GetMetric(size_t i) const;

  // MetricsSenderInterface implementation:
  bool SendMetric(const std::string& name,
                  int sample,
                  int min,
                  int max,
                  int num_buckets) override;
  bool SendEnumMetric(const std::string& name, int sample, int max) override;

 private:
  // Sent metrics.
  std::vector<Metric> metrics_;
};

}  // namespace power_manager

#endif  // POWER_MANAGER_COMMON_METRICS_SENDER_STUB_H_
