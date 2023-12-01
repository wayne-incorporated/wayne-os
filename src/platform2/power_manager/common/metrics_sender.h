// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef POWER_MANAGER_COMMON_METRICS_SENDER_H_
#define POWER_MANAGER_COMMON_METRICS_SENDER_H_

#include <memory>
#include <string>

#include <base/compiler_specific.h>

class MetricsLibraryInterface;

namespace power_manager {

// Stubbable interface for sending metrics.
class MetricsSenderInterface {
 public:
  // Returns the currently-registered singleton. The return value may be NULL
  // (e.g. during testing).
  static MetricsSenderInterface* GetInstance();

  // Registers |instance| as the current singleton. Another instance must not
  // already be registered. Ownership of |instance| remains with the caller.
  static void SetInstance(MetricsSenderInterface* instance);

  virtual ~MetricsSenderInterface() = default;

  // See MetricsLibrary::SendToUMA in metrics/metrics_library.h for a
  // description of the arguments in the below methods.

  // Sends a regular (exponential) histogram sample.
  //
  // There are various constraints on values (see base/metrics/histogram.h in
  // Chrome), including:
  //
  // * 1 <= |min| < |max| < base::HistogramBase::kSampleType_MAX
  // * |num_buckets| < base::Histogram::kBucketCount_MAX
  // * |num_buckets| <= |max| - |min| + 2
  //
  // Violating these constraints may result in Chrome silently discarding the
  // sample rather than reporting.
  virtual bool SendMetric(const std::string& name,
                          int sample,
                          int min,
                          int max,
                          int num_buckets) = 0;

  // Sends an enumeration (linear) histogram sample.
  virtual bool SendEnumMetric(const std::string& name, int sample, int max) = 0;
};

// MetricsSenderInterface implementation that wraps the metrics library and
// actually forwards metrics to Chrome.
class MetricsSender : public MetricsSenderInterface {
 public:
  // Create an new MetricsSender, using the given MetricsLibrary object.
  //
  // The c'tor and d'tor call SetInstance() to register and unregister this
  // instance.
  //
  // Caller retains ownership of `metrics_lib`, which must outlive this
  // instance.
  explicit MetricsSender(MetricsLibraryInterface& metrics_lib);
  MetricsSender(const MetricsSender&) = delete;
  MetricsSender& operator=(const MetricsSender&) = delete;

  ~MetricsSender() override;

  // MetricsSenderInterface implementation:
  bool SendMetric(const std::string& name,
                  int sample,
                  int min,
                  int max,
                  int num_buckets) override;
  bool SendEnumMetric(const std::string& name, int sample, int max) override;

 private:
  MetricsLibraryInterface* metrics_lib_;  // Owned elsewhere.
};

// Convenience wrapper for calling SendMetric() on the currently-registered
// MetricsSenderInterface singleton. Returns true without doing anything if no
// singleton is currently registered (e.g. for testing).
bool SendMetric(
    const std::string& name, int sample, int min, int max, int num_buckets);

// Convenience wrapper for calling SendEnumMetric() on the currently-registered
// MetricsSenderInterface singleton. Returns true without doing anything if no
// singleton is currently registered (e.g. for testing).
bool SendEnumMetric(const std::string& name, int sample, int max);

}  // namespace power_manager

#endif  // POWER_MANAGER_COMMON_METRICS_SENDER_H_
