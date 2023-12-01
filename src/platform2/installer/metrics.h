// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef INSTALLER_METRICS_H_
#define INSTALLER_METRICS_H_

#include <memory>
#include <string>

// Most CrOS boards don't send metrics from postinstall. To avoid pulling in the
// metrics library unnecessarily on those boards we don't use the testing types
// it supplies, instead hiding it behind this MetricsInterface.
// The static GetMetricsInstance will provide a usable instance.
class MetricsInterface {
 public:
  // Returns a concrete Metrics object.
  // Without USE=postinst_metrics the returned instance's methods will all be
  // no-ops.
  static std::unique_ptr<MetricsInterface> GetMetricsInstance();

  virtual ~MetricsInterface() = default;

  // See metrics/metrics_library.h for a description of the arguments.
  // See power_manager/common/metrics_sender.h for a very readable description
  // of the constraints to follow if you don't want Chrome to silently discard
  // your metric.
  virtual bool SendMetric(const std::string& name,
                          int sample,
                          int min,
                          int max,
                          int num_buckets) = 0;
  virtual bool SendLinearMetric(const std::string& name,
                                int sample,
                                int max) = 0;
  virtual bool SendBooleanMetric(const std::string& name, bool sample) = 0;
  virtual bool SendEnumMetric(const std::string& name, int sample, int max) = 0;
};

#endif  // INSTALLER_METRICS_H_
