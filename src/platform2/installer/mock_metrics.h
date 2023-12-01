// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef INSTALLER_MOCK_METRICS_H_
#define INSTALLER_MOCK_METRICS_H_

#include <string>

#include <gmock/gmock.h>

#include "installer/metrics.h"

class MockMetrics : public MetricsInterface {
 public:
  MOCK_METHOD(
      bool,
      SendMetric,
      (const std::string& name, int sample, int min, int max, int num_buckets),
      (override));
  MOCK_METHOD(bool,
              SendLinearMetric,
              (const std::string& name, int sample, int max),
              (override));
  MOCK_METHOD(bool,
              SendBooleanMetric,
              (const std::string& name, bool sample),
              (override));
  MOCK_METHOD(bool,
              SendEnumMetric,
              (const std::string& name, int sample, int max),
              (override));
};

#endif  // INSTALLER_MOCK_METRICS_H_
