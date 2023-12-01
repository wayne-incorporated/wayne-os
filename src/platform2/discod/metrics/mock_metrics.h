// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DISCOD_METRICS_MOCK_METRICS_H_
#define DISCOD_METRICS_MOCK_METRICS_H_

#include <string>

#include <gmock/gmock.h>

#include "discod/metrics/metrics.h"

namespace discod {

class MockMetrics : public Metrics {
 public:
  MockMetrics() = default;
  MockMetrics(const MockMetrics&) = delete;
  MockMetrics& operator=(const MockMetrics&) = delete;

  ~MockMetrics() override = default;

  MOCK_METHOD(void,
              SendToUMA,
              (const std::string&, int, int, int, int),
              (override));
  MOCK_METHOD(void, SendPercentageToUMA, (const std::string&, int), (override));
  MOCK_METHOD(void, SendEnumToUMA, (const std::string&, int, int), (override));
};

}  // namespace discod

#endif  // DISCOD_METRICS_MOCK_METRICS_H_
