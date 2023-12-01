// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MINIOS_MOCK_METRICS_REPORTER_H_
#define MINIOS_MOCK_METRICS_REPORTER_H_

#include <gmock/gmock.h>

#include "minios/metrics_reporter_interface.h"

namespace minios {

class MockMetricsReporter : public MetricsReporterInterface {
 public:
  MockMetricsReporter() = default;

  MOCK_METHOD(void, RecordNBRStart, (), (override));
  MOCK_METHOD(void, ReportNBRComplete, (), (override));
};

}  // namespace minios

#endif  // MINIOS_MOCK_METRICS_REPORTER_H_
