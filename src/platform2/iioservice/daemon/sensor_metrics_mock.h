// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef IIOSERVICE_DAEMON_SENSOR_METRICS_MOCK_H_
#define IIOSERVICE_DAEMON_SENSOR_METRICS_MOCK_H_

#include "iioservice/daemon/sensor_metrics.h"

#include <memory>

#include <metrics/metrics_library_mock.h>

namespace iioservice {

class IIOSERVICE_EXPORT SensorMetricsMock : public SensorMetrics {
 public:
  // Creates the global SensorMetricsMock instance for testing.
  static MetricsLibraryMock* InitializeForTesting();

 private:
  explicit SensorMetricsMock(
      std::unique_ptr<MetricsLibraryInterface> metrics_lib);
};

}  // namespace iioservice

#endif  // IIOSERVICE_DAEMON_SENSOR_METRICS_MOCK_H_
