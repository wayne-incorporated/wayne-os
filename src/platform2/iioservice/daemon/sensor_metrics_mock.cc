// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "iioservice/daemon/sensor_metrics_mock.h"

#include <memory>
#include <utility>

#include "iioservice/include/common.h"

namespace iioservice {

// static
MetricsLibraryMock* SensorMetricsMock::InitializeForTesting() {
  if (SensorMetricsMock::GetInstance()) {
    LOGF(WARNING) << "SensorMetrics was already initialized";
    return nullptr;
  }

  std::unique_ptr<MetricsLibraryMock> metrics_lib_mock(
      new MetricsLibraryMock());
  auto ptr = metrics_lib_mock.get();
  SensorMetricsMock::SetInstance(
      new SensorMetricsMock(std::move(metrics_lib_mock)));

  return ptr;
}

SensorMetricsMock::SensorMetricsMock(
    std::unique_ptr<MetricsLibraryInterface> metrics_lib)
    : SensorMetrics(std::move(metrics_lib)) {}

}  // namespace iioservice
