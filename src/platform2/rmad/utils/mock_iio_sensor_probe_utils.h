// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RMAD_UTILS_MOCK_IIO_SENSOR_PROBE_UTILS_H_
#define RMAD_UTILS_MOCK_IIO_SENSOR_PROBE_UTILS_H_

#include "rmad/utils/iio_sensor_probe_utils.h"

#include <set>

#include <gmock/gmock.h>

#include "rmad/proto_bindings/rmad.pb.h"

namespace rmad {

class MockIioSensorProbeUtils : public IioSensorProbeUtils {
 public:
  MockIioSensorProbeUtils() = default;
  ~MockIioSensorProbeUtils() override = default;

  MOCK_METHOD(std::set<RmadComponent>, Probe, (), (override));
};

}  // namespace rmad

#endif  // RMAD_UTILS_MOCK_IIO_SENSOR_PROBE_UTILS_H_
