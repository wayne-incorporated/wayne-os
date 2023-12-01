// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RMAD_UTILS_MOCK_SENSOR_CALIBRATION_UTILS_H_
#define RMAD_UTILS_MOCK_SENSOR_CALIBRATION_UTILS_H_

#include "rmad/utils/sensor_calibration_utils.h"

#include <string>

#include <gmock/gmock.h>

namespace rmad {

class MockSensorCalibrationUtils : public SensorCalibrationUtils {
 public:
  MockSensorCalibrationUtils() = default;
  ~MockSensorCalibrationUtils() override = default;

  MOCK_METHOD(void,
              Calibrate,
              (CalibrationComponentStatusCallback, CalibrationResultCallback),
              (override));
};

}  // namespace rmad

#endif  // RMAD_UTILS_MOCK_SENSOR_CALIBRATION_UTILS_H_
