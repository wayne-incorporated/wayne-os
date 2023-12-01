// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RMAD_UTILS_MOCK_IIO_EC_SENSOR_UTILS_H_
#define RMAD_UTILS_MOCK_IIO_EC_SENSOR_UTILS_H_

#include "rmad/utils/iio_ec_sensor_utils.h"

#include <string>
#include <vector>

#include <gmock/gmock.h>

namespace rmad {

class MockIioEcSensorUtils : public IioEcSensorUtils {
 public:
  explicit MockIioEcSensorUtils(const std::string& location,
                                const std::string& name)
      : IioEcSensorUtils(location, name) {}
  ~MockIioEcSensorUtils() override = default;

  MOCK_METHOD(bool,
              GetAvgData,
              (GetAvgDataCallback, const std::vector<std::string>&, int),
              (override));
  MOCK_METHOD(bool,
              GetSysValues,
              (const std::vector<std::string>&, std::vector<double>*),
              (const override));
};

}  // namespace rmad

#endif  // RMAD_UTILS_MOCK_IIO_EC_SENSOR_UTILS_H_
