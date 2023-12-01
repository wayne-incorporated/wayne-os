// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RMAD_UTILS_SENSOR_CALIBRATION_UTILS_H_
#define RMAD_UTILS_SENSOR_CALIBRATION_UTILS_H_

#include <map>
#include <string>

#include <base/functional/callback.h>
#include <rmad/proto_bindings/rmad.pb.h>

namespace rmad {

class SensorCalibrationUtils {
 public:
  SensorCalibrationUtils() = default;
  virtual ~SensorCalibrationUtils() = default;

  // Define callback to update calibration progress.
  using CalibrationComponentStatusCallback =
      base::RepeatingCallback<void(CalibrationComponentStatus)>;
  // Define callback to update calibration result via map (keyname in vpd ->
  // calibration bias).
  using CalibrationResultCallback =
      base::OnceCallback<void(const std::map<std::string, int>&)>;

  virtual void Calibrate(
      CalibrationComponentStatusCallback component_status_callback,
      CalibrationResultCallback result_callback) = 0;
};

}  // namespace rmad

#endif  // RMAD_UTILS_SENSOR_CALIBRATION_UTILS_H_
