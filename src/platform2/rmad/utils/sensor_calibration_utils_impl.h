// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RMAD_UTILS_SENSOR_CALIBRATION_UTILS_IMPL_H_
#define RMAD_UTILS_SENSOR_CALIBRATION_UTILS_IMPL_H_

#include <memory>
#include <string>
#include <vector>

#include <base/functional/callback.h>

#include "rmad/utils/iio_ec_sensor_utils.h"
#include "rmad/utils/mojo_service_utils.h"
#include "rmad/utils/sensor_calibration_utils.h"

namespace rmad {

class SensorCalibrationUtilsImpl : public SensorCalibrationUtils {
 public:
  explicit SensorCalibrationUtilsImpl(
      scoped_refptr<MojoServiceUtils> mojo_service,
      const std::string& location,
      const std::string& name,
      RmadComponent component);

  // Used to inject iio_ec_sensor_utils for testing.
  explicit SensorCalibrationUtilsImpl(
      const std::string& location,
      const std::string& name,
      RmadComponent component,
      std::unique_ptr<IioEcSensorUtils> iio_ec_sensor_utils);

  ~SensorCalibrationUtilsImpl() override = default;

  const std::string& GetLocation() const;
  const std::string& GetName() const;

  void Calibrate(CalibrationComponentStatusCallback component_status_callback,
                 CalibrationResultCallback result_callback) override;

  static constexpr char kGyroSensorName[] = "cros-ec-gyro";
  static constexpr char kAccelSensorName[] = "cros-ec-accel";
  static constexpr char kBaseLocationName[] = "base";
  static constexpr char kLidLocationName[] = "lid";

 private:
  void HandleGetAvgDataResult(
      CalibrationComponentStatusCallback component_status_callback,
      CalibrationResultCallback result_callback,
      const std::vector<double>& original_calibbias,
      const std::vector<double>& avg_data,
      const std::vector<double>& variance_data);
  bool CheckVariance(const std::vector<double> variances) const;
  CalibrationComponentStatus GenerateComponentStatus(
      CalibrationComponentStatus::CalibrationStatus, double progress);

  std::vector<std::string> calibbias_;
  std::vector<std::string> channels_;
  std::vector<double> ideal_values_;

  // For each sensor, we can identify it by its location (base or lid)
  // and name (cros-ec-accel or cros-ec-gyro)
  std::string location_;
  std::string name_;
  RmadComponent component_;

  // utils part.
  std::unique_ptr<IioEcSensorUtils> iio_ec_sensor_utils_;
};

}  // namespace rmad

#endif  // RMAD_UTILS_SENSOR_CALIBRATION_UTILS_IMPL_H_
