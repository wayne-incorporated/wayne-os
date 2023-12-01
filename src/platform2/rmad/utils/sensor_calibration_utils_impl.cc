// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "rmad/utils/sensor_calibration_utils_impl.h"

#include <map>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <base/logging.h>

#include "base/check.h"
#include "rmad/utils/iio_ec_sensor_utils_impl.h"

namespace {

constexpr int kSamples = 100;

constexpr double kGravity = 9.80665;
constexpr double kDegree2Radian = M_PI / 180.0;

// Both thresholds are used in m/s^2 units. The offset is indicating the
// tolerance in m/s^2 for the digital output of sensors under 0 and 1G.
// TODO(jeffulin): This threshold seems too relaxed for gyroscope. We should
// find the reliable sources to set the thresholds for different sensors.
constexpr double kOffsetThreshold = 2.0;
// The variance of capture data can not be larger than the threshold.
constexpr double kVarianceThreshold = 5.0;

constexpr double kProgressFailed = -1.0;
constexpr double kProgressInit = 0.0;
constexpr double kProgressGetOriginalCalibbias = 0.2;
constexpr double kProgressSensorDataReceived = 0.7;
constexpr double kProgressBiasCalculated = 0.8;
constexpr double kProgressCalibbiasCached = 0.9;

constexpr char kCalibbiasPrefix[] = "in_";
constexpr char kCalibbiasPostfix[] = "_calibbias";

const std::set<std::string> kValidSensorNames = {
    rmad::SensorCalibrationUtilsImpl::kGyroSensorName,
    rmad::SensorCalibrationUtilsImpl::kAccelSensorName};

const std::map<std::string, std::vector<std::string>> kSensorChannels = {
    {rmad::SensorCalibrationUtilsImpl::kGyroSensorName,
     {"anglvel_x", "anglvel_y", "anglvel_z"}},
    {rmad::SensorCalibrationUtilsImpl::kAccelSensorName,
     {"accel_x", "accel_y", "accel_z"}}};

const std::map<std::string, std::vector<std::string>> kSensorCalibbias = {
    {rmad::SensorCalibrationUtilsImpl::kGyroSensorName,
     {"in_anglvel_x_calibbias", "in_anglvel_y_calibbias",
      "in_anglvel_z_calibbias"}},
    {rmad::SensorCalibrationUtilsImpl::kAccelSensorName,
     {"in_accel_x_calibbias", "in_accel_y_calibbias", "in_accel_z_calibbias"}}};

const std::map<std::string, std::vector<double>> kSensorIdealValues = {
    {rmad::SensorCalibrationUtilsImpl::kGyroSensorName, {0, 0, 0}},
    {rmad::SensorCalibrationUtilsImpl::kAccelSensorName, {0, 0, kGravity}}};

// The calibbias data unit in gyroscope is 1/1024 dps, and the sensor reading is
// rad/s. The calibbias data unit in accelerometer is G/1024, and the sensor
// reading unit is m/s^2.
const std::map<std::string, double> kCalibbias2SensorReading = {
    {rmad::SensorCalibrationUtilsImpl::kGyroSensorName, kDegree2Radian / 1024},
    {rmad::SensorCalibrationUtilsImpl::kAccelSensorName, kGravity / 1024.0}};

}  // namespace

namespace rmad {

SensorCalibrationUtilsImpl::SensorCalibrationUtilsImpl(
    scoped_refptr<MojoServiceUtils> mojo_service,
    const std::string& location,
    const std::string& name,
    RmadComponent component)
    : location_(location), name_(name), component_(component) {
  CHECK(kValidSensorNames.find(name) != kValidSensorNames.end())
      << "Sensor name \"" << name << "\" is invalid.";

  calibbias_ = kSensorCalibbias.at(name);
  channels_ = kSensorChannels.at(name);
  ideal_values_ = kSensorIdealValues.at(name);

  iio_ec_sensor_utils_ =
      std::make_unique<IioEcSensorUtilsImpl>(mojo_service, location, name);
}

SensorCalibrationUtilsImpl::SensorCalibrationUtilsImpl(
    const std::string& location,
    const std::string& name,
    RmadComponent component,
    std::unique_ptr<IioEcSensorUtils> iio_ec_sensor_utils)
    : location_(location),
      name_(name),
      component_(component),
      iio_ec_sensor_utils_(std::move(iio_ec_sensor_utils)) {
  calibbias_ = kSensorCalibbias.at(name);
  channels_ = kSensorChannels.at(name);
  ideal_values_ = kSensorIdealValues.at(name);
}

void SensorCalibrationUtilsImpl::Calibrate(
    CalibrationComponentStatusCallback component_status_callback,
    CalibrationResultCallback result_callback) {
  CHECK(iio_ec_sensor_utils_);
  CHECK_EQ(GetLocation(), iio_ec_sensor_utils_->GetLocation());
  CHECK_EQ(GetName(), iio_ec_sensor_utils_->GetName());

  std::vector<double> original_calibbias;
  component_status_callback.Run(GenerateComponentStatus(
      CalibrationComponentStatus::RMAD_CALIBRATION_IN_PROGRESS, kProgressInit));

  // Before the calibration, we get original calibbias by reading sysfs.
  if (!iio_ec_sensor_utils_->GetSysValues(calibbias_, &original_calibbias)) {
    component_status_callback.Run(GenerateComponentStatus(
        CalibrationComponentStatus::RMAD_CALIBRATION_FAILED, kProgressFailed));
    return;
  }
  component_status_callback.Run(GenerateComponentStatus(
      CalibrationComponentStatus::RMAD_CALIBRATION_GET_ORIGINAL_CALIBBIAS,
      kProgressGetOriginalCalibbias));

  // Due to the uncertainty of the sensor value, we use the average value to
  // calibrate it.
  if (!iio_ec_sensor_utils_->GetAvgData(
          base::BindOnce(&SensorCalibrationUtilsImpl::HandleGetAvgDataResult,
                         base::Unretained(this), component_status_callback,
                         std::move(result_callback), original_calibbias),
          channels_, kSamples)) {
    LOG(ERROR) << GetLocation() << ":" << GetName()
               << ": Failed to accumulate data.";
    component_status_callback.Run(GenerateComponentStatus(
        CalibrationComponentStatus::RMAD_CALIBRATION_FAILED, kProgressFailed));
    return;
  }
}

void SensorCalibrationUtilsImpl::HandleGetAvgDataResult(
    CalibrationComponentStatusCallback component_status_callback,
    CalibrationResultCallback result_callback,
    const std::vector<double>& original_calibbias,
    const std::vector<double>& avg_data,
    const std::vector<double>& variance_data) {
  std::map<std::string, int> calibbias;
  component_status_callback.Run(GenerateComponentStatus(
      CalibrationComponentStatus::RMAD_CALIBRATION_SENSOR_DATA_RECEIVED,
      kProgressSensorDataReceived));

  if (avg_data.size() != ideal_values_.size()) {
    LOG(ERROR) << GetLocation() << ":" << GetName() << ": Get wrong data size "
               << avg_data.size();
    component_status_callback.Run(GenerateComponentStatus(
        CalibrationComponentStatus::RMAD_CALIBRATION_FAILED, kProgressFailed));
    return;
  }

  if (GetName() == SensorCalibrationUtilsImpl::kAccelSensorName &&
      !CheckVariance(variance_data)) {
    component_status_callback.Run(GenerateComponentStatus(
        CalibrationComponentStatus::RMAD_CALIBRATION_FAILED, kProgressFailed));
    return;
  }

  // For each axis, we calculate the difference between the ideal values.
  for (int i = 0; i < avg_data.size(); i++) {
    double offset =
        ideal_values_.at(i) - avg_data.at(i) +
        original_calibbias.at(i) * kCalibbias2SensorReading.at(GetName());
    if (GetName() == SensorCalibrationUtilsImpl::kAccelSensorName &&
        std::fabs(offset) > kOffsetThreshold) {
      LOG(ERROR) << GetLocation() << ":" << GetName()
                 << ": Data is out of range, the sensor may be damaged or the"
                    " device setup is incorrect.";
      component_status_callback.Run(GenerateComponentStatus(
          CalibrationComponentStatus::RMAD_CALIBRATION_FAILED,
          kProgressFailed));
      return;
    }
    std::string entry = kCalibbiasPrefix + channels_.at(i) + "_" +
                        GetLocation() + kCalibbiasPostfix;
    calibbias[entry] = round(offset / kCalibbias2SensorReading.at(GetName()));
  }
  component_status_callback.Run(GenerateComponentStatus(
      CalibrationComponentStatus::RMAD_CALIBRATION_CALIBBIAS_CALCULATED,
      kProgressBiasCalculated));

  std::move(result_callback).Run(calibbias);
  component_status_callback.Run(GenerateComponentStatus(
      CalibrationComponentStatus::RMAD_CALIBRATION_CALIBBIAS_CACHED,
      kProgressCalibbiasCached));
}

bool SensorCalibrationUtilsImpl::CheckVariance(
    const std::vector<double> variances) const {
  if (variances.size() != ideal_values_.size()) {
    LOG(ERROR) << location_ << ":" << name_ << ": Get wrong variance data size "
               << variances.size();
    return false;
  }

  for (int i = 0; i < variances.size(); i++) {
    if (variances.at(i) > kVarianceThreshold) {
      LOG(ERROR) << location_ << ":" << name_
                 << ": Data variance=" << variances.at(i)
                 << " too high in channel " << channels_.at(i)
                 << ". Expected to be less than " << kVarianceThreshold;
      return false;
    }
  }
  return true;
}

const std::string& SensorCalibrationUtilsImpl::GetLocation() const {
  return location_;
}

const std::string& SensorCalibrationUtilsImpl::GetName() const {
  return name_;
}

CalibrationComponentStatus SensorCalibrationUtilsImpl::GenerateComponentStatus(
    CalibrationComponentStatus::CalibrationStatus status, double progress) {
  CalibrationComponentStatus component_status;
  component_status.set_component(component_);
  component_status.set_status(status);
  component_status.set_progress(progress);
  return component_status;
}

}  // namespace rmad
