// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/routines/sensor/sensor_existence_checker.h"

#include <string>
#include <utility>
#include <vector>

#include <base/functional/bind.h>
#include <base/functional/callback.h>
#include <base/logging.h>
#include <iioservice/mojo/sensor.mojom.h>

#include "diagnostics/cros_healthd/system/system_config.h"
#include "diagnostics/cros_healthd/utils/callback_barrier.h"

namespace {

// Return true if the sensor is accelerometer, gyroscope or magnetometer.
bool IsTargetType(const std::vector<cros::mojom::DeviceType>& types) {
  for (const auto& type : types) {
    if (type == cros::mojom::DeviceType::ACCEL ||
        type == cros::mojom::DeviceType::ANGLVEL ||
        type == cros::mojom::DeviceType::MAGN ||
        type == cros::mojom::DeviceType::GRAVITY)
      return true;
  }
  return false;
}

// Check if the |has_sensor| value in static config is consistent with the
// actual |is_present| and retrun the result.
diagnostics::SensorExistenceChecker::Result::State GetExistenceCheckState(
    std::optional<bool> has_sensor, bool is_present) {
  if (!has_sensor.has_value()) {
    return diagnostics::SensorExistenceChecker::Result::kSkipped;
  } else if (has_sensor.value() != is_present) {
    if (!is_present)
      return diagnostics::SensorExistenceChecker::Result::kMissing;
    else
      return diagnostics::SensorExistenceChecker::Result::kUnexpected;
  } else {
    return diagnostics::SensorExistenceChecker::Result::kPassed;
  }
}

}  // namespace

namespace diagnostics {

SensorExistenceChecker::SensorExistenceChecker(
    MojoService* const mojo_service, SystemConfigInterface* const system_config)
    : mojo_service_(mojo_service), system_config_(system_config) {
  CHECK(mojo_service_);
  CHECK(system_config_);
}

SensorExistenceChecker::~SensorExistenceChecker() = default;

void SensorExistenceChecker::VerifySensorInfo(
    const base::flat_map<int32_t, std::vector<cros::mojom::DeviceType>>&
        ids_types,
    base::OnceCallback<void(std::map<SensorType, Result>)> on_finish) {
  CallbackBarrier barrier{
      base::BindOnce(&SensorExistenceChecker::CheckSystemConfig,
                     weak_ptr_factory_.GetWeakPtr(), std::move(on_finish))};
  for (const auto& [sensor_id, sensor_types] : ids_types) {
    if (!IsTargetType(sensor_types))
      continue;

    // Get the sensor location.
    mojo_service_->GetSensorDevice(sensor_id)->GetAttributes(
        {cros::mojom::kLocation},
        barrier.Depend(base::BindOnce(
            &SensorExistenceChecker::HandleSensorLocationResponse,
            weak_ptr_factory_.GetWeakPtr(), sensor_id, sensor_types)));
  }
}

void SensorExistenceChecker::HandleSensorLocationResponse(
    int32_t sensor_id,
    const std::vector<cros::mojom::DeviceType>& sensor_types,
    const std::vector<std::optional<std::string>>& attributes) {
  if (attributes.size() != 1 || !attributes[0].has_value()) {
    LOG(ERROR) << "Failed to access sensor location.";
    return;
  }

  const auto& location = attributes[0].value();
  for (const auto& type : sensor_types) {
    if (type == cros::mojom::DeviceType::ACCEL) {
      if (location == cros::mojom::kLocationBase)
        iio_sensor_ids_[kBaseAccelerometer].push_back(sensor_id);
      else if (location == cros::mojom::kLocationLid)
        iio_sensor_ids_[kLidAccelerometer].push_back(sensor_id);
    } else if (type == cros::mojom::DeviceType::ANGLVEL) {
      if (location == cros::mojom::kLocationBase)
        iio_sensor_ids_[kBaseGyroscope].push_back(sensor_id);
      else if (location == cros::mojom::kLocationLid)
        iio_sensor_ids_[kLidGyroscope].push_back(sensor_id);
    } else if (type == cros::mojom::DeviceType::MAGN) {
      if (location == cros::mojom::kLocationBase)
        iio_sensor_ids_[kBaseMagnetometer].push_back(sensor_id);
      else if (location == cros::mojom::kLocationLid)
        iio_sensor_ids_[kLidMagnetometer].push_back(sensor_id);
    } else if (type == cros::mojom::DeviceType::GRAVITY) {
      if (location == cros::mojom::kLocationBase)
        iio_sensor_ids_[kBaseGravitySensor].push_back(sensor_id);
      else if (location == cros::mojom::kLocationLid)
        iio_sensor_ids_[kLidGravitySensor].push_back(sensor_id);
    }
  }
}

void SensorExistenceChecker::CheckSystemConfig(
    base::OnceCallback<void(std::map<SensorType, Result>)> on_finish,
    bool all_callbacks_called) {
  if (!all_callbacks_called) {
    LOG(ERROR) << "Some callbacks are not called successfully";
    std::move(on_finish).Run({});
    return;
  }

  std::map<SensorType, Result> existence_check_result;
  for (const auto& sensor :
       {kBaseAccelerometer, kLidAccelerometer, kBaseGyroscope, kLidGyroscope,
        kBaseGravitySensor, kBaseMagnetometer, kLidMagnetometer,
        kLidGravitySensor}) {
    existence_check_result[sensor] = {
        .state = GetExistenceCheckState(
            /*has_sensor=*/system_config_->HasSensor(sensor),
            /*is_present=*/!iio_sensor_ids_[sensor].empty()),
        .sensor_ids = iio_sensor_ids_[sensor]};
  }

  std::move(on_finish).Run(std::move(existence_check_result));
}

}  // namespace diagnostics
