// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/powerd/system/ambient_light_sensor_manager_mojo.h"

#include <algorithm>
#include <optional>
#include <utility>

#include <base/check.h>
#include <base/check_op.h>
#include <base/functional/bind.h>
#include <base/logging.h>

#include "power_manager/common/power_constants.h"
#include "power_manager/common/prefs.h"
#include "power_manager/powerd/system/ambient_light_sensor_delegate_mojo.h"

namespace power_manager::system {

AmbientLightSensorInterface*
AmbientLightSensorManagerMojo::GetSensorForInternalBacklight() {
  return lid_sensor_.sensor;
}

AmbientLightSensorInterface*
AmbientLightSensorManagerMojo::GetSensorForKeyboardBacklight() {
  return base_sensor_.sensor;
}

AmbientLightSensorManagerMojo::AmbientLightSensorManagerMojo(
    PrefsInterface* prefs, SensorServiceHandler* sensor_service_handler)
    : SensorServiceHandlerObserver(sensor_service_handler) {
  prefs->GetInt64(kHasAmbientLightSensorPref, &num_sensors_);
  if (num_sensors_ <= 0)
    return;

  CHECK(prefs->GetBool(kAllowAmbientEQ, &allow_ambient_eq_))
      << "Failed to read pref " << kAllowAmbientEQ;

  if (num_sensors_ == 1) {
    sensors_.push_back(std::make_unique<AmbientLightSensor>());

    lid_sensor_.sensor = base_sensor_.sensor = sensors_[0].get();

    return;
  }

  sensors_.push_back(std::make_unique<AmbientLightSensor>());
  lid_sensor_.sensor = sensors_[0].get();

  sensors_.push_back(std::make_unique<AmbientLightSensor>());
  base_sensor_.sensor = sensors_[1].get();
}

AmbientLightSensorManagerMojo::~AmbientLightSensorManagerMojo() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  sensors_.clear();
  lights_.clear();
}

bool AmbientLightSensorManagerMojo::HasColorSensor() {
  for (const auto& sensor : sensors_) {
    if (sensor->IsColorSensor())
      return true;
  }
  return false;
}

void AmbientLightSensorManagerMojo::OnNewDeviceAdded(
    int32_t iio_device_id, const std::vector<cros::mojom::DeviceType>& types) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  if (num_sensors_ <= 0)
    return;

  if (std::find(types.begin(), types.end(), cros::mojom::DeviceType::LIGHT) ==
      types.end()) {
    // Not a light sensor. Ignoring this device.
    return;
  }

  if (lights_.find(iio_device_id) != lights_.end()) {
    // Has already added this device.
    return;
  }

  auto& light = lights_[iio_device_id];

  sensor_service_handler_->GetDevice(iio_device_id,
                                     light.remote.BindNewPipeAndPassReceiver());
  light.remote.set_disconnect_with_reason_handler(
      base::BindOnce(&AmbientLightSensorManagerMojo::OnSensorDeviceDisconnect,
                     base::Unretained(this), iio_device_id));

  if (num_sensors_ == 1) {
    light.remote->GetAttributes(
        std::vector<std::string>{cros::mojom::kDeviceName},
        base::BindOnce(&AmbientLightSensorManagerMojo::GetNameCallback,
                       base::Unretained(this), iio_device_id));
  } else {  // num_sensors_ >= 2
    light.remote->GetAttributes(
        std::vector<std::string>{cros::mojom::kDeviceName,
                                 cros::mojom::kLocation},
        base::BindOnce(
            &AmbientLightSensorManagerMojo::GetNameAndLocationCallback,
            base::Unretained(this), iio_device_id));
  }
}

void AmbientLightSensorManagerMojo::SensorServiceConnected() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  if (num_sensors_ <= 0)
    return;

  if (num_sensors_ == 1) {
    if (lid_sensor_.iio_device_id.has_value()) {
      // Use the original device.
      SetSensorDeviceMojo(&lid_sensor_, allow_ambient_eq_);
    }
  } else {  // num_sensors_ >= 2
    // The two cros-ec-lights on lid and base should exist. Therefore, the
    // potential existing acpi-als is ignored.
    if (lid_sensor_.iio_device_id.has_value())
      SetSensorDeviceMojo(&lid_sensor_, allow_ambient_eq_);

    if (base_sensor_.iio_device_id.has_value())
      SetSensorDeviceMojo(&base_sensor_, /*allow_ambient_eq=*/false);
  }
}

void AmbientLightSensorManagerMojo::SensorServiceDisconnected() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  ResetSensorService();
}

void AmbientLightSensorManagerMojo::ResetSensorService() {
  for (auto& sensor : sensors_)
    sensor->SetDelegate(nullptr);

  for (auto& light : lights_)
    light.second.remote.reset();
}

void AmbientLightSensorManagerMojo::ResetStates() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  for (auto& sensor : sensors_)
    sensor->SetDelegate(nullptr);

  lid_sensor_.iio_device_id = base_sensor_.iio_device_id = std::nullopt;
  lights_.clear();

  QueryDevices();
}

void AmbientLightSensorManagerMojo::QueryDevices() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  sensor_service_handler_->RemoveObserver(this);
  sensor_service_handler_->AddObserver(this);
}

void AmbientLightSensorManagerMojo::OnSensorDeviceDisconnect(
    int32_t id, uint32_t custom_reason_code, const std::string& description) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  const auto reason = static_cast<cros::mojom::SensorDeviceDisconnectReason>(
      custom_reason_code);
  LOG(WARNING) << "OnSensorDeviceDisconnect: " << id << ", reason: " << reason
               << ", description: " << description;

  switch (reason) {
    case cros::mojom::SensorDeviceDisconnectReason::IIOSERVICE_CRASHED:
      ResetSensorService();
      break;

    case cros::mojom::SensorDeviceDisconnectReason::DEVICE_REMOVED:
      if (lid_sensor_.iio_device_id == id || base_sensor_.iio_device_id == id) {
        // Reset usages & states, and restart the mojo devices initialization.
        ResetStates();
      } else {
        // This light sensor is not in use.
        lights_.erase(id);
      }
      break;
  }
}

void AmbientLightSensorManagerMojo::GetNameCallback(
    int32_t id, const std::vector<std::optional<std::string>>& values) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  DCHECK_EQ(num_sensors_, 1);

  auto& light = lights_[id];
  DCHECK(light.remote.is_bound());

  if (values.empty()) {
    LOG(ERROR) << "Sensor values doesn't contain the name attribute.";
    light.ignored = true;
    light.remote.reset();
    return;
  }

  if (values.size() != 1) {
    LOG(WARNING) << "Sensor values contain more than the name attribute. Size: "
                 << values.size();
  }

  light.name = values[0];
  if (light.name.has_value() &&
      light.name.value().compare(kCrosECLightName) == 0) {
    LOG(INFO) << "Using ALS with id: " << id
              << ", name: " << light.name.value();

    lid_sensor_.iio_device_id = base_sensor_.iio_device_id = id;
    auto delegate = AmbientLightSensorDelegateMojo::Create(
        id, std::move(light.remote), allow_ambient_eq_,
        lid_sensor_.closure_for_testing);
    lid_sensor_.sensor->SetDelegate(std::move(delegate));

    // Found cros-ec-light. Other devices are not needed.
    AllDevicesFound();

    return;
  }

  // Not cros-ec-light
  if (!light.name.has_value() ||
      light.name.value().compare(kAcpiAlsName) != 0) {
    LOG(WARNING) << "Unexpected or empty light name: "
                 << light.name.value_or("");
  }

  if (lid_sensor_.iio_device_id.has_value()) {
    VLOG(1) << "Already have another light sensor with name: "
            << lights_[lid_sensor_.iio_device_id.value()].name.value_or("");
    light.ignored = true;
    light.remote.reset();
    return;
  }

  LOG(INFO) << "Using ALS with id: " << id
            << ", name: " << light.name.value_or("null");

  lid_sensor_.iio_device_id = id;
  auto delegate = AmbientLightSensorDelegateMojo::Create(
      id, std::move(light.remote), allow_ambient_eq_,
      lid_sensor_.closure_for_testing);
  lid_sensor_.sensor->SetDelegate(std::move(delegate));
}

void AmbientLightSensorManagerMojo::GetNameAndLocationCallback(
    int32_t id, const std::vector<std::optional<std::string>>& values) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  DCHECK_GE(num_sensors_, 2);

  auto& light = lights_[id];
  DCHECK(light.remote.is_bound());

  if (values.size() < 2) {
    LOG(ERROR) << "Sensor is missing name or location attribute.";
    light.ignored = true;
    light.remote.reset();
    return;
  }

  if (values.size() > 2) {
    LOG(WARNING)
        << "Sensor values contain more than name and location attribute. Size: "
        << values.size();
  }

  light.name = values[0];
  if (!light.name.has_value() ||
      light.name.value().compare(kCrosECLightName) != 0) {
    LOG(ERROR) << "Not " << kCrosECLightName
               << ", sensor name: " << light.name.value_or("");
    light.ignored = true;
    light.remote.reset();
    return;
  }

  const std::optional<std::string>& location = values[1];
  if (!location.has_value()) {
    LOG(WARNING) << "Sensor doesn't have the location attribute: " << id;
    SetSensorDeviceAtLocation(id, SensorLocation::UNKNOWN);
    return;
  }

  if (location.value() == cros::mojom::kLocationLid) {
    SetSensorDeviceAtLocation(id, SensorLocation::LID);
  } else if (location.value() == cros::mojom::kLocationBase) {
    SetSensorDeviceAtLocation(id, SensorLocation::BASE);
  } else {
    LOG(ERROR) << "Invalid sensor " << id << ", location: " << location.value();
    SetSensorDeviceAtLocation(id, SensorLocation::UNKNOWN);
  }
}

void AmbientLightSensorManagerMojo::SetSensorDeviceAtLocation(
    int32_t id, SensorLocation location) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  DCHECK_GE(num_sensors_, 2);

  auto& light = lights_[id];
  DCHECK(!light.location.has_value() || light.location == location);
  light.location = location;

  if (location == SensorLocation::LID &&
      (!lid_sensor_.iio_device_id.has_value() ||
       lid_sensor_.iio_device_id.value() == id)) {
    LOG(INFO) << "Using Lid ALS with id: " << id;

    lid_sensor_.iio_device_id = id;

    auto delegate = AmbientLightSensorDelegateMojo::Create(
        id, std::move(light.remote), allow_ambient_eq_,
        lid_sensor_.closure_for_testing);
    lid_sensor_.sensor->SetDelegate(std::move(delegate));
  } else if (location == SensorLocation::BASE &&
             (!base_sensor_.iio_device_id.has_value() ||
              base_sensor_.iio_device_id.value() == id)) {
    LOG(INFO) << "Using Base ALS with id: " << id;

    base_sensor_.iio_device_id = id;

    auto delegate = AmbientLightSensorDelegateMojo::Create(
        id, std::move(light.remote),
        /*enable_color_support=*/false,  // BASE sensor is not expected to be
                                         // used for AEQ.
        base_sensor_.closure_for_testing);
    base_sensor_.sensor->SetDelegate(std::move(delegate));
  }

  if (lid_sensor_.iio_device_id.has_value() &&
      base_sensor_.iio_device_id.has_value()) {
    // Has found the two cros-ec-lights. Don't need other devices.
    AllDevicesFound();
  }

  light.remote.reset();
}

void AmbientLightSensorManagerMojo::AllDevicesFound() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  // Remove and ignore remaining remotes as they're not needed anymore.
  for (auto& light : lights_) {
    if (!light.second.remote.is_bound())
      continue;

    light.second.ignored = true;
    light.second.remote.reset();
  }
}

void AmbientLightSensorManagerMojo::SetSensorDeviceMojo(Sensor* sensor,
                                                        bool allow_ambient_eq) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  DCHECK(sensor->iio_device_id.has_value());

  mojo::Remote<cros::mojom::SensorDevice> sensor_device_remote;
  sensor_service_handler_->GetDevice(
      sensor->iio_device_id.value(),
      sensor_device_remote.BindNewPipeAndPassReceiver());

  sensor_device_remote.set_disconnect_with_reason_handler(
      base::BindOnce(&AmbientLightSensorManagerMojo::OnSensorDeviceDisconnect,
                     base::Unretained(this), sensor->iio_device_id.value()));

  std::unique_ptr<AmbientLightSensorDelegateMojo> delegate =
      AmbientLightSensorDelegateMojo::Create(
          sensor->iio_device_id.value(), std::move(sensor_device_remote),
          allow_ambient_eq, sensor->closure_for_testing);
  sensor->sensor->SetDelegate(std::move(delegate));
}

}  // namespace power_manager::system
