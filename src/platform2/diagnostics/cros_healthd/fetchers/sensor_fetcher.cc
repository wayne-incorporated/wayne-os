// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/fetchers/sensor_fetcher.h"

#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <base/files/file_util.h>
#include <chromeos/ec/ec_commands.h>
#include <iioservice/mojo/sensor.mojom.h>

#include "diagnostics/cros_healthd/utils/callback_barrier.h"
#include "diagnostics/cros_healthd/utils/error_utils.h"

namespace diagnostics {

namespace {

namespace mojom = ::ash::cros_healthd::mojom;

// Relative filepath used to determine whether a device has a Google EC.
constexpr char kRelativeCrosEcPath[] = "sys/class/chromeos/cros_ec";

// The target sensor attributes to fetch.
const std::vector<std::string> kTargetSensorAttributes_ = {
    cros::mojom::kDeviceName, cros::mojom::kLocation};

// Filter for the sensor type we want and convert it to mojom::Sensor::Type.
std::vector<mojom::Sensor::Type> GetSupportedTypes(
    const std::vector<cros::mojom::DeviceType>& types) {
  std::vector<mojom::Sensor::Type> out_types;

  for (const auto& type : types) {
    switch (type) {
      case cros::mojom::DeviceType::ACCEL:
        out_types.push_back(mojom::Sensor::Type::kAccel);
        break;
      case cros::mojom::DeviceType::LIGHT:
        out_types.push_back(mojom::Sensor::Type::kLight);
        break;
      case cros::mojom::DeviceType::ANGLVEL:
        out_types.push_back(mojom::Sensor::Type::kGyro);
        break;
      case cros::mojom::DeviceType::ANGL:
        out_types.push_back(mojom::Sensor::Type::kAngle);
        break;
      case cros::mojom::DeviceType::GRAVITY:
        out_types.push_back(mojom::Sensor::Type::kGravity);
        break;
      case cros::mojom::DeviceType::MAGN:
        out_types.push_back(mojom::Sensor::Type::kMagn);
        break;
      default:
        // Ignore other sensor types.
        LOG(ERROR) << "Unsupport sensor device type: " << type;
        break;
    }
  }
  return out_types;
}

// Convert the location string to mojom::Sensor::Location.
mojom::Sensor::Location ConvertLocation(
    const std::optional<std::string>& location) {
  if (location.has_value()) {
    if (location.value() == cros::mojom::kLocationBase)
      return mojom::Sensor::Location::kBase;
    else if (location.value() == cros::mojom::kLocationLid)
      return mojom::Sensor::Location::kLid;
    else if (location.value() == cros::mojom::kLocationCamera)
      return mojom::Sensor::Location::kCamera;
  }
  return mojom::Sensor::Location::kUnknown;
}

class State {
 public:
  explicit State(MojoService* mojo_service);
  State(const State&) = delete;
  State& operator=(const State&) = delete;
  ~State() = default;

  // Handle the response of sensor id and types from the sensor service.
  void HandleSensorIdsTypesResponse(
      base::OnceClosure completion_callback,
      const base::flat_map<int32_t, std::vector<cros::mojom::DeviceType>>&
          ids_types);

  // Handle the response of sensor attributes from the sensor device.
  void HandleAttributesResponse(
      int32_t id,
      const std::vector<mojom::Sensor::Type>& types,
      const std::vector<std::optional<std::string>>& attributes);

  // Handle the response of lid angle from the executor.
  void HandleLidAngleResponse(std::optional<uint16_t> lid_angle);

  // Send back the SensorResult via |callback|. The result is ProbeError if
  // |error_| is not null or |is_finished| is false, otherwise |info_|.
  void HandleResult(FetchSensorInfoCallback callback, bool is_finished);

 private:
  // Used to get sensor devices.
  MojoService* const mojo_service_;
  // The info to be returned.
  mojom::SensorInfoPtr info_;
  // The error to be returned.
  mojom::ProbeErrorPtr error_;
};

State::State(MojoService* mojo_service)
    : mojo_service_(mojo_service), info_(mojom::SensorInfo::New()) {
  info_->sensors = std::vector<mojom::SensorPtr>{};
}

void State::HandleSensorIdsTypesResponse(
    base::OnceClosure completion_callback,
    const base::flat_map<int32_t, std::vector<cros::mojom::DeviceType>>&
        ids_types) {
  CallbackBarrier barrier{/*on_success=*/std::move(completion_callback),
                          /*on_error=*/base::DoNothing()};
  for (const auto& [sensor_id, sensor_types] : ids_types) {
    auto types = GetSupportedTypes(sensor_types);
    if (types.size() == 0)
      continue;

    mojo_service_->GetSensorDevice(sensor_id)->GetAttributes(
        kTargetSensorAttributes_,
        barrier.Depend(base::BindOnce(&State::HandleAttributesResponse,
                                      base::Unretained(this), sensor_id,
                                      types)));
  }
}

void State::HandleAttributesResponse(
    int32_t id,
    const std::vector<mojom::Sensor::Type>& types,
    const std::vector<std::optional<std::string>>& attributes) {
  if (attributes.size() != kTargetSensorAttributes_.size()) {
    error_ = CreateAndLogProbeError(mojom::ErrorType::kParseError,
                                    "Failed to get valid sensor attributes.");
    return;
  }
  for (const auto& type : types) {
    info_->sensors->push_back(mojom::Sensor::New(
        attributes[0], id, type, ConvertLocation(attributes[1])));
  }
}

void State::HandleLidAngleResponse(std::optional<uint16_t> lid_angle) {
  if (!lid_angle.has_value()) {
    error_ = CreateAndLogProbeError(mojom::ErrorType::kSystemUtilityError,
                                    "Failed to get lid angle.");
    return;
  }
  const auto& value = lid_angle.value();
  if (value == LID_ANGLE_UNRELIABLE) {
    return;
  } else if (value > 360) {
    error_ = CreateAndLogProbeError(mojom::ErrorType::kSystemUtilityError,
                                    "Get invalid lid angle.");
    return;
  }
  info_->lid_angle = mojom::NullableUint16::New(value);
}

void State::HandleResult(FetchSensorInfoCallback callback, bool is_finished) {
  if (!is_finished) {
    error_ = CreateAndLogProbeError(mojom::ErrorType::kSystemUtilityError,
                                    "Failed to finish all callbacks.");
  }

  if (!error_.is_null()) {
    std::move(callback).Run(mojom::SensorResult::NewError(std::move(error_)));
    return;
  }
  std::move(callback).Run(mojom::SensorResult::NewSensorInfo(std::move(info_)));
}

}  // namespace

void FetchSensorInfo(Context* context, FetchSensorInfoCallback callback) {
  auto* mojo_service = context->mojo_service();
  auto state = std::make_unique<State>(mojo_service);
  State* state_ptr = state.get();
  CallbackBarrier barrier{base::BindOnce(&State::HandleResult, std::move(state),
                                         std::move(callback))};

  // Get sensors' attributes.
  mojo_service->GetSensorService()->GetAllDeviceIds(
      barrier.Depend(base::BindOnce(&State::HandleSensorIdsTypesResponse,
                                    base::Unretained(state_ptr),
                                    barrier.CreateDependencyClosure())));

  // Devices without a Google EC, and therefore ectool, cannot obtain lid angle.
  if (base::PathExists(context->root_dir().Append(kRelativeCrosEcPath))) {
    context->executor()->GetLidAngle(barrier.Depend(base::BindOnce(
        &State::HandleLidAngleResponse, base::Unretained(state_ptr))));
  }
}

}  // namespace diagnostics
