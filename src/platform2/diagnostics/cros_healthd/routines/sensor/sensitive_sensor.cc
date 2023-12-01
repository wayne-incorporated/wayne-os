// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/routines/sensor/sensitive_sensor.h"

#include <algorithm>
#include <memory>
#include <numeric>
#include <string>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/check_op.h>
#include <base/functional/bind.h>
#include <base/json/json_writer.h>
#include <base/logging.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <base/task/single_thread_task_runner.h>

#include "diagnostics/base/mojo_utils.h"

namespace diagnostics {
namespace {

namespace mojom = ::ash::cros_healthd::mojom;

constexpr double kSampleReadingFrequency = 5;
constexpr char kChannelAxes[] = {'x', 'y', 'z'};
constexpr char kOutputDictPassedSensorsKey[] = "passed_sensors";
constexpr char kOutputDictFailedSensorsKey[] = "failed_sensors";
constexpr char kOutputDictExistenceCheckResultKey[] = "existence_check_result";

// This routine only supports accelerometers, gyro sensors, gravity sensors and
// magnetometers.
std::vector<cros::mojom::DeviceType> FilterSupportedTypes(
    std::vector<cros::mojom::DeviceType> types) {
  auto is_supported_type = [](cros::mojom::DeviceType type) {
    switch (type) {
      case cros::mojom::DeviceType::ACCEL:
      case cros::mojom::DeviceType::ANGLVEL:
      case cros::mojom::DeviceType::GRAVITY:
      case cros::mojom::DeviceType::MAGN:
        return true;
      default:
        return false;
    }
  };
  std::vector<cros::mojom::DeviceType> supported_types;
  std::copy_if(types.begin(), types.end(), std::back_inserter(supported_types),
               is_supported_type);
  return supported_types;
}

// Convert sensor device type enum to string.
std::string ConverDeviceTypeToString(cros::mojom::DeviceType type) {
  switch (type) {
    case cros::mojom::DeviceType::ACCEL:
      return kSensitiveSensorRoutineTypeAccel;
    case cros::mojom::DeviceType::ANGLVEL:
      return kSensitiveSensorRoutineTypeGyro;
    case cros::mojom::DeviceType::GRAVITY:
      return kSensitiveSensorRoutineTypeGravity;
    case cros::mojom::DeviceType::MAGN:
      return kSensitiveSensorRoutineTypeMagn;
    default:
      // The other sensor types are not supported in this routine.
      NOTREACHED_NORETURN();
  }
}

// Convert sensor device type enum to channel prefix.
std::string ConvertDeviceTypeToChannelPrefix(cros::mojom::DeviceType type) {
  switch (type) {
    case cros::mojom::DeviceType::ACCEL:
      return cros::mojom::kAccelerometerChannel;
    case cros::mojom::DeviceType::ANGLVEL:
      return cros::mojom::kGyroscopeChannel;
    case cros::mojom::DeviceType::GRAVITY:
      return cros::mojom::kGravityChannel;
    case cros::mojom::DeviceType::MAGN:
      return cros::mojom::kMagnetometerChannel;
    default:
      // The other sensor types are not supported in this routine.
      NOTREACHED_NORETURN();
  }
}

// Get required channels for each sensor type.
std::vector<std::string> GetRequiredChannels(
    std::vector<cros::mojom::DeviceType> types) {
  std::vector<std::string> channels = {cros::mojom::kTimestampChannel};
  for (auto type : types) {
    auto channel_prefix = ConvertDeviceTypeToChannelPrefix(type);
    for (char axis : kChannelAxes)
      channels.push_back(channel_prefix + "_" + axis);
  }
  return channels;
}

// Convert the enum to readable string.
std::string Convert(SensorType sensor) {
  switch (sensor) {
    case SensorType::kBaseAccelerometer:
      return "base_accelerometer";
    case SensorType::kBaseGyroscope:
      return "base_gyroscope";
    case SensorType::kBaseMagnetometer:
      return "base_magnetometer";
    case SensorType::kBaseGravitySensor:
      return "base_gravity_sensor";
    case SensorType::kLidAccelerometer:
      return "lid_accelerometer";
    case SensorType::kLidGyroscope:
      return "lid_gyroscope";
    case SensorType::kLidMagnetometer:
      return "lid_magnetometer";
    case SensorType::kLidGravitySensor:
      return "lid_gravity_sensor";
  }
}

// Convert the enum to readable string.
std::string Convert(SensorExistenceChecker::Result::State state) {
  switch (state) {
    case SensorExistenceChecker::Result::State::kPassed:
      return "passed";
    case SensorExistenceChecker::Result::State::kSkipped:
      return "skipped";
    case SensorExistenceChecker::Result::State::kMissing:
      return "missing";
    case SensorExistenceChecker::Result::State::kUnexpected:
      return "unexpected";
  }
}

}  // namespace

void SensitiveSensorRoutine::SensorDetail::UpdateChannelSample(int32_t indice,
                                                               int64_t value) {
  // Passed channels are removed from |checking_channel_sample|.
  if (checking_channel_sample.find(indice) == checking_channel_sample.end())
    return;

  // First sample data for the channel.
  if (!checking_channel_sample[indice].has_value()) {
    checking_channel_sample[indice] = value;
    return;
  }

  // Remove channel when changed sample is found.
  if (value != checking_channel_sample[indice].value()) {
    checking_channel_sample.erase(indice);
  }
}

base::Value::Dict SensitiveSensorRoutine::SensorDetail::GetDetailValue(
    int32_t id) {
  base::Value::Dict sensor_output;
  sensor_output.Set("id", id);
  base::Value::List out_types;
  for (const auto& type : types)
    out_types.Append(ConverDeviceTypeToString(type));
  sensor_output.Set("types", std::move(out_types));
  base::Value::List out_channels;
  if (channels.has_value())
    for (const auto& channel_name : channels.value())
      out_channels.Append(channel_name);
  sensor_output.Set("channels", std::move(out_channels));
  return sensor_output;
}

SensitiveSensorRoutine::SensitiveSensorRoutine(
    MojoService* const mojo_service, SystemConfigInterface* const system_config)
    : mojo_service_(mojo_service),
      sensor_checker_{mojo_service, system_config} {
  DCHECK(mojo_service);

  observer_receiver_set_.set_disconnect_handler(base::BindRepeating(
      []() { LOG(ERROR) << "Observer connection closed"; }));
}

SensitiveSensorRoutine::~SensitiveSensorRoutine() = default;

void SensitiveSensorRoutine::Start() {
  DCHECK_EQ(GetStatus(), mojom::DiagnosticRoutineStatusEnum::kReady);

  start_ticks_ = base::TimeTicks::Now();

  mojo_service_->GetSensorService()->GetAllDeviceIds(
      base::BindOnce(&SensitiveSensorRoutine::HandleGetAllDeviceIdsResponse,
                     weak_ptr_factory_.GetWeakPtr()));
  UpdateStatus(mojom::DiagnosticRoutineStatusEnum::kRunning,
               kSensitiveSensorRoutineRunningMessage);

  base::SingleThreadTaskRunner::GetCurrentDefault()->PostDelayedTask(
      FROM_HERE,
      base::BindOnce(&SensitiveSensorRoutine::OnTimeoutOccurred,
                     weak_ptr_factory_.GetWeakPtr()),
      kSensitiveSensorRoutineTimeout);
}

void SensitiveSensorRoutine::Resume() {
  LOG(ERROR) << "Sensitive sensor routine cannot be resumed";
}

void SensitiveSensorRoutine::Cancel() {
  LOG(ERROR) << "Sensitive sensor routine cannot be cancelled";
}

void SensitiveSensorRoutine::PopulateStatusUpdate(
    mojom::RoutineUpdate* response, bool include_output) {
  DCHECK(response);

  auto status = GetStatus();

  response->routine_update_union =
      mojom::RoutineUpdateUnion::NewNoninteractiveUpdate(
          mojom::NonInteractiveRoutineUpdate::New(status, GetStatusMessage()));

  if (include_output) {
    base::Value::Dict output_dict;
    for (const auto& [sensor, result] : existence_check_result_) {
      output_dict.Set(Convert(sensor), ConstructSensorOutput(sensor));
    }
    std::string json;
    base::JSONWriter::Write(output_dict, &json);
    response->output = CreateReadOnlySharedMemoryRegionMojoHandle(json);
  }

  // The routine is finished.
  if (status == mojom::DiagnosticRoutineStatusEnum::kPassed ||
      status == mojom::DiagnosticRoutineStatusEnum::kFailed ||
      status == mojom::DiagnosticRoutineStatusEnum::kError) {
    response->progress_percent = 100;
    return;
  }

  // The routine is not started.
  if (status == mojom::DiagnosticRoutineStatusEnum::kReady) {
    response->progress_percent = 0;
    return;
  }

  double tested_sensor_percent = 0;
  int total_sensor_num =
      passed_sensors_.size() + pending_sensors_.size() + failed_sensors_.size();
  if (total_sensor_num != 0) {
    tested_sensor_percent =
        100.0 * (total_sensor_num - pending_sensors_.size()) / total_sensor_num;
  }
  double running_time_ratio =
      (base::TimeTicks::Now() - start_ticks_) / kSensitiveSensorRoutineTimeout;
  response->progress_percent =
      tested_sensor_percent +
      (100.0 - tested_sensor_percent) * std::min(1.0, running_time_ratio);
}

void SensitiveSensorRoutine::HandleGetAllDeviceIdsResponse(
    const base::flat_map<int32_t, std::vector<cros::mojom::DeviceType>>&
        ids_types) {
  sensor_checker_.VerifySensorInfo(
      ids_types,
      base::BindOnce(&SensitiveSensorRoutine::HandleVerificationResponse,
                     weak_ptr_factory_.GetWeakPtr(), ids_types));
}

void SensitiveSensorRoutine::HandleVerificationResponse(
    const base::flat_map<int32_t, std::vector<cros::mojom::DeviceType>>&
        ids_types,
    std::map<SensorType, SensorExistenceChecker::Result>
        existence_check_result) {
  existence_check_result_ = std::move(existence_check_result);
  if (existence_check_result_.empty()) {
    SetResultAndStop(mojom::DiagnosticRoutineStatusEnum::kError,
                     kSensitiveSensorRoutineFailedUnexpectedlyMessage);
    return;
  }

  for (const auto& [sensor_id, sensor_types] : ids_types) {
    auto types = FilterSupportedTypes(sensor_types);
    if (types.empty())
      continue;

    pending_sensors_[sensor_id] = {.types = types};
    InitSensorDevice(sensor_id);
  }
  if (pending_sensors_.empty())
    OnRoutineFinished();
}

void SensitiveSensorRoutine::InitSensorDevice(int32_t sensor_id) {
  mojo_service_->GetSensorDevice(sensor_id)->SetFrequency(
      kSampleReadingFrequency,
      base::BindOnce(&SensitiveSensorRoutine::HandleFrequencyResponse,
                     weak_ptr_factory_.GetWeakPtr(), sensor_id));
}

void SensitiveSensorRoutine::HandleFrequencyResponse(int32_t sensor_id,
                                                     double frequency) {
  if (frequency <= 0.0) {
    LOG(ERROR) << "Failed to set frequency on sensor with id: " << sensor_id;
    failed_sensors_[sensor_id] =
        pending_sensors_[sensor_id].GetDetailValue(sensor_id);
    SetResultAndStop(mojom::DiagnosticRoutineStatusEnum::kError,
                     kSensitiveSensorRoutineFailedUnexpectedlyMessage);
    return;
  }

  mojo_service_->GetSensorDevice(sensor_id)->GetAllChannelIds(
      base::BindOnce(&SensitiveSensorRoutine::HandleChannelIdsResponse,
                     weak_ptr_factory_.GetWeakPtr(), sensor_id));
}

void SensitiveSensorRoutine::HandleChannelIdsResponse(
    int32_t sensor_id, const std::vector<std::string>& channels) {
  pending_sensors_[sensor_id].channels = channels;
  std::vector<int32_t> channel_indices;
  for (auto required_channel :
       GetRequiredChannels(pending_sensors_[sensor_id].types)) {
    auto it = std::find(channels.begin(), channels.end(), required_channel);
    if (it == channels.end()) {
      LOG(ERROR) << "Failed to get required channels on sensor with id: "
                 << sensor_id;
      failed_sensors_[sensor_id] =
          pending_sensors_[sensor_id].GetDetailValue(sensor_id);
      SetResultAndStop(mojom::DiagnosticRoutineStatusEnum::kError,
                       kSensitiveSensorRoutineFailedUnexpectedlyMessage);
      return;
    }

    int32_t indice = it - channels.begin();
    channel_indices.push_back(indice);
    // Set the indeice of required channel to check samples.
    pending_sensors_[sensor_id].checking_channel_sample[indice] = std::nullopt;
  }

  mojo_service_->GetSensorDevice(sensor_id)->SetChannelsEnabled(
      channel_indices, true,
      base::BindOnce(&SensitiveSensorRoutine::HandleSetChannelsEnabledResponse,
                     weak_ptr_factory_.GetWeakPtr(), sensor_id));
}

void SensitiveSensorRoutine::HandleSetChannelsEnabledResponse(
    int32_t sensor_id, const std::vector<int32_t>& failed_indices) {
  if (!failed_indices.empty()) {
    LOG(ERROR) << "Failed to set channels enabled on sensor with id: "
               << sensor_id;
    failed_sensors_[sensor_id] =
        pending_sensors_[sensor_id].GetDetailValue(sensor_id);
    SetResultAndStop(mojom::DiagnosticRoutineStatusEnum::kError,
                     kSensitiveSensorRoutineFailedUnexpectedlyMessage);
    return;
  }

  auto remote = mojo::PendingRemote<cros::mojom::SensorDeviceSamplesObserver>();
  observer_receiver_set_.Add(this, remote.InitWithNewPipeAndPassReceiver(),
                             sensor_id);
  mojo_service_->GetSensorDevice(sensor_id)->StartReadingSamples(
      std::move(remote));
}

void SensitiveSensorRoutine::OnSampleUpdated(
    const base::flat_map<int32_t, int64_t>& sample) {
  const auto& sensor_id = observer_receiver_set_.current_context();
  auto& sensor = pending_sensors_[sensor_id];

  for (auto channel : sample)
    sensor.UpdateChannelSample(channel.first, channel.second);

  // All channels have finished checking.
  if (sensor.checking_channel_sample.empty()) {
    mojo_service_->GetSensorDevice(sensor_id)->StopReadingSamples();

    // Store detail of passed sensor.
    passed_sensors_[sensor_id] = sensor.GetDetailValue(sensor_id);
    pending_sensors_.erase(sensor_id);
    observer_receiver_set_.Remove(observer_receiver_set_.current_receiver());
    if (pending_sensors_.empty())
      OnRoutineFinished();
  }
}

void SensitiveSensorRoutine::OnErrorOccurred(
    cros::mojom::ObserverErrorType type) {
  const auto& id = observer_receiver_set_.current_context();
  LOG(ERROR) << "Observer error occurred while reading sample: " << type
             << ", sensor id: " << id;
  failed_sensors_[id] = pending_sensors_[id].GetDetailValue(id);
  SetResultAndStop(mojom::DiagnosticRoutineStatusEnum::kError,
                   kSensitiveSensorRoutineFailedUnexpectedlyMessage);
}

void SensitiveSensorRoutine::OnTimeoutOccurred() {
  // No pending sensors, or number of pending sensors is inconsistent.
  if (pending_sensors_.empty() ||
      pending_sensors_.size() != observer_receiver_set_.size()) {
    LOG(ERROR) << "Mojo connection lost between Healthd and Iioservice";
    SetResultAndStop(mojom::DiagnosticRoutineStatusEnum::kError,
                     kSensitiveSensorRoutineFailedUnexpectedlyMessage);
    return;
  }

  // Sensor failed to pass the routine.
  for (const auto& [sensor_id, _] : pending_sensors_) {
    mojo_service_->GetSensorDevice(sensor_id)->StopReadingSamples();

    // Store detail of failed sensor.
    failed_sensors_[sensor_id] =
        pending_sensors_[sensor_id].GetDetailValue(sensor_id);
  }
  OnRoutineFinished();
}

void SensitiveSensorRoutine::OnRoutineFinished() {
  for (const auto& [_, result] : existence_check_result_) {
    if (result.state == SensorExistenceChecker::Result::kMissing ||
        result.state == SensorExistenceChecker::Result::kUnexpected) {
      SetResultAndStop(mojom::DiagnosticRoutineStatusEnum::kError,
                       kSensitiveSensorRoutineFailedCheckConfigMessage);
      return;
    }
  }
  if (failed_sensors_.empty()) {
    SetResultAndStop(mojom::DiagnosticRoutineStatusEnum::kPassed,
                     kSensitiveSensorRoutinePassedMessage);
  } else {
    SetResultAndStop(mojom::DiagnosticRoutineStatusEnum::kFailed,
                     kSensitiveSensorRoutineFailedMessage);
  }
}

void SensitiveSensorRoutine::SetResultAndStop(
    mojom::DiagnosticRoutineStatusEnum status, std::string status_message) {
  // Cancel all pending callbacks.
  weak_ptr_factory_.InvalidateWeakPtrs();
  // Clear sensor observers.
  observer_receiver_set_.Clear();
  UpdateStatus(status, std::move(status_message));
}

base::Value::Dict SensitiveSensorRoutine::ConstructSensorOutput(
    SensorType sensor) {
  base::Value::Dict sensor_dict;
  base::Value::List passed_sensors, failed_sensors;
  const auto& result = existence_check_result_[sensor];
  sensor_dict.Set(kOutputDictExistenceCheckResultKey, Convert(result.state));
  for (const auto& sensor_id : result.sensor_ids) {
    if (passed_sensors_.count(sensor_id))
      passed_sensors.Append(passed_sensors_[sensor_id].Clone());
    if (failed_sensors_.count(sensor_id))
      failed_sensors.Append(failed_sensors_[sensor_id].Clone());
  }
  sensor_dict.Set(kOutputDictPassedSensorsKey, std::move(passed_sensors));
  sensor_dict.Set(kOutputDictFailedSensorsKey, std::move(failed_sensors));
  return sensor_dict;
}

}  // namespace diagnostics
