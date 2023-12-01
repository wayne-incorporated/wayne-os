/*
 * Copyright 2021 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "common/sensor_reader.h"

#include <iterator>
#include <optional>
#include <utility>

#include <base/notreached.h>
#include <base/ranges/algorithm.h>
#include <base/strings/stringprintf.h>

#include "cros-camera/common.h"

namespace cros {

namespace {

constexpr char kChannelFormat[] = "%s_%c";
constexpr char kAxes[SensorReader::kNumberOfAxes] = {'x', 'y', 'z'};

std::string GetChannelPrefix(cros::mojom::DeviceType type) {
  switch (type) {
    case cros::mojom::DeviceType::ACCEL:
      return mojom::kAccelerometerChannel;

    case cros::mojom::DeviceType::ANGLVEL:
      return mojom::kGyroscopeChannel;

    case cros::mojom::DeviceType::GRAVITY:
      return mojom::kGravityChannel;

    default:
      NOTREACHED() << "Unsupported type: " << type;
      return "";
  }
}

}  // namespace

// static
constexpr int SensorReader::kNumberOfAxes;

SensorReader::SensorReader(
    scoped_refptr<base::SingleThreadTaskRunner> ipc_task_runner,
    int32_t iio_device_id,
    cros::mojom::DeviceType type,
    double frequency,
    double scale,
    SamplesObserver* samples_observer,
    mojo::Remote<mojom::SensorDevice> remote)
    : ipc_task_runner_(std::move(ipc_task_runner)),
      iio_device_id_(iio_device_id),
      type_(type),
      frequency_(frequency),
      scale_(scale),
      samples_observer_(samples_observer),
      sensor_device_remote_(std::move(remote)) {
  DCHECK(ipc_task_runner_->BelongsToCurrentThread());
  DCHECK_GT(frequency_, 0.0);
  DCHECK(samples_observer_);

  sensor_device_remote_.set_disconnect_handler(base::BindOnce(
      &SensorReader::OnSensorDeviceDisconnect, weak_ptr_factory_.GetWeakPtr()));

  sensor_device_remote_->GetAllChannelIds(base::BindOnce(
      &SensorReader::GetAllChannelIdsCallback, weak_ptr_factory_.GetWeakPtr()));
}

SensorReader::~SensorReader() {
  DCHECK(ipc_task_runner_->BelongsToCurrentThread());
}

void SensorReader::OnSampleUpdated(
    const base::flat_map<int32_t, int64_t>& sample) {
  DCHECK(ipc_task_runner_->BelongsToCurrentThread());
  DCHECK(timestamp_index_);

  if (sample.size() != kNumberOfAxes + 1) {
    LOGF(ERROR) << "Invalid sample with size: " << sample.size();
    OnErrorOccurred(mojom::ObserverErrorType::READ_FAILED);
    return;
  }

  for (int i = 0; i < kNumberOfAxes; ++i) {
    DCHECK(channel_indices_[i]);
    if (sample.find(*channel_indices_[i]) == sample.end()) {
      LOGF(ERROR) << "Missing channel: " << kAxes[i]
                  << " in sample with device id: " << iio_device_id_;
      OnErrorOccurred(mojom::ObserverErrorType::READ_FAILED);
      return;
    }
  }

  if (sample.find(*timestamp_index_) == sample.end()) {
    LOGF(ERROR) << "Missing channel: " << mojom::kTimestampChannel
                << " in sample with device id: " << iio_device_id_;
    OnErrorOccurred(mojom::ObserverErrorType::READ_FAILED);
    return;
  }

  SamplesObserver::Sample reading_sample;
  reading_sample.x_value = GetScaledValue(sample.at(*channel_indices_[0]));
  reading_sample.y_value = GetScaledValue(sample.at(*channel_indices_[1]));
  reading_sample.z_value = GetScaledValue(sample.at(*channel_indices_[2]));
  // TODO(gwendal): Check the format of the timestamp.
  reading_sample.timestamp = sample.at(*timestamp_index_);

  samples_observer_->OnSampleUpdated(reading_sample);
}

void SensorReader::OnErrorOccurred(mojom::ObserverErrorType type) {
  DCHECK(ipc_task_runner_->BelongsToCurrentThread());

  switch (type) {
    case mojom::ObserverErrorType::ALREADY_STARTED:
      LOGF(ERROR) << "Device " << iio_device_id_
                  << ": Another observer has already started to read samples";
      ResetOnError();
      break;

    case mojom::ObserverErrorType::FREQUENCY_INVALID:
      LOGF(ERROR) << "Device " << iio_device_id_
                  << ": Observer started with an invalid frequency";
      ResetOnError();
      break;

    case mojom::ObserverErrorType::NO_ENABLED_CHANNELS:
      LOGF(ERROR) << "Device " << iio_device_id_
                  << ": Observer started with no channels enabled";
      SetChannelsEnabled();
      break;

    case mojom::ObserverErrorType::SET_FREQUENCY_IO_FAILED:
      LOGF(ERROR) << "Device " << iio_device_id_
                  << ": Failed to set frequency to the physical device";
      break;

    case mojom::ObserverErrorType::GET_FD_FAILED:
      LOGF(ERROR) << "Device " << iio_device_id_
                  << ": Failed to get the device's fd to poll on";
      break;

    case mojom::ObserverErrorType::READ_FAILED:
      LOGF(ERROR) << "Device " << iio_device_id_ << ": Failed to read a sample";
      samples_observer_->OnErrorOccurred(
          SamplesObserver::ErrorType::READ_FAILED);
      break;

    case mojom::ObserverErrorType::READ_TIMEOUT:
      LOGF(ERROR) << "Device " << iio_device_id_ << ": A read timed out";
      break;

    default:
      LOGF(ERROR) << "Device " << iio_device_id_ << ": error " << type;
      break;
  }
}

void SensorReader::ResetOnError() {
  DCHECK(ipc_task_runner_->BelongsToCurrentThread());

  LOGF(ERROR) << "ResetOnError";
  sensor_device_remote_.reset();
  receiver_.reset();
}

double SensorReader::GetScaledValue(int64_t value) {
  DCHECK(ipc_task_runner_->BelongsToCurrentThread());

  return value * scale_;
}

void SensorReader::OnSensorDeviceDisconnect() {
  DCHECK(ipc_task_runner_->BelongsToCurrentThread());

  LOGF(ERROR) << "SensorDevice disconnected with id: " << iio_device_id_
              << ", and type: " << type_;

  ResetOnError();
}

void SensorReader::GetAllChannelIdsCallback(
    const std::vector<std::string>& iio_channel_ids) {
  DCHECK(ipc_task_runner_->BelongsToCurrentThread());
  DCHECK(sensor_device_remote_.is_bound());

  std::string prefix = GetChannelPrefix(type_);
  for (int i = 0; i < kNumberOfAxes; ++i) {
    std::string channel =
        base::StringPrintf(kChannelFormat, prefix.c_str(), kAxes[i]);

    auto it = base::ranges::find(iio_channel_ids, channel);
    if (it == iio_channel_ids.end()) {
      LOGF(ERROR) << "Missing channel: " << channel;
      samples_observer_->OnErrorOccurred(
          SamplesObserver::ErrorType::INVALID_ARGUMENT);
      ResetOnError();
      return;
    }

    channel_indices_[i] = std::distance(iio_channel_ids.begin(), it);
  }

  auto it = base::ranges::find(iio_channel_ids, mojom::kTimestampChannel);
  if (it == iio_channel_ids.end()) {
    LOGF(ERROR) << "Missing channel: " << mojom::kTimestampChannel;
    samples_observer_->OnErrorOccurred(
        SamplesObserver::ErrorType::INVALID_ARGUMENT);
    ResetOnError();
    return;
  }

  timestamp_index_ = std::distance(iio_channel_ids.begin(), it);

  SetChannelsEnabled();
}

void SensorReader::SetChannelsEnabled() {
  DCHECK(ipc_task_runner_->BelongsToCurrentThread());
  DCHECK(timestamp_index_);

  std::vector<int32_t> indices;
  for (int i = 0; i < kNumberOfAxes; ++i) {
    DCHECK(channel_indices_[i]);
    indices.push_back(*channel_indices_[i]);
  }

  indices.push_back(*timestamp_index_);

  sensor_device_remote_->SetChannelsEnabled(
      indices, true,
      base::BindOnce(&SensorReader::SetChannelsEnabledCallback,
                     weak_ptr_factory_.GetWeakPtr()));

  sensor_device_remote_->SetFrequency(
      frequency_, base::BindOnce(&SensorReader::SetFrequencyCallback,
                                 weak_ptr_factory_.GetWeakPtr()));
  sensor_device_remote_->StartReadingSamples(
      receiver_.BindNewPipeAndPassRemote());
}

void SensorReader::SetChannelsEnabledCallback(
    const std::vector<int32_t>& failed_indices) {
  DCHECK(ipc_task_runner_->BelongsToCurrentThread());
  DCHECK(timestamp_index_);

  if (failed_indices.empty()) {
    return;
  }

  samples_observer_->OnErrorOccurred(
      SamplesObserver::ErrorType::INVALID_ARGUMENT);

  for (int32_t index : failed_indices) {
    std::optional<std::string> channel = std::nullopt;
    if (index == *timestamp_index_) {
      channel = mojom::kTimestampChannel;
    } else {
      std::string prefix = GetChannelPrefix(type_);
      for (int i = 0; i < kNumberOfAxes; ++i) {
        DCHECK(channel_indices_[i]);
        if (index == *channel_indices_[i]) {
          channel =
              base::StringPrintf(kChannelFormat, prefix.c_str(), kAxes[i]);
          break;
        }
      }
    }

    if (channel) {
      LOGF(ERROR) << "Failed to enable channel " << *channel
                  << ", in device with id: " << iio_device_id_;
    } else {
      LOGF(ERROR) << "Failed to enable channel with index: " << index
                  << ", in device with id: " << iio_device_id_;
    }
  }

  ResetOnError();
}

void SensorReader::SetFrequencyCallback(double result_freq) {
  DCHECK(ipc_task_runner_->BelongsToCurrentThread());
  if (result_freq > 0.0) {
    return;
  }

  samples_observer_->OnErrorOccurred(
      SamplesObserver::ErrorType::INVALID_ARGUMENT);

  LOGF(ERROR) << "SetFrequency failed. Target frequency: " << frequency_
              << ", result requency: " << result_freq;
  ResetOnError();
}

}  // namespace cros
