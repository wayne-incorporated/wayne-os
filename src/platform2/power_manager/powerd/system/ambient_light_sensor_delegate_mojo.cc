// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/powerd/system/ambient_light_sensor_delegate_mojo.h"

#include <fcntl.h>

#include <algorithm>
#include <cmath>
#include <iterator>
#include <map>
#include <optional>
#include <utility>

#include <base/check.h>
#include <base/check_op.h>
#include <base/containers/flat_map.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/strings/stringprintf.h>

namespace power_manager::system {

namespace {

constexpr double kFrequencyInHz = 1.0;

const struct ColorChannelInfo* ChannelIdToColorChannelInfo(
    const std::string& id) {
  for (const ColorChannelInfo& channel : kColorChannelConfig) {
    if (id == AmbientLightSensorDelegateMojo::GetChannelIlluminanceColorId(
                  channel.rgb_name)) {
      return &channel;
    }
  }

  return nullptr;
}

}  // namespace

// static
std::string AmbientLightSensorDelegateMojo::GetChannelIlluminanceColorId(
    const char* rgb_name) {
  return base::StringPrintf("%s_%s", cros::mojom::kLightChannel, rgb_name);
}

// static
std::unique_ptr<AmbientLightSensorDelegateMojo>
AmbientLightSensorDelegateMojo::Create(
    int iio_device_id,
    mojo::Remote<cros::mojom::SensorDevice> remote,
    bool enable_color_support,
    base::OnceClosure init_closure) {
  if (!remote.is_bound())
    return nullptr;

  std::unique_ptr<AmbientLightSensorDelegateMojo> sensor_mojo(
      new AmbientLightSensorDelegateMojo(iio_device_id, std::move(remote),
                                         enable_color_support,
                                         std::move(init_closure)));

  return sensor_mojo;
}

AmbientLightSensorDelegateMojo::~AmbientLightSensorDelegateMojo() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
}

bool AmbientLightSensorDelegateMojo::IsColorSensor() const {
  return color_channels_enabled_;
}

base::FilePath AmbientLightSensorDelegateMojo::GetIlluminancePath() const {
  return base::FilePath();
}

void AmbientLightSensorDelegateMojo::OnSampleUpdated(
    const base::flat_map<int32_t, int64_t>& sample) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  DCHECK(illuminance_index_.has_value());
  DCHECK_LT(illuminance_index_.value(), iio_channel_ids_.size());

  if (!set_lux_callback_)
    return;

  auto it = sample.find(illuminance_index_.value());
  std::optional<int> lux_value, color_temperature;
  if (it == sample.end()) {
    VLOG(2) << "No channel " << cros::mojom::kLightChannel
            << " found in the sample.";
    OnErrorOccurred(cros::mojom::ObserverErrorType::READ_FAILED);
  } else if (it->second < 0) {
    VLOG(2) << "Invalid " << cros::mojom::kLightChannel << ": " << it->second;
    OnErrorOccurred(cros::mojom::ObserverErrorType::READ_FAILED);
  } else {
    lux_value = it->second;

    VLOG(1) << "Read lux " << lux_value.value() << " from channel "
            << iio_channel_ids_[illuminance_index_.value()];

    if (++num_recovery_reads_ == kNumRecoveryReads) {
      num_recovery_reads_ = 0;
      if (num_failed_reads_ > 0)
        --num_failed_reads_;
    }
  }

  if (color_channels_enabled_)
    color_temperature = GetColorTemperature(sample);

  if (lux_value.has_value() || color_temperature.has_value())
    set_lux_callback_.Run(lux_value, color_temperature);
}

void AmbientLightSensorDelegateMojo::OnErrorOccurred(
    cros::mojom::ObserverErrorType type) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  switch (type) {
    case cros::mojom::ObserverErrorType::ALREADY_STARTED:
      LOG(ERROR) << "Device " << iio_device_id_
                 << ": Another observer has already started to read samples";
      Reset();
      break;

    case cros::mojom::ObserverErrorType::FREQUENCY_INVALID:
      LOG(ERROR) << "Device " << iio_device_id_
                 << ": Observer started with an invalid frequency";
      if (sensor_device_remote_.is_bound()) {
        sensor_device_remote_->SetFrequency(
            kFrequencyInHz,
            base::BindOnce(
                &AmbientLightSensorDelegateMojo::SetFrequencyCallback,
                weak_factory_.GetWeakPtr()));
      }
      break;

    case cros::mojom::ObserverErrorType::NO_ENABLED_CHANNELS:
      LOG(ERROR) << "Device " << iio_device_id_
                 << ": Observer started with no channels enabled";
      if (sensor_device_remote_.is_bound()) {
        sensor_device_remote_->SetChannelsEnabled(
            channel_indices_, true,
            base::BindOnce(
                &AmbientLightSensorDelegateMojo::SetChannelsEnabledCallback,
                weak_factory_.GetWeakPtr()));
      }
      break;

    case cros::mojom::ObserverErrorType::SET_FREQUENCY_IO_FAILED:
      LOG(ERROR) << "Device " << iio_device_id_
                 << ": Failed to set frequency to the physical device";
      break;
    case cros::mojom::ObserverErrorType::GET_FD_FAILED:
      LOG(ERROR) << "Device " << iio_device_id_
                 << ": Failed to get the device's fd to poll on";
      break;

    case cros::mojom::ObserverErrorType::READ_FAILED:
      LOG(ERROR) << "Device " << iio_device_id_ << ": Failed to read a sample";
      ReadError();
      break;

    case cros::mojom::ObserverErrorType::READ_TIMEOUT:
      LOG(ERROR) << "Device " << iio_device_id_ << ": A read timed out";
      ReadError();
      break;

    default:
      LOG(ERROR) << "Device " << iio_device_id_ << ": error "
                 << static_cast<int>(type);
      break;
  }
}

AmbientLightSensorDelegateMojo::AmbientLightSensorDelegateMojo(
    int iio_device_id,
    mojo::Remote<cros::mojom::SensorDevice> remote,
    bool enable_color_support,
    base::OnceClosure init_closure)
    : iio_device_id_(iio_device_id),
      sensor_device_remote_(std::move(remote)),
      enable_color_support_(enable_color_support),
      init_closure_(std::move(init_closure)) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  DCHECK(sensor_device_remote_.is_bound());

  if (enable_color_support_) {
    for (const ColorChannelInfo& channel : kColorChannelConfig)
      channel_ids_to_enable_.insert(
          GetChannelIlluminanceColorId(channel.rgb_name));
  }

  // Add the id of the clear channel.
  channel_ids_to_enable_.insert(cros::mojom::kLightChannel);

  GetAllChannelIds();
}

void AmbientLightSensorDelegateMojo::Reset() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  LOG(INFO) << "Resetting AmbientLightSensorDelegateMojo";

  receiver_.reset();
  sensor_device_remote_.reset();

  iio_channel_ids_.clear();
  channel_indices_.clear();
  illuminance_index_.reset();
  color_indices_.clear();

  num_failed_reads_ = 0;
  num_recovery_reads_ = 0;

  FinishInitialization();
}

void AmbientLightSensorDelegateMojo::GetAllChannelIds() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  DCHECK(sensor_device_remote_.is_bound());

  sensor_device_remote_->GetAllChannelIds(
      base::BindOnce(&AmbientLightSensorDelegateMojo::GetAllChannelIdsCallback,
                     weak_factory_.GetWeakPtr()));
}

void AmbientLightSensorDelegateMojo::GetAllChannelIdsCallback(
    const std::vector<std::string>& iio_channel_ids) {
  iio_channel_ids_ = iio_channel_ids;
  channel_indices_.clear();
  illuminance_index_.reset();
  color_indices_.clear();

  for (const auto& channel_id : channel_ids_to_enable_) {
    for (int32_t j = 0; j < iio_channel_ids_.size(); ++j) {
      if (channel_id != iio_channel_ids_[j])
        continue;

      if (!enable_color_support_) {
        illuminance_index_ = j;
        break;
      }

      auto* color_channel_info = ChannelIdToColorChannelInfo(channel_id);
      if (color_channel_info) {
        color_indices_[color_channel_info->type] = j;
      } else {
        // Cannot find the color lux channel, use the clear channel instead.
        illuminance_index_ = j;
      }

      break;
    }
  }

  if (!illuminance_index_.has_value()) {
    LOG(ERROR) << "Lux channel not found";
    Reset();

    return;
  }

  if (enable_color_support_ &&
      color_indices_.size() == std::size(kColorChannelConfig)) {
    for (const auto& color_index : color_indices_)
      channel_indices_.push_back(color_index.second);
  } else {
    enable_color_support_ = false;
  }

  channel_indices_.push_back(illuminance_index_.value());

  StartReading();
}

void AmbientLightSensorDelegateMojo::StartReading() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  DCHECK(sensor_device_remote_.is_bound());

  sensor_device_remote_->SetTimeout(0);
  sensor_device_remote_->SetFrequency(
      kFrequencyInHz,
      base::BindOnce(&AmbientLightSensorDelegateMojo::SetFrequencyCallback,
                     weak_factory_.GetWeakPtr()));

  sensor_device_remote_->SetChannelsEnabled(
      channel_indices_, true,
      base::BindOnce(
          &AmbientLightSensorDelegateMojo::SetChannelsEnabledCallback,
          weak_factory_.GetWeakPtr()));

  sensor_device_remote_->StartReadingSamples(GetRemote());
}

mojo::PendingRemote<cros::mojom::SensorDeviceSamplesObserver>
AmbientLightSensorDelegateMojo::GetRemote() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  auto pending_remote = receiver_.BindNewPipeAndPassRemote();

  receiver_.set_disconnect_handler(
      base::BindOnce(&AmbientLightSensorDelegateMojo::OnObserverDisconnect,
                     weak_factory_.GetWeakPtr()));
  return pending_remote;
}

std::optional<int> AmbientLightSensorDelegateMojo::GetColorValue(
    const base::flat_map<int32_t, int64_t>& sample, ChannelType type) {
  auto it_color_index = color_indices_.find(type);
  if (it_color_index == color_indices_.end())
    return std::nullopt;

  auto it = sample.find(it_color_index->second);
  if (it == sample.end())
    return std::nullopt;

  return it->second;
}

std::optional<int> AmbientLightSensorDelegateMojo::GetColorTemperature(
    const base::flat_map<int32_t, int64_t>& sample) {
  std::map<ChannelType, int> readings;
  for (const ColorChannelInfo& channel : kColorChannelConfig) {
    auto value_opt = GetColorValue(sample, channel.type);
    if (!value_opt.has_value())
      continue;

    readings[channel.type] = value_opt.value();
  }

  return AmbientLightSensorDelegate::CalculateColorTemperature(readings);
}

void AmbientLightSensorDelegateMojo::OnObserverDisconnect() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  LOG(ERROR) << "OnObserverDisconnect error, assuming IIO Service crashes and "
                "waiting for it to relaunch";
  // Don't reset |sensor_device_remote_| so that AmbientLightSensorManager and
  // AmbientLightSensorWatcher can get the disconnection.
  receiver_.reset();
}

void AmbientLightSensorDelegateMojo::SetFrequencyCallback(double result_freq) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  if (result_freq > 0.0)
    return;

  LOG(ERROR) << "Failed to set frequency";
  Reset();
}

void AmbientLightSensorDelegateMojo::SetChannelsEnabledCallback(
    const std::vector<int32_t>& failed_indices) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  DCHECK(illuminance_index_.has_value());

  for (int32_t index : failed_indices) {
    if (index == illuminance_index_.value()) {
      LOG(ERROR) << "Failed to enable " << cros::mojom::kLightChannel
                 << ". Giving up on reading samples";
      Reset();
      return;
    }

    LOG(ERROR) << "Failed to enable channel: " << iio_channel_ids_[index];
  }

  if (enable_color_support_ && failed_indices.empty())
    color_channels_enabled_ = true;

  FinishInitialization();
}

void AmbientLightSensorDelegateMojo::ReadError() {
  if (++num_failed_reads_ < kNumFailedReadsBeforeGivingUp) {
    LOG(ERROR) << "ReadSamples error #" << num_failed_reads_ << " occurred";
    return;
  }

  // reset counts
  num_failed_reads_ = num_recovery_reads_ = 0;

  LOG(ERROR) << "Too many failed reads";
  Reset();
}

void AmbientLightSensorDelegateMojo::FinishInitialization() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  if (init_closure_)
    std::move(init_closure_).Run();
}

}  // namespace power_manager::system
