// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "rmad/utils/iio_ec_sensor_utils_impl.h"

#include <numeric>
#include <utility>

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/process/launch.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_util.h>
#include <re2/re2.h>

namespace {

constexpr int kMaxNumEntries = 1024;
constexpr int kTimeoutOverheadInMS = 1000;
constexpr double kSecond2Millisecond = 1000.0;
constexpr int kNumberFirstReadsDiscarded = 10;

constexpr char kIioDevicePathPrefix[] = "/sys/bus/iio/devices/iio:device";
constexpr char kIioDeviceEntryName[] = "name";
constexpr char kIioDeviceEntryLocation[] = "location";
constexpr char kIioDeviceEntryFrequencyAvailable[] =
    "sampling_frequency_available";
constexpr char kIioDeviceEntryScale[] = "scale";

}  // namespace

namespace rmad {

IioEcSensorUtilsImpl::IioEcSensorUtilsImpl(
    scoped_refptr<MojoServiceUtils> mojo_service,
    const std::string& location,
    const std::string& name)
    : IioEcSensorUtils(location, name),
      sysfs_prefix_(kIioDevicePathPrefix),
      initialized_(false),
      mojo_service_(mojo_service) {
  Initialize();
}

IioEcSensorUtilsImpl::IioEcSensorUtilsImpl(
    scoped_refptr<MojoServiceUtils> mojo_service,
    const std::string& location,
    const std::string& name,
    const std::string& sysfs_prefix)
    : IioEcSensorUtils(location, name),
      sysfs_prefix_(sysfs_prefix),
      initialized_(false),
      mojo_service_(mojo_service) {
  Initialize();
}

bool IioEcSensorUtilsImpl::GetAvgData(GetAvgDataCallback result_callback,
                                      const std::vector<std::string>& channels,
                                      int samples) {
  CHECK_GT(channels.size(), 0);
  CHECK_GT(samples, 0);

  // Bind callback for OnSampleUpdated.
  get_avg_data_result_callback_ = std::move(result_callback);

  if (!initialized_) {
    LOG(ERROR) << location_ << ":" << name_ << " is not initialized.";
    return false;
  }

  target_channels_ = channels;
  sample_times_ = samples;
  samples_to_discard_ = kNumberFirstReadsDiscarded;
  sampled_data_.clear();

  mojo_service_->GetSensorDevice(id_)->GetAllChannelIds(
      base::BindOnce(&IioEcSensorUtilsImpl::HandleGetAllChannelIds,
                     weak_ptr_factory_.GetMutableWeakPtr()));

  return true;
}

bool IioEcSensorUtilsImpl::GetSysValues(const std::vector<std::string>& entries,
                                        std::vector<double>* values) const {
  if (!initialized_) {
    LOG(ERROR) << location_ << ":" << name_ << " is not initialized.";
    return false;
  }

  std::vector<double> buffer_values;
  for (int i = 0; i < entries.size(); i++) {
    auto entry = sysfs_path_.Append(entries[i]);
    double val = 0.0;
    if (std::string str_val;
        !base::PathExists(entry) || !base::ReadFileToString(entry, &str_val) ||
        !base::StringToDouble(
            base::TrimWhitespaceASCII(str_val, base::TRIM_ALL), &val)) {
      LOG(ERROR) << "Failed to read sys value at " << entry;
      return false;
    }
    buffer_values.push_back(val);
  }

  *values = buffer_values;
  return true;
}

void IioEcSensorUtilsImpl::Initialize() {
  for (int i = 0; i < kMaxNumEntries; i++) {
    base::FilePath sysfs_path(sysfs_prefix_ + base::NumberToString(i));
    if (!base::PathExists(sysfs_path)) {
      break;
    }

    if (InitializeFromSysfsPath(sysfs_path)) {
      id_ = i;
      sysfs_path_ = sysfs_path;
      initialized_ = true;
      break;
    }
  }
}

bool IioEcSensorUtilsImpl::InitializeFromSysfsPath(
    const base::FilePath& sysfs_path) {
  CHECK(base::PathExists(sysfs_path));

  base::FilePath entry_name = sysfs_path.Append(kIioDeviceEntryName);
  if (std::string buf;
      !base::PathExists(entry_name) ||
      !base::ReadFileToString(entry_name, &buf) ||
      name_ != base::TrimWhitespaceASCII(buf, base::TRIM_TRAILING)) {
    return false;
  }

  base::FilePath entry_location = sysfs_path.Append(kIioDeviceEntryLocation);
  if (std::string buf;
      !base::PathExists(entry_location) ||
      !base::ReadFileToString(entry_location, &buf) ||
      location_ != base::TrimWhitespaceASCII(buf, base::TRIM_TRAILING)) {
    return false;
  }

  // For the sensor to work properly, we should set it according to one of its
  // available sampling frequencies. Since all available frequencies should
  // work, we will use the fastest frequency for calibration to save time.
  base::FilePath entry_frequency_available =
      sysfs_path.Append(kIioDeviceEntryFrequencyAvailable);
  std::string frequency_available;
  if (!base::PathExists(entry_frequency_available) ||
      !base::ReadFileToString(entry_frequency_available,
                              &frequency_available)) {
    return false;
  }
  // The value from sysfs could be one of:
  // 1. A set of small discrete values, such as "0 2 4 6 8".
  // 2. A range "[min min_step max]", where steps are not linear but power of 2.
  frequency_ = 0;
  re2::StringPiece str_piece(frequency_available);
  // Currently, we only used the highest frequency.
  re2::RE2 reg(R"((\d+(\.\d+)?)\s*$)");
  std::string match;
  if (double freq; RE2::FindAndConsume(&str_piece, reg, &match) &&
                   base::StringToDouble(match, &freq) && freq > frequency_) {
    frequency_ = freq;
  } else {
    return false;
  }

  base::FilePath entry_scale = sysfs_path.Append(kIioDeviceEntryScale);
  if (std::string buf;
      !base::PathExists(entry_scale) ||
      !base::ReadFileToString(entry_scale, &buf) ||
      !base::StringToDouble(base::TrimWhitespaceASCII(buf, base::TRIM_TRAILING),
                            &scale_)) {
    return false;
  }

  return true;
}

void IioEcSensorUtilsImpl::OnSampleUpdated(
    const base::flat_map<int, int64_t>& data) {
  // TODO(jeffulin): Remove this workaround when new firmware is released.
  if (samples_to_discard_-- > 0)
    return;

  for (const auto& channel_id : target_channel_ids_) {
    sampled_data_[channel_id].push_back(
        static_cast<double>(data.at(channel_id)) * scale_);
  }

  // Check if we got enough samples and stop sampling.
  if (sampled_data_.at(target_channel_ids_.at(0)).size() == sample_times_) {
    mojo_service_->GetSensorDevice(id_)->StopReadingSamples();
    DLOG(INFO) << "Stopped sampling";
    FinishSampling();
  }
}

void IioEcSensorUtilsImpl::FinishSampling() {
  std::vector<double> avg_data;
  avg_data.resize(target_channels_.size());
  for (int i = 0; i < target_channels_.size(); i++) {
    const int channel_id = target_channel_ids_.at(i);
    avg_data.at(i) = std::accumulate(sampled_data_.at(channel_id).begin(),
                                     sampled_data_.at(channel_id).end(), 0.0) /
                     sample_times_;
  }

  std::vector<double> variance;
  variance.resize(target_channels_.size(), 0.0);
  for (int i = 0; i < target_channels_.size(); i++) {
    const double avg = avg_data.at(i);
    const int channel_id = target_channel_ids_.at(i);
    for (const double value : sampled_data_.at(channel_id)) {
      variance.at(i) += (value - avg) * (value - avg);
    }
    variance.at(i) /=
        static_cast<double>(sampled_data_.at(channel_id).size() - 1);
  }

  std::move(get_avg_data_result_callback_)
      .Run(std::move(avg_data), std::move(variance));
}

void IioEcSensorUtilsImpl::OnErrorOccurred(
    cros::mojom::ObserverErrorType type) {
  LOG(ERROR) << "Got observer error while reading samples: " << type;
  std::move(get_avg_data_result_callback_).Run({}, {});
}

void IioEcSensorUtilsImpl::HandleSetChannelsEnabled(
    const std::vector<int>& failed_channel_ids) {
  if (!failed_channel_ids.empty()) {
    LOG(ERROR) << "Failed to enable channels.";
    std::move(get_avg_data_result_callback_).Run({}, {});
    return;
  }

  // Prepare for reading samples.
  device_sample_receiver_.reset();
  mojo_service_->GetSensorDevice(id_)->StartReadingSamples(
      device_sample_receiver_.BindNewPipeAndPassRemote());
}

void IioEcSensorUtilsImpl::HandleGetAllChannelIds(
    const std::vector<std::string>& channels) {
  channel_id_map_.clear();
  target_channel_ids_.clear();

  for (auto it = channels.begin(); it != channels.end(); it++) {
    channel_id_map_[*it] = it - channels.begin();
  }

  for (const auto& channel : target_channels_) {
    if (channel_id_map_.find(channel) == channel_id_map_.end()) {
      LOG(ERROR) << "Channel \"" << channel
                 << "\" is not an available channel.";
      std::move(get_avg_data_result_callback_).Run({}, {});
      return;
    }
    target_channel_ids_.push_back(channel_id_map_[channel]);
  }

  mojo_service_->GetSensorDevice(id_)->SetTimeout(
      ceil(kSecond2Millisecond / frequency_) + kTimeoutOverheadInMS);
  mojo_service_->GetSensorDevice(id_)->SetFrequency(frequency_,
                                                    base::DoNothing());

  mojo_service_->GetSensorDevice(id_)->SetChannelsEnabled(
      target_channel_ids_, true,
      base::BindOnce(&IioEcSensorUtilsImpl::HandleSetChannelsEnabled,
                     weak_ptr_factory_.GetMutableWeakPtr()));
}

}  // namespace rmad
