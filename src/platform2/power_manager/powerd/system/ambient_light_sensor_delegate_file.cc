// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/powerd/system/ambient_light_sensor_delegate_file.h"

#include <fcntl.h>

#include <algorithm>
#include <cerrno>
#include <cmath>
#include <cstring>
#include <iterator>
#include <map>
#include <optional>
#include <utility>

#include <base/check.h>
#include <base/files/file_enumerator.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>

#include "power_manager/common/tracing.h"

namespace power_manager::system {

namespace {

// Default path examined for backlight device directories.
const char kDefaultDeviceListPath[] = "/sys/bus/iio/devices";

// Default interval for polling the ambient light sensor.
constexpr base::TimeDelta kDefaultPollInterval = base::Seconds(1);

SensorLocation StringToSensorLocation(const std::string& location) {
  if (location == "base")
    return SensorLocation::BASE;
  if (location == "lid")
    return SensorLocation::LID;
  return SensorLocation::UNKNOWN;
}

std::string SensorLocationToString(SensorLocation location) {
  switch (location) {
    case SensorLocation::UNKNOWN:
      return "unknown";
    case SensorLocation::BASE:
      return "base";
    case SensorLocation::LID:
      return "lid";
  }
}

bool ParseLuxData(const std::string& data, int* value) {
  DCHECK(value);
  std::string trimmed_data;
  base::TrimWhitespaceASCII(data, base::TRIM_ALL, &trimmed_data);
  if (!base::StringToInt(trimmed_data, value)) {
    LOG(ERROR) << "Could not read lux value from ALS file contents: ["
               << trimmed_data << "]";
    return false;
  }
  VLOG(1) << "Read lux value " << *value;
  return true;
}

}  // namespace

const int AmbientLightSensorDelegateFile::kNumInitAttemptsBeforeLogging = 5;
const int AmbientLightSensorDelegateFile::kNumInitAttemptsBeforeGivingUp = 20;

AmbientLightSensorDelegateFile::AmbientLightSensorDelegateFile(
    SensorLocation expected_sensor_location, bool enable_color_support)
    : device_list_path_(kDefaultDeviceListPath),
      poll_interval_(kDefaultPollInterval),
      enable_color_support_(enable_color_support),
      expected_sensor_location_(expected_sensor_location) {}

AmbientLightSensorDelegateFile::AmbientLightSensorDelegateFile(
    const std::string& device, bool enable_color_support)
    : device_list_path_(kDefaultDeviceListPath),
      device_(device),
      poll_interval_(kDefaultPollInterval),
      enable_color_support_(enable_color_support),
      expected_sensor_location_(SensorLocation::UNKNOWN) {}

void AmbientLightSensorDelegateFile::Init(bool read_immediately) {
  if (read_immediately)
    ReadAls();
  StartTimer();
}

bool AmbientLightSensorDelegateFile::TriggerPollTimerForTesting() {
  if (!poll_timer_.IsRunning())
    return false;

  ReadAls();
  return true;
}

bool AmbientLightSensorDelegateFile::IsColorSensor() const {
  return !color_als_files_.empty();
}

base::FilePath AmbientLightSensorDelegateFile::GetIlluminancePath() const {
  if (als_file_.HasOpenedFile())
    return als_file_.path();
  return base::FilePath();
}

void AmbientLightSensorDelegateFile::StartTimer() {
  poll_timer_.Start(FROM_HERE, poll_interval_, this,
                    &AmbientLightSensorDelegateFile::ReadAls);
}

void AmbientLightSensorDelegateFile::ReadAls() {
  TRACE_EVENT("power", "AmbientLightSensorDelegateFile::ReadAls");
  // We really want to read the ambient light level.
  // Complete the deferred lux file open if necessary.
  if (!als_file_.HasOpenedFile() && !InitAlsFile()) {
    if (num_init_attempts_ >= kNumInitAttemptsBeforeGivingUp) {
      LOG(ERROR) << "Giving up on reading from sensor";
      poll_timer_.Stop();
    }
    return;
  }

  // The timer will be restarted after the read finishes.
  poll_timer_.Stop();

  clear_reading_.reset();
  als_file_.StartRead(
      base::BindOnce(&AmbientLightSensorDelegateFile::ReadCallback,
                     base::Unretained(this)),
      base::BindOnce(&AmbientLightSensorDelegateFile::ErrorCallback,
                     base::Unretained(this)));
  if (!IsColorSensor())
    return;

  color_readings_.clear();
  for (const ColorChannelInfo& channel : kColorChannelConfig) {
    color_als_files_[&channel].StartRead(
        base::BindOnce(
            &AmbientLightSensorDelegateFile::ReadColorChannelCallback,
            base::Unretained(this), &channel),
        base::BindOnce(
            &AmbientLightSensorDelegateFile::ErrorColorChannelCallback,
            base::Unretained(this), &channel));
  }
}

void AmbientLightSensorDelegateFile::ReadCallback(const std::string& data) {
  if (!set_lux_callback_)
    return;

  int value = -1;

  if (IsColorSensor()) {
    ParseLuxData(data, &value);
    clear_reading_ = value;
    CollectChannelReadings();
    return;
  }

  if (ParseLuxData(data, &value))
    set_lux_callback_.Run(value, std::nullopt);

  StartTimer();
}

void AmbientLightSensorDelegateFile::ErrorCallback() {
  LOG(ERROR) << "Error reading ALS file";

  if (IsColorSensor()) {
    clear_reading_ = -1;
    CollectChannelReadings();
    return;
  }

  StartTimer();
}

void AmbientLightSensorDelegateFile::ReadColorChannelCallback(
    const ColorChannelInfo* channel, const std::string& data) {
  int value = -1;
  ParseLuxData(data, &value);
  color_readings_[channel] = value;
  CollectChannelReadings();
}

void AmbientLightSensorDelegateFile::ErrorColorChannelCallback(
    const ColorChannelInfo* channel) {
  LOG(ERROR) << "Error reading ALS file for " << channel->xyz_name << "channel";
  color_readings_[channel] = -1;
  CollectChannelReadings();
}

void AmbientLightSensorDelegateFile::CollectChannelReadings() {
  if (!set_lux_callback_ || !clear_reading_.has_value() ||
      color_readings_.size() != std::size(kColorChannelConfig)) {
    return;
  }

  std::map<ChannelType, int> readings;
  std::optional<int> lux_value = std::nullopt;
  if (clear_reading_.value() > -1)
    lux_value = clear_reading_.value();

  for (const auto& reading : color_readings_) {
    // -1 marks an invalid reading.
    if (reading.second == -1)
      continue;
    readings[reading.first->type] = reading.second;
  }

  auto color_temperature =
      AmbientLightSensorDelegate::CalculateColorTemperature(readings);

  // We should notify observers if there is either a change in lux or a change
  // in color temperature.
  if (lux_value.has_value() || color_temperature.has_value())
    set_lux_callback_.Run(lux_value, color_temperature);

  StartTimer();
}

void AmbientLightSensorDelegateFile::InitColorAlsFiles(
    const base::FilePath& device_dir) {
  color_als_files_.clear();
  std::map<const ColorChannelInfo*, AsyncFileReader> channel_map;

  for (const ColorChannelInfo& channel : kColorChannelConfig) {
    base::FilePath channel_path(device_dir.Append(
        base::StringPrintf("in_illuminance_%s_raw", channel.rgb_name)));
    if (!base::PathExists(channel_path))
      return;
    if (!channel_map[&channel].Init(channel_path))
      return;
    VLOG(2) << "Found " << channel.xyz_name << " light intensity file at "
            << channel_path.value();
  }

  color_als_files_ = std::move(channel_map);
  LOG(INFO) << "ALS at path " << device_dir.value() << " has color support";
}

bool AmbientLightSensorDelegateFile::CheckPath(
    const base::FilePath& check_path) {
  const char* input_names[] = {
      "in_illuminance0_input", "in_illuminance_input", "in_illuminance0_raw",
      "in_illuminance_raw",    "illuminance0_input",
  };

  if (expected_sensor_location_ != SensorLocation::UNKNOWN) {
    base::FilePath loc_path = check_path.Append("location");
    std::string location;
    if (!base::ReadFileToString(loc_path, &location)) {
      return false;
    }
    base::TrimWhitespaceASCII(location, base::TRIM_ALL, &location);
    SensorLocation als_loc = StringToSensorLocation(location);
    if (als_loc != expected_sensor_location_) {
      return false;
    }
  }
  for (const auto& name : input_names) {
    base::FilePath als_path = check_path.Append(name);
    if (!base::PathExists(als_path))
      continue;
    if (!als_file_.Init(als_path))
      continue;
    if (enable_color_support_)
      InitColorAlsFiles(check_path);
    LOG(INFO) << "Using lux file " << GetIlluminancePath().value() << " for "
              << SensorLocationToString(expected_sensor_location_) << " ALS";
    return true;
  }
  return false;
}

bool AmbientLightSensorDelegateFile::InitAlsFile() {
  CHECK(!als_file_.HasOpenedFile());

  num_init_attempts_++;

  if (device_.empty()) {
    // Search the iio/devices directory for a subdirectory (eg "device0" or
    // "iio:device0") that contains the "[in_]illuminance[0]_{input|raw}" file.
    base::FileEnumerator dir_enumerator(device_list_path_, false,
                                        base::FileEnumerator::DIRECTORIES);

    for (base::FilePath check_path = dir_enumerator.Next(); !check_path.empty();
         check_path = dir_enumerator.Next()) {
      if (CheckPath(check_path)) {
        return true;
      }
    }
  } else {
    if (CheckPath(device_list_path_.Append(device_))) {
      return true;
    }
  }

  // If the illuminance file is not immediately found, issue a deferral
  // message and try again later.
  if (num_init_attempts_ > kNumInitAttemptsBeforeLogging)
    PLOG(ERROR) << "lux file initialization failed";
  return false;
}

}  // namespace power_manager::system
