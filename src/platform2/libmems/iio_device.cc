// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libmems/iio_device.h"

#include <stdlib.h>

#include <optional>

#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_split.h>

#include "libmems/common_types.h"
#include "libmems/iio_channel.h"
#include "libmems/iio_event.h"

namespace libmems {

IioDevice::~IioDevice() = default;

std::optional<base::FilePath> IioDevice::GetAbsoluteSysPath() const {
  base::FilePath iio_path(GetPath());
  base::FilePath sys_path;
  if (base::ReadSymbolicLink(iio_path, &sys_path)) {
    if (sys_path.IsAbsolute()) {
      return sys_path;

    } else {
      base::FilePath result = iio_path.DirName();
      result = result.Append(sys_path);

      return base::MakeAbsoluteFilePath(result);
    }
  }

  return std::nullopt;
}

std::optional<std::string> IioDevice::GetLocation() const {
  auto label = ReadStringAttribute(kLabelAttr);
  if (label.has_value()) {
    if (label->find("-base") != std::string::npos)
      return "base";

    if (label->find("-display") != std::string::npos)
      return "lid";

    if (label->find("-camera") != std::string::npos)
      return "camera";
  }

  return ReadStringAttribute(kLocationAttr);
}

bool IioDevice::IsSingleSensor() const {
  return ReadStringAttribute(kLocationAttr).has_value();
}

// static
std::optional<int> IioDevice::GetIdAfterPrefix(const char* id_str,
                                               const char* prefix) {
  size_t id_len = strlen(id_str);
  size_t prefix_len = strlen(prefix);
  if (id_len <= prefix_len || strncmp(id_str, prefix, prefix_len) != 0) {
    return std::nullopt;
  }

  int value = 0;
  bool success = base::StringToInt(std::string(id_str + prefix_len), &value);
  if (success)
    return value;

  return std::nullopt;
}

std::vector<IioChannel*> IioDevice::GetAllChannels() {
  std::vector<IioChannel*> channels;
  for (const auto& channel_data : channels_)
    channels.push_back(channel_data.chn.get());

  return channels;
}

void IioDevice::EnableAllChannels() {
  for (IioChannel* chn : GetAllChannels()) {
    if (!chn->SetEnabledAndCheck(true))
      LOG(ERROR) << "Failed to enable channel: " << chn->GetId();
  }
}

IioChannel* IioDevice::GetChannel(int32_t index) {
  if (index < 0 || index >= channels_.size())
    return nullptr;

  return channels_[index].chn.get();
}

IioChannel* IioDevice::GetChannel(const std::string& name) {
  for (size_t i = 0; i < channels_.size(); ++i) {
    if (channels_[i].chn_id == name)
      return channels_[i].chn.get();
  }

  return nullptr;
}

std::vector<IioEvent*> IioDevice::GetAllEvents() {
  std::vector<IioEvent*> events;
  for (const auto& event : events_)
    events.push_back(event.get());

  return events;
}

void IioDevice::EnableAllEvents() {
  for (const auto& event : events_) {
    if (!event->SetEnabledAndCheck(true))
      LOG(ERROR) << "Failed to enable event: " << event->GetChannelNumber();
  }
}

IioEvent* IioDevice::GetEvent(int32_t index) {
  if (index < 0 || index >= events_.size())
    return nullptr;

  return events_[index].get();
}

bool IioDevice::GetMinMaxFrequency(double* min_freq, double* max_freq) {
  auto available_opt = ReadStringAttribute(kSamplingFrequencyAvailable);
  if (!available_opt.has_value()) {
    LOG(ERROR) << "Failed to read attribute: " << kSamplingFrequencyAvailable;
    return false;
  }

  std::string sampling_frequency_available = available_opt.value();
  // Remove trailing '\0' for parsing
  auto pos = available_opt->find_first_of('\0');
  if (pos != std::string::npos)
    sampling_frequency_available = available_opt->substr(0, pos);

  std::vector<std::string> sampling_frequencies =
      base::SplitString(sampling_frequency_available, " ",
                        base::TRIM_WHITESPACE, base::SPLIT_WANT_NONEMPTY);

  switch (sampling_frequencies.size()) {
    case 0:
      LOG(ERROR) << "Invalid format of " << kSamplingFrequencyAvailable << ": "
                 << sampling_frequency_available;
      return false;

    case 1:
      if (!base::StringToDouble(sampling_frequencies.front(), min_freq) ||
          *min_freq < 0.0 || *min_freq < kFrequencyEpsilon) {
        LOG(ERROR) << "Failed to parse min max sampling_frequency: "
                   << sampling_frequency_available;
        return false;
      }

      *max_freq = *min_freq;
      return true;

    default:
      if (!base::StringToDouble(sampling_frequencies.back(), max_freq) ||
          *max_freq < kFrequencyEpsilon) {
        LOG(ERROR) << "Failed to parse max sampling_frequency: "
                   << sampling_frequency_available;
        return false;
      }

      if (!base::StringToDouble(sampling_frequencies.front(), min_freq) ||
          *min_freq < 0.0) {
        LOG(ERROR) << "Failed to parse the first sampling_frequency: "
                   << sampling_frequency_available;
        return false;
      }

      if (*min_freq == 0.0) {
        if (!base::StringToDouble(sampling_frequencies[1], min_freq) ||
            *min_freq < 0.0 || *max_freq < *min_freq) {
          LOG(ERROR) << "Failed to parse min sampling_frequency: "
                     << sampling_frequency_available;
          return false;
        }
      }

      return true;
  }
}

}  // namespace libmems
