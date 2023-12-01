// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libmems/iio_event_impl.h"

#include <map>
#include <optional>
#include <vector>

#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_split.h>

namespace libmems {

namespace {

// iio_chan_type strings.
constexpr char kProximity[] = "proximity";

// iio_event_type strings.
constexpr char kThresh[] = "thresh";
constexpr char kMag[] = "mag";
constexpr char kRoc[] = "roc";
constexpr char kAdaptive[] = "adaptive";
constexpr char kChange[] = "change";

// iio_event_direction strings.
constexpr char kEither[] = "either";
constexpr char kRising[] = "rising";
constexpr char kFalling[] = "falling";
constexpr char kNone[] = "none";

const std::map<std::string, iio_chan_type> kChanTypeMap = {
    {"proximity", iio_chan_type::IIO_PROXIMITY}};

bool MatchString(std::string chan_str, const char prefix[]) {
  auto prefix_len = strlen(prefix);
  if (chan_str.size() < prefix_len)
    return false;

  return chan_str.compare(0, prefix_len, prefix) == 0;
}

std::optional<iio_chan_type> GetChanType(std::string chan_str) {
  if (MatchString(chan_str, kProximity))
    return iio_chan_type::IIO_PROXIMITY;

  return std::nullopt;
}

const char* GetChanTypeStr(iio_chan_type chan_type) {
  switch (chan_type) {
    case iio_chan_type::IIO_PROXIMITY:
      return kProximity;

    default:
      return nullptr;
  }
}

int GetChannel(std::string chan_str, iio_chan_type chan_type) {
  auto chan_type_str = GetChanTypeStr(chan_type);
  DCHECK(chan_type_str);

  std::string substr = chan_str.substr(strlen(chan_type_str));

  // If there's only one channel, the `0` is omitted.
  // See |index| field in |struct iio_chan_spec| in include/linux/iio/iio.h
  // kernel include file.
  if (substr.empty())
    return 0;

  int channel;
  if (!base::StringToInt(substr, &channel)) {
    LOG(ERROR) << "Cannot convert string to int: " << substr;
    return -1;
  }

  return channel;
}

std::optional<iio_event_type> GetEventType(std::string event_type_str,
                                           std::string prev_str) {
  if (event_type_str.compare(kThresh) == 0)
    return iio_event_type::IIO_EV_TYPE_THRESH;
  if (event_type_str.compare(kMag) == 0)
    return iio_event_type::IIO_EV_TYPE_MAG;
  if (event_type_str.compare(kRoc) == 0)
    return iio_event_type::IIO_EV_TYPE_ROC;
  if (event_type_str.compare(kAdaptive) == 0) {
    if (prev_str.compare(kThresh) == 0)
      return iio_event_type::IIO_EV_TYPE_THRESH_ADAPTIVE;
    if (prev_str.compare(kMag) == 0)
      return iio_event_type::IIO_EV_TYPE_MAG_ADAPTIVE;
  }
  if (event_type_str.compare(kChange) == 0)
    return iio_event_type::IIO_EV_TYPE_CHANGE;

  return std::nullopt;
}

std::optional<iio_event_direction> GetDirection(std::string direction_str) {
  if (direction_str.compare(kEither) == 0)
    return iio_event_direction::IIO_EV_DIR_EITHER;
  if (direction_str.compare(kRising) == 0)
    return iio_event_direction::IIO_EV_DIR_RISING;
  if (direction_str.compare(kFalling) == 0)
    return iio_event_direction::IIO_EV_DIR_FALLING;
  if (direction_str.compare(kNone) == 0)
    return iio_event_direction::IIO_EV_DIR_NONE;

  return std::nullopt;
}

}  // namespace

// static
std::unique_ptr<IioEventImpl> IioEventImpl::Create(base::FilePath file) {
  std::string file_name = file.BaseName().value();
  std::vector<std::string> pieces = base::SplitString(
      file_name, "_", base::TRIM_WHITESPACE, base::SPLIT_WANT_NONEMPTY);

  if (pieces.size() < 5 || pieces.front().compare("in") != 0 ||
      pieces.back().compare("en") != 0) {
    return nullptr;
  }

  std::optional<iio_chan_type> chan_type = ::libmems::GetChanType(pieces[1]);
  if (!chan_type.has_value())
    return nullptr;

  int channel = ::libmems::GetChannel(pieces[1], chan_type.value());

  std::optional<iio_event_type> event_type = ::libmems::GetEventType(
      pieces[pieces.size() - 3], pieces[pieces.size() - 4]);
  if (!event_type.has_value())
    return nullptr;

  std::optional<iio_event_direction> direction =
      ::libmems::GetDirection(pieces[pieces.size() - 2]);
  if (!direction.has_value())
    return nullptr;

  std::unique_ptr<IioEventImpl> iio_event_impl(new IioEventImpl(
      file.DirName(), file_name.substr(0, file_name.size() - 2),
      chan_type.value(), event_type.value(), direction.value(), channel));

  return iio_event_impl;
}

IioEventImpl::IioEventImpl(base::FilePath event_dir,
                           std::string event_pattern,
                           iio_chan_type chan_type,
                           iio_event_type event_type,
                           iio_event_direction direction,
                           int channel)
    : IioEvent(chan_type, event_type, direction, channel),
      event_dir_(event_dir),
      event_pattern_(event_pattern) {}

bool IioEventImpl::IsEnabled() const {
  base::FilePath file = GetAttributePath("en");

  std::string en;
  if (!ReadFileToString(file, &en)) {
    LOG(ERROR) << "Failed to read file: " << file.value();
    return false;
  }

  if (!en.empty() && en.front() == '1')
    return true;

  return false;
}

void IioEventImpl::SetEnabled(bool en) {
  base::FilePath file = GetAttributePath("en");

  if (!WriteFile(file, en ? "1\n" : "0\n"))
    LOG(ERROR) << "Failed to write file: " << file.value();
}

std::optional<std::string> IioEventImpl::ReadStringAttribute(
    const std::string& name) const {
  base::FilePath file = GetAttributePath(name);

  std::string value;
  if (!ReadFileToString(file, &value)) {
    LOG(ERROR) << "Failed to read file: " << file.value();
    return std::nullopt;
  }

  return value;
}

bool IioEventImpl::WriteStringAttribute(const std::string& name,
                                        const std::string& value) {
  base::FilePath file = GetAttributePath(name);

  if (!WriteFile(file, value)) {
    LOG(ERROR) << "Failed to write file: " << file.value();
    return false;
  }

  return true;
}

base::FilePath IioEventImpl::GetAttributePath(
    const std::string& attribute) const {
  return event_dir_.Append(event_pattern_ + attribute);
}

}  // namespace libmems
