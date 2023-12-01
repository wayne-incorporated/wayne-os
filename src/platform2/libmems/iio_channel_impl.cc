// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <optional>
#include <string>

#include <base/check.h>
#include <base/logging.h>
#include <base/strings/stringprintf.h>
#include <base/strings/string_util.h>

#include "libmems/common_types.h"
#include "libmems/iio_channel_impl.h"
#include "libmems/iio_device.h"

namespace {

constexpr char kUnsupportedChannels[][24] = {"rot_from_north_magnetic"};

}  // namespace

namespace libmems {

IioChannelImpl::IioChannelImpl(iio_channel* channel,
                               int device_id,
                               const char* device_name)
    : channel_(channel) {
  CHECK(channel_);

  log_prefix_ =
      base::StringPrintf("Device with id: %d and name: %s, channel: %s. ",
                         device_id, device_name, GetId());
}

const char* IioChannelImpl::GetId() const {
  return iio_channel_get_id(channel_);
}

bool IioChannelImpl::IsEnabled() const {
  return iio_channel_is_enabled(channel_);
}

void IioChannelImpl::SetEnabled(bool en) {
  for (const auto& unsupported_channel : kUnsupportedChannels) {
    if (strcmp(unsupported_channel, GetId()) == 0) {
      // This channel is not supported in samples. Skip enabling it.
      return;
    }
  }

  if (en)
    iio_channel_enable(channel_);
  else
    iio_channel_disable(channel_);
}

bool IioChannelImpl::SetScanElementsEnabled(bool en) {
  if (!iio_channel_is_scan_element(channel_))
    return true;

  std::string en_attrib_name = base::StringPrintf(
      "scan_elements/%s_%s_en", iio_channel_is_output(channel_) ? "out" : "in",
      GetId());
  int error = iio_channel_attr_write_bool(channel_, en_attrib_name.c_str(), en);
  if (error) {
    LOG(WARNING) << log_prefix_ << "Could not write to " << en_attrib_name
                 << ", error: " << error;
    return false;
  }

  return true;
}

std::optional<std::string> IioChannelImpl::ReadStringAttribute(
    const std::string& name) const {
  char data[kReadAttrBufferSize] = {0};
  ssize_t len =
      iio_channel_attr_read(channel_, name.c_str(), data, sizeof(data));
  if (len < 0) {
    LOG(WARNING) << log_prefix_ << "Attempting to read string attribute "
                 << name << " failed: " << len;
    return std::nullopt;
  }
  return std::string(base::TrimString(std::string(data, len),
                                      base::StringPiece("\0\n", 2),
                                      base::TRIM_TRAILING));
}

std::optional<int64_t> IioChannelImpl::ReadNumberAttribute(
    const std::string& name) const {
  long long val = 0;  // NOLINT(runtime/int)
  int error = iio_channel_attr_read_longlong(channel_, name.c_str(), &val);
  if (error) {
    LOG(WARNING) << log_prefix_ << "Attempting to read number attribute "
                 << name << " failed: " << error;
    return std::nullopt;
  }
  return val;
}

std::optional<double> IioChannelImpl::ReadDoubleAttribute(
    const std::string& name) const {
  double val = 0;
  int error = iio_channel_attr_read_double(channel_, name.c_str(), &val);
  if (error) {
    LOG(WARNING) << log_prefix_ << "Attempting to read double attribute "
                 << name << " failed: " << error;
    return std::nullopt;
  }
  return val;
}

bool IioChannelImpl::WriteStringAttribute(const std::string& name,
                                          const std::string& value) {
  int error = iio_channel_attr_write_raw(
      channel_, name.size() > 0 ? name.c_str() : nullptr, value.data(),
      value.size());
  if (error) {
    LOG(WARNING) << log_prefix_ << "Attempting to write string attribute "
                 << name << " failed: " << error;
    return false;
  }
  return true;
}

bool IioChannelImpl::WriteNumberAttribute(const std::string& name,
                                          int64_t value) {
  int error = iio_channel_attr_write_longlong(channel_, name.c_str(), value);
  if (error) {
    LOG(WARNING) << log_prefix_ << "Attempting to write number attribute "
                 << name << " failed: " << error;
    return false;
  }
  return true;
}

bool IioChannelImpl::WriteDoubleAttribute(const std::string& name,
                                          double value) {
  int error = iio_channel_attr_write_double(channel_, name.c_str(), value);
  if (error) {
    LOG(WARNING) << log_prefix_ << "Attempting to write double attribute "
                 << name << " failed: " << error;
    return false;
  }
  return true;
}

std::optional<int64_t> IioChannelImpl::Convert(const uint8_t* src) const {
  const iio_data_format* format = iio_channel_get_data_format(channel_);
  if (!format) {
    LOG(WARNING) << log_prefix_ << "Cannot find format.";
    return std::nullopt;
  }

  size_t len = format->length;
  if (len == 0)
    return 0;

  int64_t value = 0;
  iio_channel_convert(channel_, &value, src);

  if (format->is_signed && len < CHAR_BIT * sizeof(int64_t)) {
    int64_t mask = 1LL << (len - 1);

    if (mask & value) {
      // Doing sign extension
      value |= (~0LL) << len;
    }
  }

  return value;
}

std::optional<uint64_t> IioChannelImpl::Length() const {
  const iio_data_format* format = iio_channel_get_data_format(channel_);
  if (!format) {
    LOG(WARNING) << log_prefix_ << "Cannot find format.";
    return std::nullopt;
  }

  return format->length;
}

}  // namespace libmems
