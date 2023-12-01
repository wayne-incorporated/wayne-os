// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libmems/iio_event.h"

#include <optional>

#include <base/logging.h>
#include <base/strings/string_number_conversions.h>

namespace libmems {

IioEvent::~IioEvent() = default;

bool IioEvent::SetEnabledAndCheck(bool en) {
  SetEnabled(en);
  return en == IsEnabled();
}

bool IioEvent::MatchMask(uint64_t mask) {
  if (IIO_EVENT_CODE_EXTRACT_CHAN_TYPE(mask) != chan_type_)
    return false;

  if (IIO_EVENT_CODE_EXTRACT_TYPE(mask) != event_type_)
    return false;

  if (direction_ != iio_event_direction::IIO_EV_DIR_EITHER &&
      IIO_EVENT_CODE_EXTRACT_DIR(mask) != direction_) {
    return false;
  }

  if (channel_ != -1 && IIO_EVENT_CODE_EXTRACT_CHAN(mask) != channel_)
    return false;

  return true;
}

iio_chan_type IioEvent::GetChannelType() const {
  return chan_type_;
}

iio_event_type IioEvent::GetEventType() const {
  return event_type_;
}

iio_event_direction IioEvent::GetDirection() const {
  return direction_;
}

int IioEvent::GetChannelNumber() const {
  return channel_;
}

std::optional<int64_t> IioEvent::ReadNumberAttribute(
    const std::string& name) const {
  std::optional<std::string> value = ReadStringAttribute(name);
  if (!value.has_value())
    return std::nullopt;

  int64_t number;
  if (!base::StringToInt64(value.value(), &number)) {
    LOG(ERROR) << "Cannot convert string to int64: " << value.value();
    return std::nullopt;
  }

  return number;
}

std::optional<double> IioEvent::ReadDoubleAttribute(
    const std::string& name) const {
  std::optional<std::string> value = ReadStringAttribute(name);
  if (!value.has_value())
    return std::nullopt;

  double number;
  if (!base::StringToDouble(value.value(), &number)) {
    LOG(ERROR) << "Cannot convert string to double: " << value.value();
    return std::nullopt;
  }

  return number;
}

bool IioEvent::WriteNumberAttribute(const std::string& name, int64_t value) {
  return WriteStringAttribute(name, base::NumberToString(value));
}

bool IioEvent::WriteDoubleAttribute(const std::string& name, double value) {
  return WriteStringAttribute(name, base::NumberToString(value));
}

IioEvent::IioEvent(iio_chan_type chan_type,
                   iio_event_type event_type,
                   iio_event_direction direction,
                   int channel)
    : chan_type_(chan_type),
      event_type_(event_type),
      direction_(direction),
      channel_(channel) {}

}  // namespace libmems
