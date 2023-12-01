// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBMEMS_IIO_EVENT_H_
#define LIBMEMS_IIO_EVENT_H_

#include <iio.h>

#include <linux/iio/events.h>
#include <linux/iio/types.h>
#include <optional>
#include <string>

#include "libmems/export.h"

namespace libmems {

// The IioEvent represents an event on an IIO device, for example the
// channel: 0, event type: threshold, direction: either in proximity sensor.
// Events can be enabled and/or disabled via this class.
class LIBMEMS_EXPORT IioEvent {
 public:
  virtual ~IioEvent();

  // Returns true if this event is enabled.
  virtual bool IsEnabled() const = 0;

  // Sets this event's enabled status to |en|.
  virtual void SetEnabled(bool en) = 0;

  // Sets the event's enabled status to |en|,
  // and returns true if the event's enabled status matches
  // what was set, false otherwise.
  bool SetEnabledAndCheck(bool en);

  // Checks if the mask (iio_event_data.id) matches this event.
  bool MatchMask(uint64_t mask);

  iio_chan_type GetChannelType() const;
  iio_event_type GetEventType() const;
  iio_event_direction GetDirection() const;
  // Returns -1 if invalid
  int GetChannelNumber() const;

  // Reads the |name| attribute of this event and returns the value
  // as a string. It will return std::nullopt if the attribute cannot
  // be read.
  virtual std::optional<std::string> ReadStringAttribute(
      const std::string& name) const = 0;

  // Reads the |name| attribute of this event and returns the value
  // as a signed number. It will return std::nullopt if the attribute
  // cannot be read or is not a valid number.
  std::optional<int64_t> ReadNumberAttribute(const std::string& name) const;

  // Reads the |name| attribute of this device and returns the value
  // as a double precision floating point. It will return std::nullopt
  // if the attribute cannot be read or is not a valid number.
  std::optional<double> ReadDoubleAttribute(const std::string& name) const;

  // Writes the string |value| to the attribute |name| of this event. Returns
  // false if an error occurs.
  virtual bool WriteStringAttribute(const std::string& name,
                                    const std::string& value) = 0;

  // Writes the number |value| to the attribute |name| of this event. Returns
  // false if an error occurs.
  bool WriteNumberAttribute(const std::string& name, int64_t value);

  // Writes the floating point |value| to the attribute |name| of this event.
  // Returns false if an error occurs.
  bool WriteDoubleAttribute(const std::string& name, double value);

 protected:
  IioEvent(iio_chan_type chan_type,
           iio_event_type event_type,
           iio_event_direction direction,
           int channel);
  IioEvent(const IioEvent&) = delete;
  IioEvent& operator=(const IioEvent&) = delete;

  const iio_chan_type chan_type_;
  const iio_event_type event_type_;
  const iio_event_direction direction_;
  const int channel_;  // -1 if invalid
};

}  // namespace libmems

#endif  // LIBMEMS_IIO_EVENT_H_
