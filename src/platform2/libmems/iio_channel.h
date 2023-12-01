// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBMEMS_IIO_CHANNEL_H_
#define LIBMEMS_IIO_CHANNEL_H_

#include <optional>
#include <string>

#include "libmems/export.h"

namespace libmems {

class LIBMEMS_EXPORT IioDevice;

// The IioChannel represents a channel on an IIO device, for example the
// X axis on an accelerometer.
// Channels can be enabled and/or disabled via this class.
class IioChannel {
 public:
  virtual ~IioChannel() = default;

  // Returns the unique ID of this channel.
  virtual const char* GetId() const = 0;

  // Returns true if this channel is enabled.
  virtual bool IsEnabled() const = 0;

  // Sets this channel's enabled status to |en|.
  virtual void SetEnabled(bool en) = 0;

  // Sets the channel's enabled status to |en|,
  // and returns true if the channel's enabled status matches
  // what was set, false otherwise.
  bool SetEnabledAndCheck(bool en) {
    SetEnabled(en);
    return en == IsEnabled();
  }

  // Used only in mems_setup to enable channels for iioservice or Chrome to use.
  // We directly write to the scan elements instead of setting up a buffer and
  // keeping it enabled while we run (which wouldn't be long enough anyway). we
  // do not need to handle the non scan-element case for the channels we care
  // about.
  // Returns false on failure of the scan-element case.
  virtual bool SetScanElementsEnabled(bool en) = 0;

  // Reads the |name| attribute of this channel and returns the value
  // as a string. It will return std::nullopt if the attribute cannot
  // be read.
  virtual std::optional<std::string> ReadStringAttribute(
      const std::string& name) const = 0;

  // Reads the |name| attribute of this channel and returns the value
  // as a signed number. It will return std::nullopt if the attribute
  // cannot be read or is not a valid number.
  virtual std::optional<int64_t> ReadNumberAttribute(
      const std::string& name) const = 0;

  // Reads the |name| attribute of this device and returns the value
  // as a double precision floating point. It will return std::nullopt
  // if the attribute cannot be read or is not a valid number.
  virtual std::optional<double> ReadDoubleAttribute(
      const std::string& name) const = 0;

  // Writes the string |value| to the attribute |name| of this channel. Returns
  // false if an error occurs.
  virtual bool WriteStringAttribute(const std::string& name,
                                    const std::string& value) = 0;

  // Writes the number |value| to the attribute |name| of this channel. Returns
  // false if an error occurs.
  virtual bool WriteNumberAttribute(const std::string& name, int64_t value) = 0;

  // Writes the floating point |value| to the attribute |name| of this channel.
  // Returns false if an error occurs.
  virtual bool WriteDoubleAttribute(const std::string& name, double value) = 0;

 protected:
  IioChannel() = default;
  IioChannel(const IioChannel&) = delete;
  IioChannel& operator=(const IioChannel&) = delete;
};

}  // namespace libmems

#endif  // LIBMEMS_IIO_CHANNEL_H_
