// Copyright 2011 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CROS_DISKS_DEVICE_EVENT_SOURCE_INTERFACE_H_
#define CROS_DISKS_DEVICE_EVENT_SOURCE_INTERFACE_H_

#include "cros-disks/device_event.h"

namespace cros_disks {

// An interface class for producing device events.
class DeviceEventSourceInterface {
 public:
  virtual ~DeviceEventSourceInterface() = default;

  // Implemented by a derived class to return the available device events
  // in |events|. Returns false on error.
  virtual bool GetDeviceEvents(DeviceEventList* events) = 0;
};

}  // namespace cros_disks

#endif  // CROS_DISKS_DEVICE_EVENT_SOURCE_INTERFACE_H_
