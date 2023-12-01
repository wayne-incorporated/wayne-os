// Copyright 2011 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CROS_DISKS_DEVICE_EVENT_DISPATCHER_INTERFACE_H_
#define CROS_DISKS_DEVICE_EVENT_DISPATCHER_INTERFACE_H_

namespace cros_disks {

struct DeviceEvent;

// An interface class for dispatching device events.
class DeviceEventDispatcherInterface {
 public:
  virtual ~DeviceEventDispatcherInterface() = default;

  // Implemented by a derived class to dispatch a device event.
  virtual void DispatchDeviceEvent(const DeviceEvent& event) = 0;
};

}  // namespace cros_disks

#endif  // CROS_DISKS_DEVICE_EVENT_DISPATCHER_INTERFACE_H_
