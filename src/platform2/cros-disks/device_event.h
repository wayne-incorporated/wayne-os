// Copyright 2011 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CROS_DISKS_DEVICE_EVENT_H_
#define CROS_DISKS_DEVICE_EVENT_H_

#include <list>
#include <ostream>
#include <string>

namespace cros_disks {

// A simple data structure for holding a device event.
struct DeviceEvent {
  enum EventType {
    kIgnored,
    kDeviceAdded,
    kDeviceScanned,
    kDeviceRemoved,
    kDiskAdded,
    kDiskChanged,
    kDiskRemoved,
  };

  DeviceEvent() : event_type(kIgnored) {}

  DeviceEvent(EventType type, const std::string& path)
      : event_type(type), device_path(path) {}

  // NOTE: This operator== is needed due to the use of gmock matcher in
  // DeviceEventModeratorTest.
  bool operator==(const DeviceEvent& event) const;

  // Returns true if the event type is DiskAdded, DiskChanged or DiskRemoved.
  bool IsDiskEvent() const;

  EventType event_type;
  std::string device_path;
};

std::ostream& operator<<(std::ostream& out, DeviceEvent::EventType type);
std::ostream& operator<<(std::ostream& out, const DeviceEvent& event);

using DeviceEventList = std::list<DeviceEvent>;

}  // namespace cros_disks

#endif  // CROS_DISKS_DEVICE_EVENT_H_
