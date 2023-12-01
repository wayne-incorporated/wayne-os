// Copyright 2011 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cros-disks/device_event.h"

#include "cros-disks/quote.h"

namespace cros_disks {

std::ostream& operator<<(std::ostream& out, DeviceEvent::EventType t) {
  switch (t) {
#define CROS_DISKS_PRINT(X) \
  case DeviceEvent::X:      \
    return out << #X;
    CROS_DISKS_PRINT(kIgnored)
    CROS_DISKS_PRINT(kDeviceAdded)
    CROS_DISKS_PRINT(kDeviceScanned)
    CROS_DISKS_PRINT(kDeviceRemoved)
    CROS_DISKS_PRINT(kDiskAdded)
    CROS_DISKS_PRINT(kDiskChanged)
    CROS_DISKS_PRINT(kDiskRemoved)
#undef CROS_DISKS_PRINT
  }
  return out << "EventType("
             << static_cast<std::underlying_type_t<DeviceEvent::EventType>>(t)
             << ")";
}

std::ostream& operator<<(std::ostream& out, const DeviceEvent& event) {
  return out << "{type: " << event.event_type
             << ", path: " << quote(event.device_path) << "}";
}

bool DeviceEvent::operator==(const DeviceEvent& event) const {
  return event.event_type == event_type && event.device_path == device_path;
}

bool DeviceEvent::IsDiskEvent() const {
  switch (event_type) {
    case kDiskAdded:
    case kDiskChanged:
    case kDiskRemoved:
      return true;
    default:
      return false;
  }
}

}  // namespace cros_disks
