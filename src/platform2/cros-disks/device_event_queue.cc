// Copyright 2011 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cros-disks/device_event_queue.h"

#include <base/check.h>
#include <base/logging.h>

#include "cros-disks/device_event.h"

namespace cros_disks {

void DeviceEventQueue::Remove() {
  if (!events_.empty())
    events_.pop_back();
}

void DeviceEventQueue::Add(const DeviceEvent& event) {
  // Discard an Ignored or DeviceScanned event.
  if (event.event_type == DeviceEvent::kIgnored ||
      event.event_type == DeviceEvent::kDeviceScanned)
    return;

  for (DeviceEventList::iterator last_event_iterator = events_.begin();
       last_event_iterator != events_.end(); ++last_event_iterator) {
    const DeviceEvent& last_event = *last_event_iterator;

    // Skip an unrelated event.
    if (event.device_path != last_event.device_path ||
        event.IsDiskEvent() != last_event.IsDiskEvent())
      continue;

    // Combine events of the same type and device path and keep the latest one.
    if (event.event_type == last_event.event_type) {
      events_.erase(last_event_iterator);
      events_.push_front(event);
      return;
    }

    // Discard a Removed event and its last related event, which is an
    // Added/Changed event. Note that the last related event cannot be
    // a Removed event as that is already handled by the code above.
    if (event.event_type == DeviceEvent::kDeviceRemoved ||
        event.event_type == DeviceEvent::kDiskRemoved) {
      CHECK(last_event.event_type != DeviceEvent::kDeviceRemoved &&
            last_event.event_type != DeviceEvent::kDiskRemoved)
          << "Last event should not be a Removed event";
      events_.erase(last_event_iterator);
      return;
    }

    // Discard a DiskChanged event if a related DiskAdded event is already
    // in the queue.
    if (event.event_type == DeviceEvent::kDiskChanged &&
        last_event.event_type == DeviceEvent::kDiskAdded)
      return;
  }

  events_.push_front(event);
}

const DeviceEvent* DeviceEventQueue::Head() const {
  return events_.empty() ? nullptr : &events_.back();
}

}  // namespace cros_disks
