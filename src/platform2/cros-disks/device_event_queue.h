// Copyright 2011 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CROS_DISKS_DEVICE_EVENT_QUEUE_H_
#define CROS_DISKS_DEVICE_EVENT_QUEUE_H_

#include "cros-disks/device_event.h"

namespace cros_disks {

struct DeviceEvent;

// An event queue for keeping track of deferred device events.
class DeviceEventQueue {
 public:
  DeviceEventQueue() = default;
  DeviceEventQueue(const DeviceEventQueue&) = delete;
  DeviceEventQueue& operator=(const DeviceEventQueue&) = delete;

  ~DeviceEventQueue() = default;

  // Removes a device event from the event queue in a FIFO manner.
  // It is a no-op if the queue is empty.
  void Remove();

  // Adds a device event to the event queue in a FIFO manner.
  //
  // Due to its use for keeping track of deferred device events, the
  // event queue does not simply accumulate events being passed to the
  // Add method. Depending on the type of an event and its correlation
  // with other events in the queue, the event may be discarded or cause
  // other events in the queue to be discarded.
  //
  // The rules are:
  // 1) Ignored and DeviceScanned events are always discarded as they
  //    do not carry any useful information to the prospective client.
  // 2) If a DeviceRemoved event is seen after a DeviceAdded event with
  //    the same device path, both events are discarded as if the device
  //    has not been added.
  // 3) If a DiskRemoved event is seen after a DiskAdded or DiskChanged
  //    event with the same device path, both events are discarded as if
  //    the device has not been added.
  // 4) A DiskChanged event is discarded if a DiskAdded event is already
  //    in the queue. This is because both events are deferred and thus
  //    the DiskChanged event, which signals some property changes in the
  //    disk, can be absorbed into the DiskAdded event.
  void Add(const DeviceEvent& event);

  // Returns a pointer to the oldest device event at the head of event
  // queue or NULL if the queue is empty. The pointer will become
  // invalid upon the next Remove call.
  const DeviceEvent* Head() const;

  const DeviceEventList& events() const { return events_; }

 private:
  // A list of events in the event queue.
  // The latest event is inserted at the beginning of the list.
  DeviceEventList events_;
};

}  // namespace cros_disks

#endif  // CROS_DISKS_DEVICE_EVENT_QUEUE_H_
