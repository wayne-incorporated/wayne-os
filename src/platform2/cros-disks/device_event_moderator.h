// Copyright 2011 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CROS_DISKS_DEVICE_EVENT_MODERATOR_H_
#define CROS_DISKS_DEVICE_EVENT_MODERATOR_H_

#include "cros-disks/device_event_queue.h"
#include "cros-disks/session_manager_observer_interface.h"

namespace cros_disks {

class DeviceEventDispatcherInterface;
class DeviceEventSourceInterface;

// A class for moderating device events by retrieving events from an event
// source and dispatching them through a dispatcher at appropriate moments.
//
// If |dispatch_initially| is true, device events are dispatched immediately
// only during an active user session. Then, after a user session ends or the
// screen is locked, any received device event is temporarily queued and only
// dispatched after a new user session starts or the screen is unlocked. This
// is to minimize the chance of device insertion attacks when the system is not
// actively used.
//
// If |dispatch_initially| is false, device events are not queued and
// dispatched immediately regardless of a session status. This is for use in
// environments where the concept of sessions is not relevant.
class DeviceEventModerator : public SessionManagerObserverInterface {
 public:
  DeviceEventModerator(DeviceEventDispatcherInterface* event_dispatcher,
                       DeviceEventSourceInterface* event_source,
                       bool dispatch_initially);
  DeviceEventModerator(const DeviceEventModerator&) = delete;
  DeviceEventModerator& operator=(const DeviceEventModerator&) = delete;

  virtual ~DeviceEventModerator() = default;

  // Dispatches all queued device events through the event dispatcher.
  void DispatchQueuedDeviceEvents();

  // Implements the SessionManagerObserverInterface interface to handle
  // the event when the screen is locked.
  virtual void OnScreenIsLocked();

  // Implements the SessionManagerObserverInterface interface to handle
  // the event when the screen is unlocked.
  virtual void OnScreenIsUnlocked();

  // Implements the SessionManagerObserverInterface interface to handle
  // the event when the session has been started.
  virtual void OnSessionStarted();

  // Implements the SessionManagerObserverInterface interface to handle
  // the event when the session has been stopped.
  virtual void OnSessionStopped();

  // Process the available device events from the event source.
  void ProcessDeviceEvents();

  bool is_event_queued() const { return is_event_queued_; }

 private:
  // An object that dispatches device events.
  DeviceEventDispatcherInterface* event_dispatcher_;

  // An object that queues up device events when the system is not active.
  DeviceEventQueue event_queue_;

  // An object from which device events are retrieved.
  DeviceEventSourceInterface* event_source_;

  // This variable is set to true if any new device event should be queued
  // instead of being dispatched immediately.
  bool is_event_queued_;
};

}  // namespace cros_disks

#endif  // CROS_DISKS_DEVICE_EVENT_MODERATOR_H_
