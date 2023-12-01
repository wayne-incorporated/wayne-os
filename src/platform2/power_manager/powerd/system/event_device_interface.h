// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef POWER_MANAGER_POWERD_SYSTEM_EVENT_DEVICE_INTERFACE_H_
#define POWER_MANAGER_POWERD_SYSTEM_EVENT_DEVICE_INTERFACE_H_

#include <memory>
#include <string>
#include <vector>

#include <base/files/file_path.h>
#include <base/functional/callback_forward.h>

#include "power_manager/common/power_constants.h"

struct input_event;  // from <linux/input.h>

namespace power_manager::system {

// Provides methods to access event devices, i.e. the device files exposed by
// the kernel evdev interface: /dev/input/eventN.
class EventDeviceInterface {
 public:
  EventDeviceInterface() = default;
  virtual ~EventDeviceInterface() = default;

  // Returns a human-readable identifier to be used for debugging.
  virtual std::string GetDebugName() = 0;

  // Returns the name (from EVIOCGNAME) of the input device.
  virtual std::string GetName() = 0;

  // Returns the physical path of the device.
  // TODO(patrikf): Consider using udev and tags instead.
  virtual std::string GetPhysPath() = 0;

  // Returns true if the device is a Chrome OS fingerprint device.
  virtual bool IsCrosFp() = 0;

  // Returns true if the device can report lid events.
  virtual bool IsLidSwitch() = 0;

  // Returns true if the device can report tablet mode events.
  virtual bool IsTabletModeSwitch() = 0;

  // Returns true if the device can report power button events.
  virtual bool IsPowerButton() = 0;

  // Returns true if the device can report hover events.
  virtual bool HoverSupported() = 0;

  // Returns true if the device reports a left button. This can be used to
  // distinguish touchpads from touchscreens.
  virtual bool HasLeftButton() = 0;

  // Returns the current state of the lid switch.
  // Must not be called after ReadEvents() or WatchForEvents().
  virtual LidState GetInitialLidState() = 0;

  // Returns the current state of the tablet mode switch.
  // Must not be called after ReadEvents() or WatchForEvents().
  virtual TabletMode GetInitialTabletMode() = 0;

  // Reads a number of events into |events_out|. Returns kSuccess if the
  // operation was successful and events were present. kFailure indicates a read
  // error, while kNoDevice is a non-recoverable failure due to the device being
  // removed.
  enum class ReadResult { kFailure, kSuccess, kNoDevice };
  virtual ReadResult ReadEvents(std::vector<input_event>* events_out) = 0;

  // Start watching this device for incoming events, and run |new_events_cb|
  // when events are ready to be read with ReadEvents(). Shall only be called
  // once.
  virtual void WatchForEvents(const base::RepeatingClosure& new_events_cb) = 0;
};

class EventDeviceFactoryInterface {
 public:
  EventDeviceFactoryInterface() = default;
  virtual ~EventDeviceFactoryInterface() = default;

  // Opens an event device by path. Returns the device or NULL on error.
  // TODO(crbug.com/1073772,ejcaruso): migrate to unique_ptr.
  // In theory, this can be unique_ptr. InputWatcher will consume this
  // unique_ptr and transfer ownership for device that should_watch. But
  // EventDeviceStub didn't create new instances for each device, instead
  // reuses the same instance. Thus if we transfer ownership via Open, this
  // device can be released by InputWatcher. devices raw pointer is created in
  // input_watcher_test.cc, and keeps reused even after an Open(). This could
  // cause heap use after free in unittest.
  virtual std::shared_ptr<EventDeviceInterface> Open(
      const base::FilePath& path) = 0;
};

}  // namespace power_manager::system

#endif  // POWER_MANAGER_POWERD_SYSTEM_EVENT_DEVICE_INTERFACE_H_
