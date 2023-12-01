// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef POWER_MANAGER_POWERD_SYSTEM_INPUT_WATCHER_INTERFACE_H_
#define POWER_MANAGER_POWERD_SYSTEM_INPUT_WATCHER_INTERFACE_H_

#include "power_manager/common/power_constants.h"

namespace power_manager::system {

class InputObserver;

// An interface for querying vaguely-input-related state.
class InputWatcherInterface {
 public:
  InputWatcherInterface() = default;
  InputWatcherInterface(const InputWatcherInterface&) = delete;
  InputWatcherInterface& operator=(const InputWatcherInterface&) = delete;

  virtual ~InputWatcherInterface() = default;

  // Adds or removes an observer.
  virtual void AddObserver(InputObserver* observer) = 0;
  virtual void RemoveObserver(InputObserver* observer) = 0;

  // Queries the system for the current lid state. LidState::NOT_PRESENT is
  // returned on error.
  virtual LidState QueryLidState() = 0;

  // Returns the most-recently-observed state from the tablet mode switch (if
  // any).
  virtual TabletMode GetTabletMode() = 0;

  // Checks if any USB input devices are connected.
  virtual bool IsUSBInputDeviceConnected() const = 0;
};

}  // namespace power_manager::system

#endif  // POWER_MANAGER_POWERD_SYSTEM_INPUT_WATCHER_INTERFACE_H_
