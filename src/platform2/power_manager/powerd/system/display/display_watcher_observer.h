// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef POWER_MANAGER_POWERD_SYSTEM_DISPLAY_DISPLAY_WATCHER_OBSERVER_H_
#define POWER_MANAGER_POWERD_SYSTEM_DISPLAY_DISPLAY_WATCHER_OBSERVER_H_

#include <vector>

#include <base/observer_list_types.h>

#include "power_manager/powerd/system/display/display_info.h"

namespace power_manager::system {

// Interface for receiving notifications from DisplayWatcher about changes to
// displays.
class DisplayWatcherObserver : public base::CheckedObserver {
 public:
  // Called when a display is connected or disconnected.
  virtual void OnDisplaysChanged(const std::vector<DisplayInfo>& displays) = 0;
};

}  // namespace power_manager::system

#endif  // POWER_MANAGER_POWERD_SYSTEM_DISPLAY_DISPLAY_WATCHER_OBSERVER_H_
