// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef POWER_MANAGER_POWERD_SYSTEM_DISPLAY_DISPLAY_WATCHER_STUB_H_
#define POWER_MANAGER_POWERD_SYSTEM_DISPLAY_DISPLAY_WATCHER_STUB_H_

#include <base/observer_list.h>
#include <vector>

#include "power_manager/powerd/system/display/display_watcher.h"

namespace power_manager::system {

// Stub implementation of DisplayWatcherInterface for testing.
class DisplayWatcherStub : public DisplayWatcherInterface {
 public:
  DisplayWatcherStub() = default;
  DisplayWatcherStub(const DisplayWatcherStub&) = delete;
  DisplayWatcherStub& operator=(const DisplayWatcherStub&) = delete;

  ~DisplayWatcherStub() override = default;

  void set_displays(const std::vector<DisplayInfo>& displays) {
    displays_ = displays;
  }

  // DisplayWatcherInterface implementation:
  const std::vector<DisplayInfo>& GetDisplays() const override;
  void AddObserver(DisplayWatcherObserver* observer) override;
  void RemoveObserver(DisplayWatcherObserver* observer) override;

  void AddDisplay(const DisplayInfo& display_info);
  void RemoveDisplay(const DisplayInfo& display_info);

 private:
  base::ObserverList<DisplayWatcherObserver> observers_;
  // Currently-connected displays.
  std::vector<DisplayInfo> displays_;
};

}  // namespace power_manager::system

#endif  // POWER_MANAGER_POWERD_SYSTEM_DISPLAY_DISPLAY_WATCHER_STUB_H_
