// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/powerd/system/display/display_watcher_stub.h"

#include <base/check.h>
#include <base/logging.h>

namespace power_manager::system {

const std::vector<DisplayInfo>& DisplayWatcherStub::GetDisplays() const {
  return displays_;
}

void DisplayWatcherStub::AddObserver(DisplayWatcherObserver* observer) {
  CHECK(observer);
  observers_.AddObserver(observer);
}

void DisplayWatcherStub::RemoveObserver(DisplayWatcherObserver* observer) {
  CHECK(observer);
  observers_.RemoveObserver(observer);
}

void DisplayWatcherStub::AddDisplay(const DisplayInfo& display_info) {
  for (const auto& display : displays_) {
    if (display == display_info) {
      return;
    }
  }

  displays_.push_back(display_info);

  for (auto& observer : observers_) {
    observer.OnDisplaysChanged(displays_);
  }
}

void DisplayWatcherStub::RemoveDisplay(const DisplayInfo& display_info) {
  bool found = false;
  for (auto it = displays_.begin(); it != displays_.end(); it++) {
    if (*it == display_info) {
      displays_.erase(it);
      found = true;
      break;
    }
  }

  if (!found) {
    return;
  }

  for (auto& observer : observers_) {
    observer.OnDisplaysChanged(displays_);
  }
}

}  // namespace power_manager::system
