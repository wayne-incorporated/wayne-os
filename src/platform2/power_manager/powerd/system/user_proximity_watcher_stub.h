// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef POWER_MANAGER_POWERD_SYSTEM_USER_PROXIMITY_WATCHER_STUB_H_
#define POWER_MANAGER_POWERD_SYSTEM_USER_PROXIMITY_WATCHER_STUB_H_

#include <base/observer_list.h>
#include <vector>

#include "power_manager/common/power_constants.h"
#include "power_manager/powerd/system/user_proximity_watcher_interface.h"

namespace power_manager::system {

// Stub implementation of UserProximityWatcherInterface for use by tests.
class UserProximityWatcherStub : public UserProximityWatcherInterface {
 public:
  UserProximityWatcherStub() = default;
  UserProximityWatcherStub(const UserProximityWatcherStub&) = delete;
  UserProximityWatcherStub& operator=(const UserProximityWatcherStub&) = delete;

  ~UserProximityWatcherStub() override = default;

  const std::vector<TabletMode>& tablet_mode_changes() const {
    return tablet_mode_changes_;
  }

  // UserProximityWatcherInterface overrides:
  void AddObserver(UserProximityObserver* observer) override;
  void RemoveObserver(UserProximityObserver* observer) override;
  void HandleTabletModeChange(TabletMode mode) override;

  void AddSensor(int id, uint32_t role);
  void SendEvent(int id, UserProximity proximity);

 private:
  base::ObserverList<UserProximityObserver> observers_;
  std::vector<TabletMode> tablet_mode_changes_;
};

}  // namespace power_manager::system

#endif  // POWER_MANAGER_POWERD_SYSTEM_USER_PROXIMITY_WATCHER_STUB_H_
