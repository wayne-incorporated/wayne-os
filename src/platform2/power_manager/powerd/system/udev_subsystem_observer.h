// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef POWER_MANAGER_POWERD_SYSTEM_UDEV_SUBSYSTEM_OBSERVER_H_
#define POWER_MANAGER_POWERD_SYSTEM_UDEV_SUBSYSTEM_OBSERVER_H_

#include <string>

#include <base/observer_list_types.h>

#include "power_manager/powerd/system/udev.h"

namespace power_manager::system {

struct UdevEvent;

// Interface for receiving notification of udev events from UdevInterface.
class UdevSubsystemObserver : public base::CheckedObserver {
 public:
  ~UdevSubsystemObserver() override = default;

  // Called when an event has been received from an observed subsystem.
  virtual void OnUdevEvent(const UdevEvent& event) = 0;
};

}  // namespace power_manager::system

#endif  // POWER_MANAGER_POWERD_SYSTEM_UDEV_SUBSYSTEM_OBSERVER_H_
