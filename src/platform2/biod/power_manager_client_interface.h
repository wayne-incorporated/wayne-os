// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BIOD_POWER_MANAGER_CLIENT_INTERFACE_H_
#define BIOD_POWER_MANAGER_CLIENT_INTERFACE_H_

#include <power_manager/dbus-proxies.h>

#include "biod/power_event_observer.h"

namespace biod {

class PowerManagerClientInterface {
 public:
  PowerManagerClientInterface() = default;
  PowerManagerClientInterface(const PowerManagerClientInterface&) = delete;
  PowerManagerClientInterface& operator=(const PowerManagerClientInterface&) =
      delete;

  virtual ~PowerManagerClientInterface() = default;

  // Interface to add observers interested in powerd events.
  virtual void AddObserver(PowerEventObserver* observer) = 0;
  virtual bool HasObserver(PowerEventObserver* observer) = 0;
  virtual void RemoveObserver(PowerEventObserver* observer) = 0;
};

}  // namespace biod

#endif  // BIOD_POWER_MANAGER_CLIENT_INTERFACE_H_
