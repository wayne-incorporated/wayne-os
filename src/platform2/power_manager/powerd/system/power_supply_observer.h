// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef POWER_MANAGER_POWERD_SYSTEM_POWER_SUPPLY_OBSERVER_H_
#define POWER_MANAGER_POWERD_SYSTEM_POWER_SUPPLY_OBSERVER_H_

#include <base/observer_list_types.h>

namespace power_manager::system {

struct PowerStatus;

class PowerSupplyObserver : public base::CheckedObserver {
 public:
  ~PowerSupplyObserver() override = default;

  // Called when the power status has been updated.
  virtual void OnPowerStatusUpdate() = 0;
};

}  // namespace power_manager::system

#endif  // POWER_MANAGER_POWERD_SYSTEM_POWER_SUPPLY_OBSERVER_H_
