// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef POWER_MANAGER_POWERD_SYSTEM_THERMAL_THERMAL_DEVICE_OBSERVER_H_
#define POWER_MANAGER_POWERD_SYSTEM_THERMAL_THERMAL_DEVICE_OBSERVER_H_

#include <base/observer_list_types.h>

namespace power_manager::system {

class ThermalDeviceInterface;

// Interface for classes interested in receiving updates about thermal states
// from thermal devices.
class ThermalDeviceObserver : public base::CheckedObserver {
 public:
  ~ThermalDeviceObserver() override = default;

  // Called when the thermal state changed.
  virtual void OnThermalChanged(ThermalDeviceInterface* sensor) = 0;
};

}  // namespace power_manager::system

#endif  // POWER_MANAGER_POWERD_SYSTEM_THERMAL_THERMAL_DEVICE_OBSERVER_H_
