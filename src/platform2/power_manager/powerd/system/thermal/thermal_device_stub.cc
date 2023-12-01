// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/powerd/system/thermal/thermal_device_stub.h"

#include "power_manager/powerd/system/thermal/device_thermal_state.h"
#include "power_manager/powerd/system/thermal/thermal_device.h"

#include <base/check.h>

namespace power_manager::system {

void ThermalDeviceStub::AddObserver(ThermalDeviceObserver* observer) {
  DCHECK(observer);
  observers_.AddObserver(observer);
}

void ThermalDeviceStub::RemoveObserver(ThermalDeviceObserver* observer) {
  DCHECK(observer);
  observers_.RemoveObserver(observer);
}

DeviceThermalState ThermalDeviceStub::GetThermalState() const {
  return current_state_;
}

void ThermalDeviceStub::NotifyObservers() {
  for (auto& observer : observers_)
    observer.OnThermalChanged(this);
}

ThermalDeviceType ThermalDeviceStub::GetType() const {
  return type_;
}

}  // namespace power_manager::system
