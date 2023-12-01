// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/powerd/system/power_supply_stub.h"

#include <base/check.h>

namespace power_manager::system {

void PowerSupplyStub::NotifyObservers() {
  for (PowerSupplyObserver& observer : observers_)
    observer.OnPowerStatusUpdate();
}

void PowerSupplyStub::AddObserver(PowerSupplyObserver* observer) {
  CHECK(observer);
  observers_.AddObserver(observer);
}

void PowerSupplyStub::RemoveObserver(PowerSupplyObserver* observer) {
  CHECK(observer);
  observers_.RemoveObserver(observer);
}

PowerStatus PowerSupplyStub::GetPowerStatus() const {
  return status_;
}

bool PowerSupplyStub::RefreshImmediately() {
  return refresh_result_;
}

void PowerSupplyStub::SetSuspended(bool suspended) {
  suspended_ = suspended;
}

void PowerSupplyStub::SetAdaptiveChargingSupported(bool supported) {}

void PowerSupplyStub::SetAdaptiveChargingHeuristicEnabled(bool enabled) {}

void PowerSupplyStub::SetAdaptiveCharging(
    const base::TimeDelta& target_time_to_full, double hold_percent) {}

void PowerSupplyStub::ClearAdaptiveChargingChargeDelay() {}

}  // namespace power_manager::system
