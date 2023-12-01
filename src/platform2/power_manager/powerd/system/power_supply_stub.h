// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef POWER_MANAGER_POWERD_SYSTEM_POWER_SUPPLY_STUB_H_
#define POWER_MANAGER_POWERD_SYSTEM_POWER_SUPPLY_STUB_H_

#include "power_manager/powerd/system/power_supply.h"

#include <string>

#include <base/observer_list.h>
#include <base/time/time.h>

namespace power_manager::system {

// Stub implementation of PowerSupplyInterface used by tests.
class PowerSupplyStub : public PowerSupplyInterface {
 public:
  PowerSupplyStub() = default;

  PowerSupplyStub(const PowerSupplyStub&) = delete;
  PowerSupplyStub& operator=(const PowerSupplyStub&) = delete;

  ~PowerSupplyStub() override = default;

  void set_refresh_result(bool result) { refresh_result_ = result; }
  void set_status(const PowerStatus& status) { status_ = status; }

  bool suspended() const { return suspended_; }

  // Notifies registered observers that the power status has been updated.
  void NotifyObservers();

  // PowerSupplyInterface implementation:
  void AddObserver(PowerSupplyObserver* observer) override;
  void RemoveObserver(PowerSupplyObserver* observer) override;
  PowerStatus GetPowerStatus() const override;
  bool RefreshImmediately() override;
  void SetSuspended(bool suspended) override;
  void SetAdaptiveChargingSupported(bool supported) override;
  void SetAdaptiveChargingHeuristicEnabled(bool enabled) override;
  void SetAdaptiveCharging(const base::TimeDelta& target_time_to_full,
                           double hold_percent) override;
  void ClearAdaptiveChargingChargeDelay() override;

 private:
  // Result to return from RefreshImmediately().
  bool refresh_result_ = true;
  bool suspended_ = false;

  // Status to return.
  PowerStatus status_;

  base::ObserverList<PowerSupplyObserver> observers_;
};

}  // namespace power_manager::system

#endif  // POWER_MANAGER_POWERD_SYSTEM_POWER_SUPPLY_STUB_H_
