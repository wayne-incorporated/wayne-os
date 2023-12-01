// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef POWER_MANAGER_POWERD_SYSTEM_WILCO_CHARGE_CONTROLLER_HELPER_H_
#define POWER_MANAGER_POWERD_SYSTEM_WILCO_CHARGE_CONTROLLER_HELPER_H_

#include <string>

#include "power_manager/powerd/system/charge_controller_helper_interface.h"

namespace power_manager::system {

// Real implementation of ChargeControllerHelperInterface.
class WilcoChargeControllerHelper final
    : public ChargeControllerHelperInterface {
 public:
  WilcoChargeControllerHelper();
  WilcoChargeControllerHelper(const WilcoChargeControllerHelper&) = delete;
  WilcoChargeControllerHelper& operator=(const WilcoChargeControllerHelper&) =
      delete;

  ~WilcoChargeControllerHelper() override;

  // ChargeControllerHelperInterface overrides:
  bool SetPeakShiftEnabled(bool enable) override;
  bool SetPeakShiftBatteryPercentThreshold(int threshold) override;
  bool SetPeakShiftDayConfig(PowerManagementPolicy::WeekDay week_day,
                             const std::string& config) override;
  bool SetBootOnAcEnabled(bool enable) override;
  bool SetUsbPowerShareEnabled(bool enable) override;
  bool SetAdvancedBatteryChargeModeEnabled(bool enable) override;
  bool SetAdvancedBatteryChargeModeDayConfig(
      PowerManagementPolicy::WeekDay week_day,
      const std::string& config) override;
  bool SetBatteryChargeMode(
      PowerManagementPolicy::BatteryChargeMode::Mode mode) override;
  bool SetBatteryChargeCustomThresholds(int custom_charge_start,
                                        int custom_charge_stop) override;
};

}  // namespace power_manager::system

#endif  // POWER_MANAGER_POWERD_SYSTEM_WILCO_CHARGE_CONTROLLER_HELPER_H_
