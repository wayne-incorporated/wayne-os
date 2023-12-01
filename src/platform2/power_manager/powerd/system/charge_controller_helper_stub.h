// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef POWER_MANAGER_POWERD_SYSTEM_CHARGE_CONTROLLER_HELPER_STUB_H_
#define POWER_MANAGER_POWERD_SYSTEM_CHARGE_CONTROLLER_HELPER_STUB_H_

#include <map>
#include <string>

#include "power_manager/powerd/system/charge_controller_helper_interface.h"

namespace power_manager::system {

// Stub implementation of ChargeControllerHelperInterface for use by tests.
class ChargeControllerHelperStub : public ChargeControllerHelperInterface {
 public:
  static const int kPeakShiftThresholdUnset;

  static const PowerManagementPolicy::BatteryChargeMode::Mode
      kBatteryChargeModeUnset;
  static const int kCustomChargeThresholdUnset;

  ChargeControllerHelperStub() = default;
  ChargeControllerHelperStub(const ChargeControllerHelperStub&) = delete;
  ChargeControllerHelperStub& operator=(const ChargeControllerHelperStub&) =
      delete;

  ~ChargeControllerHelperStub() override = default;

  bool peak_shift_enabled() const { return peak_shift_enabled_; }
  int peak_shift_threshold() const { return peak_shift_threshold_; }
  std::string peak_shift_day_config(PowerManagementPolicy::WeekDay day) const {
    const auto& it = peak_shift_day_configs_.find(day);
    return it != peak_shift_day_configs_.end() ? it->second : std::string();
  }

  bool boot_on_ac_enabled() const { return boot_on_ac_enabled_; }

  bool usb_power_share_enabled() const { return usb_power_share_enabled_; }

  bool advanced_battery_charge_mode_enabled() const {
    return advanced_battery_charge_mode_enabled_;
  }
  std::string advanced_battery_charge_mode_day_config(
      PowerManagementPolicy::WeekDay day) const {
    const auto& it = advanced_battery_charge_mode_day_configs_.find(day);
    return it != advanced_battery_charge_mode_day_configs_.end()
               ? it->second
               : std::string();
  }

  PowerManagementPolicy::BatteryChargeMode::Mode battery_charge_mode() const {
    return battery_charge_mode_;
  }
  int custom_charge_start() const { return custom_charge_start_; }
  int custom_charge_stop() const { return custom_charge_stop_; }

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
                                        int custom_charge_end) override;

  void Reset();

 private:
  bool peak_shift_enabled_ = false;
  int peak_shift_threshold_ = kPeakShiftThresholdUnset;
  std::map<PowerManagementPolicy::WeekDay, std::string> peak_shift_day_configs_;

  bool boot_on_ac_enabled_ = false;

  bool usb_power_share_enabled_ = false;

  bool advanced_battery_charge_mode_enabled_ = false;
  std::map<PowerManagementPolicy::WeekDay, std::string>
      advanced_battery_charge_mode_day_configs_;

  PowerManagementPolicy::BatteryChargeMode::Mode battery_charge_mode_ =
      kBatteryChargeModeUnset;
  int custom_charge_start_ = kCustomChargeThresholdUnset;
  int custom_charge_stop_ = kCustomChargeThresholdUnset;
};

}  // namespace power_manager::system

#endif  // POWER_MANAGER_POWERD_SYSTEM_CHARGE_CONTROLLER_HELPER_STUB_H_
