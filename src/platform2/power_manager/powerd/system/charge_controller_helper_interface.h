// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef POWER_MANAGER_POWERD_SYSTEM_CHARGE_CONTROLLER_HELPER_INTERFACE_H_
#define POWER_MANAGER_POWERD_SYSTEM_CHARGE_CONTROLLER_HELPER_INTERFACE_H_

#include <string>

#include "power_manager/proto_bindings/policy.pb.h"

namespace power_manager::system {

// Important note: It is not final version of interface,
// blocked by b:125011171.
//
// Interface for classes to perform the actions requested by
// |policy::ChargeController|.
//
// All methods return true on success and false on failure.
class ChargeControllerHelperInterface {
 public:
  virtual ~ChargeControllerHelperInterface() = default;

  // Enables or disables peak shift.
  virtual bool SetPeakShiftEnabled(bool enable) = 0;

  // Sets the lower bound of the battery charge (as a percent in [0, 100])
  // for using peak shift.
  virtual bool SetPeakShiftBatteryPercentThreshold(int threshold) = 0;

  // Configures when peak shift will be enabled on |week_day|.
  // |config| contains space separated zero-leading hour and minute of
  // start time, end time and charge start time,
  // i.e. "00 30 09 45 20 00" means:
  //     - 00:30 is start time,
  //     - 09:45 is end time,
  //     - 20:00 is charge start time.
  virtual bool SetPeakShiftDayConfig(PowerManagementPolicy::WeekDay week_day,
                                     const std::string& config) = 0;

  // Enables or disables boot on AC.
  virtual bool SetBootOnAcEnabled(bool enable) = 0;

  // Enables or disables charging USB devices from specific ports while the
  // system is suspended or shut down.
  virtual bool SetUsbPowerShareEnabled(bool enable) = 0;

  // Enables or disables advanced battery charge mode.
  virtual bool SetAdvancedBatteryChargeModeEnabled(bool enable) = 0;

  // Configures when advanced battery charge mode will be enabled on |week_day|.
  // |config| contains space separated zero-leading hour and minute of
  // charge start time and charge duration,
  // i.e. "09 15 02 30" means:
  //     - 09:15 is charge start time,
  //     - 02:30 is charge duration.
  virtual bool SetAdvancedBatteryChargeModeDayConfig(
      PowerManagementPolicy::WeekDay week_day, const std::string& config) = 0;

  // Sets battery charge mode. When custom mode is selected then charge
  // thresholds must be specified via |SetBatteryChargeCustomThresholds|.
  virtual bool SetBatteryChargeMode(
      PowerManagementPolicy::BatteryChargeMode::Mode mode) = 0;

  // Configures charge thresholds for custom battery charge mode.
  // Charging begins when battery level drops below |custom_charge_start|, and
  // ceases when battery level is above |custom_charge_stop|.
  virtual bool SetBatteryChargeCustomThresholds(int custom_charge_start,
                                                int custom_charge_stop) = 0;
};

}  // namespace power_manager::system

#endif  // POWER_MANAGER_POWERD_SYSTEM_CHARGE_CONTROLLER_HELPER_INTERFACE_H_
