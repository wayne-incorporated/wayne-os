// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/powerd/system/wilco_charge_controller_helper.h"

#include <base/check.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/strings/stringprintf.h>
#include <brillo/file_utils.h>

namespace power_manager::system {

namespace {

constexpr const char kEcDriverSysfsDirectory[] =
    "/sys/bus/platform/devices/GOOG000C:00/";

// Relative path to |kEcDriverSysfsDirectory|.
constexpr const char kChargeScheduleDirectory[] = "wilco-charge-schedule/";

// Relative path to |kChargeScheduleDirectory|.
constexpr const char kPeakShiftDirectory[] = "peak_shift";
// Relative paths to |kPeakShiftDirectory|.
constexpr const char kPeakShiftEnablePath[] = "enable";
constexpr const char kPeakShiftThresholdPath[] = "battery_threshold";

// Relative path to |kChargeScheduleDirectory|.
constexpr const char kAdvancedChargingDirectory[] = "advanced_charging";
// Relative path to |kAdvancedChargingDirectory|.
constexpr const char kAdvancedChargingEnablePath[] = "enable";

// Relative path to |kEcDriverSysfsDirectory|.
constexpr const char kBootOnAcEnablePath[] = "boot_on_ac";

// Relative path to |kEcDriverSysfsDirectory|.
constexpr const char kUsbPowerShareEnablePath[] = "usb_charge";

constexpr const char kPowerSupplyDirectory[] =
    "/sys/class/power_supply/wilco-charger/";

// Relative path to |kPowerSupplyDirectory|.
constexpr const char kBatteryChargeModePath[] = "charge_type";

// Relative path to |kPowerSupplyDirectory|.
constexpr const char kBatteryChargeCustomChargeStartPath[] =
    "charge_control_start_threshold";

// Relative path to |kPowerSupplyDirectory|.
constexpr const char kBatteryChargeCustomChargeStopPath[] =
    "charge_control_end_threshold";

// Strings returned by this function are dictated by the kernel driver and
// can't be changed.
bool WeekDayToString(PowerManagementPolicy::WeekDay week_day,
                     std::string* week_day_out) {
  DCHECK(week_day_out);
  switch (week_day) {
    case PowerManagementPolicy::MONDAY:
      *week_day_out = "monday";
      return true;
    case PowerManagementPolicy::TUESDAY:
      *week_day_out = "tuesday";
      return true;
    case PowerManagementPolicy::WEDNESDAY:
      *week_day_out = "wednesday";
      return true;
    case PowerManagementPolicy::THURSDAY:
      *week_day_out = "thursday";
      return true;
    case PowerManagementPolicy::FRIDAY:
      *week_day_out = "friday";
      return true;
    case PowerManagementPolicy::SATURDAY:
      *week_day_out = "saturday";
      return true;
    case PowerManagementPolicy::SUNDAY:
      *week_day_out = "sunday";
      return true;
  }
  LOG(WARNING) << "Unexpected week day value " << static_cast<int>(week_day);
  return false;
}

bool WriteStringToFile(const base::FilePath& filename,
                       const std::string& data) {
  if (!brillo::WriteStringToFile(filename, data)) {
    PLOG(ERROR) << "Unable to write \"" << data << "\" to " << filename.value();
    return false;
  }
  return true;
}

}  // namespace

WilcoChargeControllerHelper::WilcoChargeControllerHelper() = default;

WilcoChargeControllerHelper::~WilcoChargeControllerHelper() = default;

bool WilcoChargeControllerHelper::SetPeakShiftEnabled(bool enable) {
  return WriteStringToFile(base::FilePath(kEcDriverSysfsDirectory)
                               .Append(kChargeScheduleDirectory)
                               .Append(kPeakShiftDirectory)
                               .Append(kPeakShiftEnablePath),
                           enable ? "1" : "0");
}

bool WilcoChargeControllerHelper::SetPeakShiftBatteryPercentThreshold(
    int threshold) {
  return WriteStringToFile(base::FilePath(kEcDriverSysfsDirectory)
                               .Append(kChargeScheduleDirectory)
                               .Append(kPeakShiftDirectory)
                               .Append(kPeakShiftThresholdPath),
                           base::StringPrintf("%d", threshold));
}

bool WilcoChargeControllerHelper::SetPeakShiftDayConfig(
    PowerManagementPolicy::WeekDay week_day, const std::string& config) {
  std::string week_day_str;
  return WeekDayToString(week_day, &week_day_str) &&
         WriteStringToFile(base::FilePath(kEcDriverSysfsDirectory)
                               .Append(kChargeScheduleDirectory)
                               .Append(kPeakShiftDirectory)
                               .Append(week_day_str),
                           config);
}

bool WilcoChargeControllerHelper::SetBootOnAcEnabled(bool enable) {
  return WriteStringToFile(
      base::FilePath(kEcDriverSysfsDirectory).Append(kBootOnAcEnablePath),
      enable ? "1" : "0");
}

bool WilcoChargeControllerHelper::SetUsbPowerShareEnabled(bool enable) {
  return WriteStringToFile(
      base::FilePath(kEcDriverSysfsDirectory).Append(kUsbPowerShareEnablePath),
      enable ? "1" : "0");
}

bool WilcoChargeControllerHelper::SetAdvancedBatteryChargeModeEnabled(
    bool enable) {
  return WriteStringToFile(base::FilePath(kEcDriverSysfsDirectory)
                               .Append(kChargeScheduleDirectory)
                               .Append(kAdvancedChargingDirectory)
                               .Append(kAdvancedChargingEnablePath),
                           enable ? "1" : "0");
}

bool WilcoChargeControllerHelper::SetAdvancedBatteryChargeModeDayConfig(
    PowerManagementPolicy::WeekDay week_day, const std::string& config) {
  std::string week_day_str;
  return WeekDayToString(week_day, &week_day_str) &&
         WriteStringToFile(base::FilePath(kEcDriverSysfsDirectory)
                               .Append(kChargeScheduleDirectory)
                               .Append(kAdvancedChargingDirectory)
                               .Append(week_day_str),
                           config);
}

bool WilcoChargeControllerHelper::SetBatteryChargeMode(
    PowerManagementPolicy::BatteryChargeMode::Mode mode) {
  std::string charge_type;
  switch (mode) {
    case PowerManagementPolicy::BatteryChargeMode::STANDARD:
      charge_type = "Standard";
      break;
    case PowerManagementPolicy::BatteryChargeMode::EXPRESS_CHARGE:
      charge_type = "Fast";
      break;
    case PowerManagementPolicy::BatteryChargeMode::PRIMARILY_AC_USE:
      charge_type = "Trickle";
      break;
    case PowerManagementPolicy::BatteryChargeMode::ADAPTIVE:
      charge_type = "Adaptive";
      break;
    case PowerManagementPolicy::BatteryChargeMode::CUSTOM:
      charge_type = "Custom";
      break;
  }
  if (charge_type.empty()) {
    LOG(WARNING) << "Invalid battery charge mode " << mode;
    return false;
  }
  return WriteStringToFile(
      base::FilePath(kPowerSupplyDirectory).Append(kBatteryChargeModePath),
      charge_type);
}

bool WilcoChargeControllerHelper::SetBatteryChargeCustomThresholds(
    int custom_charge_start, int custom_charge_stop) {
  return WriteStringToFile(base::FilePath(kPowerSupplyDirectory)
                               .Append(kBatteryChargeCustomChargeStartPath),
                           base::StringPrintf("%d", custom_charge_start)) &&
         WriteStringToFile(base::FilePath(kPowerSupplyDirectory)
                               .Append(kBatteryChargeCustomChargeStopPath),
                           base::StringPrintf("%d", custom_charge_stop));
}

}  // namespace power_manager::system
