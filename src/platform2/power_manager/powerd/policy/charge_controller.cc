// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/powerd/policy/charge_controller.h"

#include <algorithm>
#include <cmath>

#include <base/check.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>

#include "power_manager/common/battery_percentage_converter.h"
#include "power_manager/powerd/system/charge_controller_helper_interface.h"

namespace power_manager::policy {

namespace {

std::string GetWeekDayDebugString(
    PowerManagementPolicy::WeekDay proto_week_day) {
  switch (proto_week_day) {
    case PowerManagementPolicy::MONDAY:
      return "monday";
    case PowerManagementPolicy::TUESDAY:
      return "tuesday";
    case PowerManagementPolicy::WEDNESDAY:
      return "wednesday";
    case PowerManagementPolicy::THURSDAY:
      return "thursday";
    case PowerManagementPolicy::FRIDAY:
      return "friday";
    case PowerManagementPolicy::SATURDAY:
      return "saturday";
    case PowerManagementPolicy::SUNDAY:
      return "sunday";
  }
  return base::StringPrintf("invalid (%d)", proto_week_day);
}

std::string GetBatteryChargeModeDebugString(
    PowerManagementPolicy::BatteryChargeMode::Mode battery_charge_mode) {
  switch (battery_charge_mode) {
    case PowerManagementPolicy::BatteryChargeMode::STANDARD:
      return "standard";
    case PowerManagementPolicy::BatteryChargeMode::EXPRESS_CHARGE:
      return "express_charge";
    case PowerManagementPolicy::BatteryChargeMode::PRIMARILY_AC_USE:
      return "primarily_ac_use";
    case PowerManagementPolicy::BatteryChargeMode::ADAPTIVE:
      return "adaptive";
    case PowerManagementPolicy::BatteryChargeMode::CUSTOM:
      return "custom";
  }
  return base::StringPrintf("invalid (%d)", battery_charge_mode);
}

std::string GetPeakShiftDayConfigDebugString(
    const PowerManagementPolicy::PeakShiftDayConfig& day_config) {
  return base::StringPrintf(
      "{day=%s time=%02d:%02d %02d:%02d %02d:%02d}",
      GetWeekDayDebugString(day_config.day()).c_str(),
      day_config.start_time().hour(), day_config.start_time().minute(),
      day_config.end_time().hour(), day_config.end_time().minute(),
      day_config.charge_start_time().hour(),
      day_config.charge_start_time().minute());
}

std::string GetAdvancedBatteryChargeModeDayConfigDebugString(
    const PowerManagementPolicy::AdvancedBatteryChargeModeDayConfig&
        day_config) {
  return base::StringPrintf("{day=%s time=%02d:%02d %02d:%02d}",
                            GetWeekDayDebugString(day_config.day()).c_str(),
                            day_config.charge_start_time().hour(),
                            day_config.charge_start_time().minute(),
                            day_config.charge_end_time().hour(),
                            day_config.charge_end_time().minute());
}

std::string GetPowerPolicyDebugString(const PowerManagementPolicy& policy) {
  std::string str;
  if (policy.has_peak_shift_battery_percent_threshold()) {
    str += "peak_shift_battery_percent_threshold=" +
           base::NumberToString(policy.peak_shift_battery_percent_threshold()) +
           " ";
  }
  if (policy.peak_shift_day_configs_size()) {
    str += "peak_shift_day_configs=[";
    str += GetPeakShiftDayConfigDebugString(policy.peak_shift_day_configs(0));
    for (int i = 1; i < policy.peak_shift_day_configs_size(); i++) {
      str += ", " +
             GetPeakShiftDayConfigDebugString(policy.peak_shift_day_configs(i));
    }
    str += "] ";
  }

  if (policy.has_boot_on_ac()) {
    str += "boot_on_ac=";
    str += policy.boot_on_ac() ? "true " : "false ";
  }

  if (policy.has_usb_power_share()) {
    str += "usb_power_share=";
    str += policy.usb_power_share() ? "true " : "false ";
  }

  if (policy.advanced_battery_charge_mode_day_configs_size()) {
    str += "advanced_battery_charge_mode_day_configs=[";
    str += GetAdvancedBatteryChargeModeDayConfigDebugString(
        policy.advanced_battery_charge_mode_day_configs(0));
    for (int i = 1; i < policy.advanced_battery_charge_mode_day_configs_size();
         i++) {
      str += ", " + GetAdvancedBatteryChargeModeDayConfigDebugString(
                        policy.advanced_battery_charge_mode_day_configs(i));
    }
    str += "] ";
  }

  if (policy.has_battery_charge_mode()) {
    if (policy.battery_charge_mode().has_mode()) {
      str +=
          "battery_charge_mode=" +
          GetBatteryChargeModeDebugString(policy.battery_charge_mode().mode()) +
          " ";
    }
    if (policy.battery_charge_mode().has_custom_charge_start()) {
      str += base::StringPrintf(
          "custom_charge_start=%d ",
          policy.battery_charge_mode().custom_charge_start());
    }
    if (policy.battery_charge_mode().has_custom_charge_stop()) {
      str +=
          base::StringPrintf("custom_charge_stop=%d ",
                             policy.battery_charge_mode().custom_charge_stop());
    }
  }

  base::TrimString(str, " ", &str);
  return str;
}

}  // namespace

constexpr int ChargeController::kCustomChargeModeStartMin = 50;
constexpr int ChargeController::kCustomChargeModeStartMax = 95;

constexpr int ChargeController::kCustomChargeModeEndMin = 55;
constexpr int ChargeController::kCustomChargeModeEndMax = 100;

constexpr int ChargeController::kCustomChargeModeThresholdsMinDiff = 5;

constexpr int ChargeController::kPeakShiftBatteryThresholdMin = 15;
constexpr int ChargeController::kPeakShiftBatteryThresholdMax = 100;

// static
void ChargeController::ClampCustomBatteryChargeThresholds(int* start,
                                                          int* end) {
  DCHECK(start);
  DCHECK(end);
  *end = std::clamp(*end, kCustomChargeModeEndMin, kCustomChargeModeEndMax);
  *start =
      std::clamp(std::min(*start, *end - kCustomChargeModeThresholdsMinDiff),
                 kCustomChargeModeStartMin, kCustomChargeModeStartMax);
}

// static
int ChargeController::ClampPeakShiftBatteryThreshold(int threshold) {
  return std::clamp(threshold, kPeakShiftBatteryThresholdMin,
                    kPeakShiftBatteryThresholdMax);
}

ChargeController::ChargeController() = default;

ChargeController::~ChargeController() = default;

void ChargeController::Init(
    system::ChargeControllerHelperInterface* helper,
    BatteryPercentageConverter* battery_percentage_converter) {
  DCHECK(helper);
  DCHECK(battery_percentage_converter);
  helper_ = helper;
  battery_percentage_converter_ = battery_percentage_converter;
}

void ChargeController::HandlePolicyChange(const PowerManagementPolicy& policy) {
  if (IsPolicyEqualToCache(policy)) {
    return;
  }

  LOG(INFO) << "Received updated power policies: "
            << GetPowerPolicyDebugString(policy);

  if (ApplyPolicyChange(policy)) {
    cached_policy_ = policy;
  } else {
    cached_policy_.reset();
  }
}

bool ChargeController::ApplyPolicyChange(const PowerManagementPolicy& policy) {
  DCHECK(helper_);

  // Try to apply as many changes as possible.
  bool success = ApplyPeakShiftChange(policy);
  success &= ApplyBootOnAcChange(policy);
  success &= ApplyUsbPowerShareChange(policy);
  success &= ApplyAdvancedBatteryChargeModeChange(policy);
  success &= ApplyBatteryChargeModeChange(policy);

  return success;
}

bool ChargeController::ApplyPeakShiftChange(
    const PowerManagementPolicy& policy) {
  if (!policy.has_peak_shift_battery_percent_threshold() ||
      policy.peak_shift_day_configs_size() == 0) {
    return helper_->SetPeakShiftEnabled(false);
  }

  if (!helper_->SetPeakShiftEnabled(true)) {
    return false;
  }

  int actual_battery_percent_threshold =
      std::round(battery_percentage_converter_->ConvertDisplayToActual(
          policy.peak_shift_battery_percent_threshold()));
  actual_battery_percent_threshold =
      ClampPeakShiftBatteryThreshold(actual_battery_percent_threshold);

  if (!helper_->SetPeakShiftBatteryPercentThreshold(
          actual_battery_percent_threshold)) {
    return false;
  }
  for (const auto& day_config : policy.peak_shift_day_configs()) {
    if (!SetPeakShiftDayConfig(day_config)) {
      return false;
    }
  }

  return true;
}

bool ChargeController::ApplyBootOnAcChange(
    const PowerManagementPolicy& policy) {
  // Disable if |boot_on_ac| is unset.
  return helper_->SetBootOnAcEnabled(policy.boot_on_ac());
}

bool ChargeController::ApplyUsbPowerShareChange(
    const PowerManagementPolicy& policy) {
  // Disable if |usb_power_share| is unset.
  return helper_->SetUsbPowerShareEnabled(policy.usb_power_share());
}

bool ChargeController::ApplyAdvancedBatteryChargeModeChange(
    const PowerManagementPolicy& policy) {
  if (policy.advanced_battery_charge_mode_day_configs_size() == 0) {
    return helper_->SetAdvancedBatteryChargeModeEnabled(false);
  }

  if (!helper_->SetAdvancedBatteryChargeModeEnabled(true)) {
    return false;
  }
  for (const auto& day_config :
       policy.advanced_battery_charge_mode_day_configs()) {
    if (!SetAdvancedBatteryChargeModeDayConfig(day_config)) {
      return false;
    }
  }
  return true;
}

bool ChargeController::ApplyBatteryChargeModeChange(
    const PowerManagementPolicy& policy) {
  // If AdvancedBatteryChargeMode is specified, it overrides BatteryChargeMode.
  if (policy.advanced_battery_charge_mode_day_configs_size() != 0) {
    return true;
  }

  // STANDARD charge mode if either |battery_charge_mode| or
  // |battery_charge_mode().mode| is unset.
  if (!helper_->SetBatteryChargeMode(policy.battery_charge_mode().mode())) {
    return false;
  }

  if (policy.battery_charge_mode().mode() !=
      PowerManagementPolicy::BatteryChargeMode::CUSTOM) {
    return true;
  }

  if (!policy.battery_charge_mode().has_custom_charge_start() ||
      !policy.battery_charge_mode().has_custom_charge_stop()) {
    LOG(ERROR) << "Start charge or stop charge is unset for custom battery"
               << " charge mode";
    return false;
  }

  int custom_charge_start =
      std::round(battery_percentage_converter_->ConvertDisplayToActual(
          policy.battery_charge_mode().custom_charge_start()));
  int custom_charge_end =
      std::round(battery_percentage_converter_->ConvertDisplayToActual(
          policy.battery_charge_mode().custom_charge_stop()));

  ClampCustomBatteryChargeThresholds(&custom_charge_start, &custom_charge_end);

  return helper_->SetBatteryChargeCustomThresholds(custom_charge_start,
                                                   custom_charge_end);
}

bool ChargeController::SetPeakShiftDayConfig(
    const PowerManagementPolicy::PeakShiftDayConfig& day_config) {
  if (!day_config.has_day() || !day_config.has_start_time() ||
      !day_config.start_time().has_hour() ||
      !day_config.start_time().has_minute() || !day_config.has_end_time() ||
      !day_config.end_time().has_hour() ||
      !day_config.end_time().has_minute() ||
      !day_config.has_charge_start_time() ||
      !day_config.charge_start_time().has_hour() ||
      !day_config.charge_start_time().has_minute()) {
    LOG(WARNING) << "Invalid peak shift day config proto";
    return false;
  }

  std::string day_config_str = base::StringPrintf(
      "%02d:%02d %02d:%02d %02d:%02d", day_config.start_time().hour(),
      day_config.start_time().minute(), day_config.end_time().hour(),
      day_config.end_time().minute(), day_config.charge_start_time().hour(),
      day_config.charge_start_time().minute());
  return helper_->SetPeakShiftDayConfig(day_config.day(), day_config_str);
}

bool ChargeController::SetAdvancedBatteryChargeModeDayConfig(
    const PowerManagementPolicy::AdvancedBatteryChargeModeDayConfig&
        day_config) {
  if (!day_config.has_day() || !day_config.has_charge_start_time() ||
      !day_config.charge_start_time().has_hour() ||
      !day_config.charge_start_time().has_minute() ||
      !day_config.has_charge_end_time() ||
      !day_config.charge_end_time().has_hour() ||
      !day_config.charge_end_time().has_minute()) {
    LOG(WARNING) << "Invalid advanced battery charge mode day config proto";
    return false;
  }

  int start_time_minutes = day_config.charge_start_time().hour() * 60 +
                           day_config.charge_start_time().minute();
  int end_time_minutes = day_config.charge_end_time().hour() * 60 +
                         day_config.charge_end_time().minute();
  if (start_time_minutes > end_time_minutes) {
    LOG(WARNING) << "Invalid advanced battery charge mode day config proto:"
                 << " start time must be less or equal than end time";
    return false;
  }

  // Policy uses charge end time, but EC driver uses charge duration.
  int duration_minutes = end_time_minutes - start_time_minutes;
  std::string day_config_str = base::StringPrintf(
      "%02d:%02d %02d:%02d", day_config.charge_start_time().hour(),
      day_config.charge_start_time().minute(), duration_minutes / 60,
      duration_minutes % 60);
  return helper_->SetAdvancedBatteryChargeModeDayConfig(day_config.day(),
                                                        day_config_str);
}

bool ChargeController::IsPolicyEqualToCache(
    const PowerManagementPolicy& policy) const {
  if (!cached_policy_.has_value()) {
    return false;
  }

  if (policy.has_peak_shift_battery_percent_threshold() !=
          cached_policy_->has_peak_shift_battery_percent_threshold() ||
      policy.peak_shift_battery_percent_threshold() !=
          cached_policy_->peak_shift_battery_percent_threshold()) {
    return false;
  }

  if (policy.peak_shift_day_configs_size() !=
      cached_policy_->peak_shift_day_configs_size()) {
    return false;
  }
  for (int i = 0; i < policy.peak_shift_day_configs_size(); i++) {
    if (policy.peak_shift_day_configs(i).SerializeAsString() !=
        cached_policy_->peak_shift_day_configs(i).SerializeAsString()) {
      return false;
    }
  }

  if (policy.has_boot_on_ac() != cached_policy_->has_boot_on_ac() ||
      policy.boot_on_ac() != cached_policy_->boot_on_ac()) {
    return false;
  }

  if (policy.has_usb_power_share() != cached_policy_->has_usb_power_share() ||
      policy.usb_power_share() != cached_policy_->usb_power_share()) {
    return false;
  }

  if (policy.advanced_battery_charge_mode_day_configs_size() !=
      cached_policy_->advanced_battery_charge_mode_day_configs_size()) {
    return false;
  }
  for (int i = 0; i < policy.advanced_battery_charge_mode_day_configs_size();
       i++) {
    if (policy.advanced_battery_charge_mode_day_configs(i)
            .SerializeAsString() !=
        cached_policy_->advanced_battery_charge_mode_day_configs(i)
            .SerializeAsString()) {
      return false;
    }
  }

  if (policy.battery_charge_mode().SerializeAsString() !=
      cached_policy_->battery_charge_mode().SerializeAsString()) {
    return false;
  }

  return true;
}

}  // namespace power_manager::policy
