// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/common/battery_percentage_converter.h"

#include <algorithm>

#include "power_manager/common/power_constants.h"
#include "power_manager/common/prefs.h"
#include "power_manager/common/util.h"

#include <base/check.h>

namespace power_manager {

// static
std::unique_ptr<BatteryPercentageConverter>
BatteryPercentageConverter::CreateFromPrefs(PrefsInterface* prefs) {
  DCHECK(prefs);

  double low_battery_shutdown_percent = 0.0;
  prefs->GetDouble(power_manager::kLowBatteryShutdownPercentPref,
                   &low_battery_shutdown_percent);
  double full_factor = 1.0;
  prefs->GetDouble(power_manager::kPowerSupplyFullFactorPref, &full_factor);

  return std::make_unique<BatteryPercentageConverter>(
      low_battery_shutdown_percent, full_factor);
}

BatteryPercentageConverter::BatteryPercentageConverter(
    double low_battery_shutdown_percent, double full_factor)
    : low_battery_shutdown_percent_(low_battery_shutdown_percent),
      full_factor_(std::min(std::max(kEpsilon, full_factor), 1.0)) {}

BatteryPercentageConverter::~BatteryPercentageConverter() = default;

double BatteryPercentageConverter::ConvertActualToDisplay(
    double actual_percentage) const {
  return util::ClampPercent(
      100.0 * (actual_percentage - low_battery_shutdown_percent_) /
      (100.0 * full_factor_ - low_battery_shutdown_percent_));
}

double BatteryPercentageConverter::ConvertDisplayToActual(
    double display_percentage) const {
  return util::ClampPercent(
      full_factor_ * display_percentage + low_battery_shutdown_percent_ -
      display_percentage * low_battery_shutdown_percent_ / 100.0);
}

}  // namespace power_manager
