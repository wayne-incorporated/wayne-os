// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef POWER_MANAGER_COMMON_BATTERY_PERCENTAGE_CONVERTER_H_
#define POWER_MANAGER_COMMON_BATTERY_PERCENTAGE_CONVERTER_H_

#include <memory>

namespace power_manager {

class PrefsInterface;

// Converts actual battery percentage to display battery percentage and vice
// versa.
class BatteryPercentageConverter {
 public:
  static std::unique_ptr<BatteryPercentageConverter> CreateFromPrefs(
      PrefsInterface* prefs);

  BatteryPercentageConverter(double low_battery_shutdown_percent,
                             double full_factor);
  BatteryPercentageConverter(const BatteryPercentageConverter&) = delete;
  BatteryPercentageConverter& operator=(const BatteryPercentageConverter&) =
      delete;

  ~BatteryPercentageConverter();

  // Converts actual battery percentage to the battery percentage which will be
  // displayed to the user. Returns value in the range [0.0, 100.0].
  double ConvertActualToDisplay(double actual_percentage) const;

  // Converts displayed battery percentage to the actual battery percentage.
  // Returns value in the range [0.0, 100.0].
  double ConvertDisplayToActual(double display_percentage) const;

 private:
  // Remaining battery percentage at which the system will shut down
  // automatically. 0.0 if unset. Initialized from
  // |kLowBatteryShutdownPercentPref|.
  const double low_battery_shutdown_percent_ = 0.0;

  // The fraction of the full charge at which the battery is considered full,
  // in the range (0.0, 1.0]. Initialized from |kPowerSupplyFullFactorPref|.
  const double full_factor_ = 1.0;
};

}  // namespace power_manager

#endif  // POWER_MANAGER_COMMON_BATTERY_PERCENTAGE_CONVERTER_H_
