// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef POWER_MANAGER_POWERD_POLICY_CHARGE_CONTROLLER_H_
#define POWER_MANAGER_POWERD_POLICY_CHARGE_CONTROLLER_H_

#include <optional>
#include <string>

#include "power_manager/proto_bindings/policy.pb.h"

namespace power_manager {

class BatteryPercentageConverter;

namespace system {
class ChargeControllerHelperInterface;
}  // namespace system

namespace policy {

// ChargeController is responsible for handling power policies:
// peak shift, advanced battery charge.
class ChargeController {
 public:
  // Min and max values for actual battery percentage |start| threshold for
  // custom battery charge mode.
  static const int kCustomChargeModeStartMin;
  static const int kCustomChargeModeStartMax;

  // Min and max values for actual battery percentage |end| threshold for
  // custom battery charge mode.
  static const int kCustomChargeModeEndMin;
  static const int kCustomChargeModeEndMax;

  // Min difference between actual battery percentage thresholds for custom
  // battery charge mode.
  static const int kCustomChargeModeThresholdsMinDiff;

  // Min and max values for actual battery percentage threshold for
  // peak shift.
  static const int kPeakShiftBatteryThresholdMin;
  static const int kPeakShiftBatteryThresholdMax;

  // Clamps actual battery percentage thresholds for custom battery charge
  // mode:
  //   1) |start| should be in the range
  //          [kCustomChargeModeStartMin, kCustomChargeModeStartMax];
  //   2) |end| should be in the range
  //          [kCustomChargeModeEndMin, kCustomChargeModeEndMax];
  //   3) difference between |end| and |start| should be at least 5.
  static void ClampCustomBatteryChargeThresholds(int* start, int* end);

  // Clamps actual battery percentage threshold for peak shift.
  // Threshold should be in the range:
  //     [kPeakShiftBatteryThresholdMin, kPeakShiftBatteryThresholdMax].
  static int ClampPeakShiftBatteryThreshold(int threshold);

  ChargeController();
  ChargeController(const ChargeController&) = delete;
  ChargeController& operator=(const ChargeController&) = delete;

  ~ChargeController();

  // |helper| and |battery_percentage_converter| must be non-null.
  void Init(system::ChargeControllerHelperInterface* helper,
            BatteryPercentageConverter* battery_percentage_converter);

  // Does nothing if |policy| and |cached_policy_| peak shift related fields
  // are equal. Otherwise updates the charging configuration per |policy| and
  // copies |policy| to |cached_policy_|.
  void HandlePolicyChange(const PowerManagementPolicy& policy);

 private:
  bool ApplyPolicyChange(const PowerManagementPolicy& policy);
  bool ApplyPeakShiftChange(const PowerManagementPolicy& policy);
  bool ApplyBootOnAcChange(const PowerManagementPolicy& policy);
  bool ApplyUsbPowerShareChange(const PowerManagementPolicy& policy);
  bool ApplyAdvancedBatteryChargeModeChange(
      const PowerManagementPolicy& policy);
  bool ApplyBatteryChargeModeChange(const PowerManagementPolicy& policy);

  // Calls delegate's |SetPeakShiftDayConfig| function and returns the result
  // if |day_config| contains all needed fields, otherwise returns false.
  bool SetPeakShiftDayConfig(
      const PowerManagementPolicy::PeakShiftDayConfig& day_config);

  // Calls delegate's |SetAdvancedBatteryChargeModeDayConfig| function and
  // returns the result if |day_config| contains all needed fields, otherwise
  // returns false.
  bool SetAdvancedBatteryChargeModeDayConfig(
      const PowerManagementPolicy::AdvancedBatteryChargeModeDayConfig&
          day_config);

  // Checks that charging-related fields are equal between |policy| and
  // |cached_policy_|.
  bool IsPolicyEqualToCache(const PowerManagementPolicy& policy) const;

  // Not owned.
  system::ChargeControllerHelperInterface* helper_ = nullptr;

  // Not owned.
  BatteryPercentageConverter* battery_percentage_converter_ = nullptr;

  // Contains last successfully applied power policies settings.
  std::optional<PowerManagementPolicy> cached_policy_;
};

}  // namespace policy
}  // namespace power_manager

#endif  // POWER_MANAGER_POWERD_POLICY_CHARGE_CONTROLLER_H_
