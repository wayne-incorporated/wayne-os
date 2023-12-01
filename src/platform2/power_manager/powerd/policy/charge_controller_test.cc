// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/powerd/policy/charge_controller.h"

#include <cmath>
#include <map>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/strings/string_split.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/stringprintf.h>
#include <gtest/gtest.h>

#include "power_manager/common/battery_percentage_converter.h"
#include "power_manager/powerd/system/charge_controller_helper_stub.h"
#include "power_manager/powerd/testing/test_environment.h"
#include "power_manager/proto_bindings/policy.pb.h"

namespace power_manager::policy {

namespace {

// Holds hours and minutes.
using TestDayConfig = std::vector<std::pair<int, int>>;

constexpr double kLowBatteryShutdownPercent = 4.0;
constexpr double kFullFactor = 0.97;

// |configs| must contain three hour/minute pairs: the start time, the end time
// and the charge start time.
void MakePeakShiftDayConfig(
    PowerManagementPolicy::WeekDay week_day,
    const TestDayConfig& configs,
    PowerManagementPolicy::PeakShiftDayConfig* config_proto) {
  DCHECK(config_proto);
  ASSERT_EQ(configs.size(), 3);

  config_proto->set_day(week_day);
  config_proto->mutable_start_time()->set_hour(configs[0].first);
  config_proto->mutable_start_time()->set_minute(configs[0].second);
  config_proto->mutable_end_time()->set_hour(configs[1].first);
  config_proto->mutable_end_time()->set_minute(configs[1].second);
  config_proto->mutable_charge_start_time()->set_hour(configs[2].first);
  config_proto->mutable_charge_start_time()->set_minute(configs[2].second);
}

// |configs| must contain two hour/minute pairs: the charge start time and the
// charge end time.
void MakeAdvancedBatteryChargeModeDayConfig(
    PowerManagementPolicy::WeekDay week_day,
    const TestDayConfig& configs,
    PowerManagementPolicy::AdvancedBatteryChargeModeDayConfig* config_proto) {
  DCHECK(config_proto);
  ASSERT_EQ(configs.size(), 2);

  config_proto->set_day(week_day);
  config_proto->mutable_charge_start_time()->set_hour(configs[0].first);
  config_proto->mutable_charge_start_time()->set_minute(configs[0].second);
  config_proto->mutable_charge_end_time()->set_hour(configs[1].first);
  config_proto->mutable_charge_end_time()->set_minute(configs[1].second);
}

}  // namespace

class ChargeControllerTest : public TestEnvironment {
 public:
  ChargeControllerTest() {
    controller_.Init(&helper_, &battery_percentage_converter_);
  }

  const BatteryPercentageConverter& battery_percentage_converter() const {
    return battery_percentage_converter_;
  }

  const system::ChargeControllerHelperStub& helper() const { return helper_; }

 protected:
  // Sets PeakShift policy in PowerManagementPolicy proto.
  void SetPeakShift(int threshold,
                    const std::map<PowerManagementPolicy::WeekDay,
                                   TestDayConfig>& day_configs) {
    policy_.set_peak_shift_battery_percent_threshold(threshold);
    policy_.mutable_peak_shift_day_configs()->Clear();
    for (const auto& item : day_configs) {
      MakePeakShiftDayConfig(item.first, item.second,
                             policy_.add_peak_shift_day_configs());
    }
  }

  // Checks that PeakShift policy was applied as expected.
  bool CheckPeakShift(bool enable,
                      int threshold,
                      const std::map<PowerManagementPolicy::WeekDay,
                                     std::string>& day_configs) {
    for (const auto& item : day_configs) {
      EXPECT_EQ(helper_.peak_shift_day_config(item.first), item.second);
      if (helper_.peak_shift_day_config(item.first) != item.second) {
        return false;
      }
    }
    EXPECT_EQ(helper_.peak_shift_enabled(), enable);
    EXPECT_EQ(helper_.peak_shift_threshold(), threshold);
    return helper_.peak_shift_enabled() == enable &&
           helper_.peak_shift_threshold() == threshold;
  }

  // Sets AdvancedBatteryChargeMode policy in PowerManagementPolicy proto.
  void SetAdvancedBatteryChargeMode(
      const std::map<PowerManagementPolicy::WeekDay, TestDayConfig>&
          day_configs) {
    policy_.mutable_advanced_battery_charge_mode_day_configs()->Clear();
    for (const auto& item : day_configs) {
      MakeAdvancedBatteryChargeModeDayConfig(
          item.first, item.second,
          policy_.add_advanced_battery_charge_mode_day_configs());
    }
  }

  // Checks that AdvancedBatteryChargeMode policy was applied as expected.
  bool CheckAdvancedBatteryChargeMode(
      bool enable,
      const std::map<PowerManagementPolicy::WeekDay, std::string>&
          day_configs) {
    for (const auto& item : day_configs) {
      EXPECT_EQ(helper_.advanced_battery_charge_mode_day_config(item.first),
                item.second);
      if (helper_.advanced_battery_charge_mode_day_config(item.first) !=
          item.second) {
        return false;
      }
    }
    EXPECT_EQ(helper_.advanced_battery_charge_mode_enabled(), enable);
    return helper_.advanced_battery_charge_mode_enabled() == enable;
  }

  // Sets BatteryChargeMode policy in PowerManagementPolicy proto.
  void SetBatteryChargeMode(PowerManagementPolicy::BatteryChargeMode::Mode mode,
                            int custom_charge_start,
                            int custom_charge_stop) {
    policy_.mutable_battery_charge_mode()->set_mode(mode);
    policy_.mutable_battery_charge_mode()->set_custom_charge_start(
        custom_charge_start);
    policy_.mutable_battery_charge_mode()->set_custom_charge_stop(
        custom_charge_stop);
  }

  // Checks that BatteryChargeMode policy was applied as expected.
  bool CheckBatteryChargeMode(
      PowerManagementPolicy::BatteryChargeMode::Mode mode,
      int custom_charge_start =
          system::ChargeControllerHelperStub::kCustomChargeThresholdUnset,
      int custom_charge_stop =
          system::ChargeControllerHelperStub::kCustomChargeThresholdUnset) {
    EXPECT_EQ(helper_.battery_charge_mode(), mode);
    EXPECT_EQ(helper_.custom_charge_start(), custom_charge_start);
    EXPECT_EQ(helper_.custom_charge_stop(), custom_charge_stop);
    return helper_.battery_charge_mode() == mode &&
           helper_.custom_charge_start() == custom_charge_start &&
           helper_.custom_charge_stop() == custom_charge_stop;
  }

  system::ChargeControllerHelperStub helper_;

  ChargeController controller_;
  PowerManagementPolicy policy_;

 private:
  BatteryPercentageConverter battery_percentage_converter_{
      kLowBatteryShutdownPercent, kFullFactor};
};

TEST_F(ChargeControllerTest, PeakShiftNoPolicies) {
  controller_.HandlePolicyChange(policy_);
  EXPECT_FALSE(helper_.peak_shift_enabled());
}

TEST_F(ChargeControllerTest, PeakShiftThresholdOnly) {
  constexpr int kThreshold = 50;
  policy_.set_peak_shift_battery_percent_threshold(kThreshold);
  controller_.HandlePolicyChange(policy_);
  EXPECT_FALSE(helper_.peak_shift_enabled());
}

TEST_F(ChargeControllerTest, PeakShiftDayConfigsOnly) {
  constexpr PowerManagementPolicy::WeekDay kDay = PowerManagementPolicy::MONDAY;
  const TestDayConfig kDayConfig{{0, 30}, {9, 45}, {20, 0}};

  MakePeakShiftDayConfig(kDay, kDayConfig,
                         policy_.add_peak_shift_day_configs());
  controller_.HandlePolicyChange(policy_);
  EXPECT_FALSE(helper_.peak_shift_enabled());
}

TEST_F(ChargeControllerTest, PeakShift) {
  constexpr int kThreshold1 = 50;
  constexpr int kThreshold2 = 45;
  constexpr int kThreshold3 = 10;

  const int actual_threshold1 = std::round(
      battery_percentage_converter().ConvertDisplayToActual(kThreshold1));
  const int actual_threshold2 = std::round(
      battery_percentage_converter().ConvertDisplayToActual(kThreshold2));
  // |kThreshold3| after converting to actual battery percentage will be less
  // than min allowed value.
  const int actual_threshold3 = ChargeController::kPeakShiftBatteryThresholdMin;

  constexpr PowerManagementPolicy::WeekDay kDay1 =
      PowerManagementPolicy::MONDAY;
  constexpr PowerManagementPolicy::WeekDay kDay2 =
      PowerManagementPolicy::FRIDAY;

  const TestDayConfig kDayConfig1{{0, 30}, {9, 45}, {20, 0}};
  constexpr char kExpectedDayConfig1[] = "00:30 09:45 20:00";

  const TestDayConfig kDayConfig2{{9, 15}, {10, 0}, {23, 15}};
  constexpr char kExpectedDayConfig2[] = "09:15 10:00 23:15";

  SetPeakShift(kThreshold1, {{kDay1, kDayConfig1}, {kDay2, kDayConfig2}});
  controller_.HandlePolicyChange(policy_);
  EXPECT_TRUE(CheckPeakShift(
      true, actual_threshold1,
      {{kDay1, kExpectedDayConfig1}, {kDay2, kExpectedDayConfig2}}));

  SetPeakShift(kThreshold2, {{kDay1, kDayConfig2}, {kDay2, kDayConfig1}});
  controller_.HandlePolicyChange(policy_);
  EXPECT_TRUE(CheckPeakShift(
      true, actual_threshold2,
      {{kDay1, kExpectedDayConfig2}, {kDay2, kExpectedDayConfig1}}));

  SetPeakShift(kThreshold3, {{kDay1, kDayConfig2}, {kDay2, kDayConfig1}});
  controller_.HandlePolicyChange(policy_);
  EXPECT_TRUE(CheckPeakShift(
      true, actual_threshold3,
      {{kDay1, kExpectedDayConfig2}, {kDay2, kExpectedDayConfig1}}));

  helper_.Reset();

  controller_.HandlePolicyChange(policy_);
  EXPECT_TRUE(CheckPeakShift(
      false, system::ChargeControllerHelperStub::kPeakShiftThresholdUnset,
      {{kDay1, ""}, {kDay2, ""}}));
}

TEST_F(ChargeControllerTest, BootOnAc) {
  policy_.set_boot_on_ac(false);
  controller_.HandlePolicyChange(policy_);
  EXPECT_FALSE(helper_.boot_on_ac_enabled());

  policy_.set_boot_on_ac(true);
  controller_.HandlePolicyChange(policy_);
  EXPECT_TRUE(helper_.boot_on_ac_enabled());

  helper_.Reset();

  controller_.HandlePolicyChange(policy_);
  EXPECT_FALSE(helper_.boot_on_ac_enabled());
}

TEST_F(ChargeControllerTest, UsbPowerShare) {
  policy_.set_usb_power_share(false);
  controller_.HandlePolicyChange(policy_);
  EXPECT_FALSE(helper_.usb_power_share_enabled());

  policy_.set_usb_power_share(true);
  controller_.HandlePolicyChange(policy_);
  EXPECT_TRUE(helper_.usb_power_share_enabled());

  helper_.Reset();

  controller_.HandlePolicyChange(policy_);
  EXPECT_FALSE(helper_.usb_power_share_enabled());
}

TEST_F(ChargeControllerTest, AdvancedBatteryChargeModeEnabledNoPolicies) {
  controller_.HandlePolicyChange(policy_);
  EXPECT_FALSE(helper_.advanced_battery_charge_mode_enabled());
}

TEST_F(ChargeControllerTest, AdvancedBatteryChargeMode) {
  constexpr PowerManagementPolicy::WeekDay kDay1 =
      PowerManagementPolicy::TUESDAY;
  constexpr PowerManagementPolicy::WeekDay kDay2 =
      PowerManagementPolicy::SUNDAY;

  const TestDayConfig kDayConfigStartEnd1{{2, 45}, {8, 30}};
  constexpr char kExpectedDayConfigStartDuration1[] = "02:45 05:45";

  const TestDayConfig kDayConfigStartEnd2{{3, 30}, {16, 0}};
  constexpr char kExpectedDayConfigStartDuration2[] = "03:30 12:30";

  SetAdvancedBatteryChargeMode(
      {{kDay1, kDayConfigStartEnd1}, {kDay2, kDayConfigStartEnd2}});
  controller_.HandlePolicyChange(policy_);
  EXPECT_TRUE(CheckAdvancedBatteryChargeMode(
      true, {{kDay1, kExpectedDayConfigStartDuration1},
             {kDay2, kExpectedDayConfigStartDuration2}}));

  SetAdvancedBatteryChargeMode(
      {{kDay1, kDayConfigStartEnd2}, {kDay2, kDayConfigStartEnd1}});
  controller_.HandlePolicyChange(policy_);
  EXPECT_TRUE(CheckAdvancedBatteryChargeMode(
      true, {{kDay1, kExpectedDayConfigStartDuration2},
             {kDay2, kExpectedDayConfigStartDuration1}}));

  helper_.Reset();

  controller_.HandlePolicyChange(policy_);
  EXPECT_TRUE(
      CheckAdvancedBatteryChargeMode(false, {{kDay1, ""}, {kDay2, ""}}));
}

TEST_F(ChargeControllerTest, BatteryChargeModeNoPolicies) {
  EXPECT_TRUE(CheckBatteryChargeMode(
      system::ChargeControllerHelperStub::kBatteryChargeModeUnset));

  controller_.HandlePolicyChange(policy_);

  EXPECT_TRUE(CheckBatteryChargeMode(
      PowerManagementPolicy::BatteryChargeMode::STANDARD));
}

TEST_F(ChargeControllerTest, BatteryChargeMode) {
  constexpr PowerManagementPolicy::BatteryChargeMode::Mode kMode1 =
      PowerManagementPolicy::BatteryChargeMode::PRIMARILY_AC_USE;
  constexpr PowerManagementPolicy::BatteryChargeMode::Mode kMode2 =
      PowerManagementPolicy::BatteryChargeMode::CUSTOM;
  constexpr int kCustomStartCharge = 60;
  constexpr int kCustomEndCharge = 90;

  const int actual_custom_start_charge =
      std::round(battery_percentage_converter().ConvertDisplayToActual(
          kCustomStartCharge));
  const int actual_custom_end_charge = std::round(
      battery_percentage_converter().ConvertDisplayToActual(kCustomEndCharge));

  policy_.mutable_battery_charge_mode()->set_mode(kMode1);
  controller_.HandlePolicyChange(policy_);
  EXPECT_TRUE(CheckBatteryChargeMode(kMode1));

  SetBatteryChargeMode(kMode2, kCustomStartCharge, kCustomEndCharge);
  controller_.HandlePolicyChange(policy_);
  EXPECT_TRUE(CheckBatteryChargeMode(kMode2, actual_custom_start_charge,
                                     actual_custom_end_charge));

  helper_.Reset();

  controller_.HandlePolicyChange(policy_);
  EXPECT_TRUE(CheckBatteryChargeMode(
      system::ChargeControllerHelperStub::kBatteryChargeModeUnset));
}

TEST_F(ChargeControllerTest, BatteryChargeModeInvalidThresholds) {
  constexpr PowerManagementPolicy::BatteryChargeMode::Mode kMode1 =
      PowerManagementPolicy::BatteryChargeMode::PRIMARILY_AC_USE;
  constexpr PowerManagementPolicy::BatteryChargeMode::Mode kMode2 =
      PowerManagementPolicy::BatteryChargeMode::CUSTOM;
  constexpr int kCustomStartCharge = 79;
  constexpr int kCustomEndCharge = 80;

  const int actual_custom_end_charge = std::round(
      battery_percentage_converter().ConvertDisplayToActual(kCustomEndCharge));
  int actual_custom_start_charge =
      std::round(battery_percentage_converter().ConvertDisplayToActual(
          kCustomStartCharge));

  // Verify that ChargeController clamps |start| and |end| thresholds within min
  // and max range and keeps min difference between them.
  EXPECT_LT(actual_custom_end_charge - actual_custom_start_charge,
            ChargeController::kCustomChargeModeThresholdsMinDiff);
  actual_custom_start_charge =
      actual_custom_end_charge -
      ChargeController::kCustomChargeModeThresholdsMinDiff;

  policy_.mutable_battery_charge_mode()->set_mode(kMode1);
  controller_.HandlePolicyChange(policy_);
  EXPECT_TRUE(CheckBatteryChargeMode(kMode1));

  SetBatteryChargeMode(kMode2, kCustomStartCharge, kCustomEndCharge);
  controller_.HandlePolicyChange(policy_);
  EXPECT_TRUE(CheckBatteryChargeMode(kMode2, actual_custom_start_charge,
                                     actual_custom_end_charge));

  helper_.Reset();

  controller_.HandlePolicyChange(policy_);
  EXPECT_TRUE(CheckBatteryChargeMode(
      system::ChargeControllerHelperStub::kBatteryChargeModeUnset));
}

// If AdvancedBatteryChargeMode is specified, it overrides BatteryChargeMode.
TEST_F(ChargeControllerTest,
       AdvancedBatteryChargeModeOverridesBatteryChargeMode) {
  constexpr PowerManagementPolicy::BatteryChargeMode::Mode kMode =
      PowerManagementPolicy::BatteryChargeMode::EXPRESS_CHARGE;

  constexpr PowerManagementPolicy::WeekDay kDay1 =
      PowerManagementPolicy::FRIDAY;
  constexpr PowerManagementPolicy::WeekDay kDay2 =
      PowerManagementPolicy::SUNDAY;

  const TestDayConfig kDayConfigStartEnd1{{8, 15}, {10, 45}};
  constexpr char kExpectedDayConfigStartDuration1[] = "08:15 02:30";

  const TestDayConfig kDayConfigStartEnd2{{4, 0}, {6, 15}};
  constexpr char kExpectedDayConfigStartDuration2[] = "04:00 02:15";

  policy_.mutable_battery_charge_mode()->set_mode(kMode);
  SetAdvancedBatteryChargeMode(
      {{kDay1, kDayConfigStartEnd1}, {kDay2, kDayConfigStartEnd2}});

  controller_.HandlePolicyChange(policy_);

  EXPECT_EQ(helper_.battery_charge_mode(),
            system::ChargeControllerHelperStub::kBatteryChargeModeUnset);
  EXPECT_TRUE(CheckAdvancedBatteryChargeMode(
      true, {{kDay1, kExpectedDayConfigStartDuration1},
             {kDay2, kExpectedDayConfigStartDuration2}}));
}

struct CustomChargeThresholdsTestData {
  // (start, end) input thresholds.
  std::pair<int, int> input;
  // (start, end) expected thresholds.
  std::pair<int, int> expected;
};

class CustomChargeThresholdsChargeControllerTest
    : public TestEnvironment,
      public testing::WithParamInterface<CustomChargeThresholdsTestData> {
 public:
  int input_start_threshold() const { return GetParam().input.first; }
  int input_end_threshold() const { return GetParam().input.second; }

  int expected_start_threshold() const { return GetParam().expected.first; }
  int expected_end_threshold() const { return GetParam().expected.second; }
};

TEST_P(CustomChargeThresholdsChargeControllerTest, All) {
  int start = input_start_threshold();
  int end = input_end_threshold();
  ChargeController::ClampCustomBatteryChargeThresholds(&start, &end);
  EXPECT_EQ(start, expected_start_threshold());
  EXPECT_EQ(end, expected_end_threshold());
  EXPECT_GE(end - start, ChargeController::kCustomChargeModeThresholdsMinDiff);
}

INSTANTIATE_TEST_SUITE_P(
    _,
    CustomChargeThresholdsChargeControllerTest,
    testing::Values(
        // Valid thresholds.
        CustomChargeThresholdsTestData{
            {ChargeController::kCustomChargeModeStartMin,
             ChargeController::kCustomChargeModeEndMin},
            {ChargeController::kCustomChargeModeStartMin,
             ChargeController::kCustomChargeModeEndMin}},
        CustomChargeThresholdsTestData{
            {ChargeController::kCustomChargeModeStartMax,
             ChargeController::kCustomChargeModeEndMax},
            {ChargeController::kCustomChargeModeStartMax,
             ChargeController::kCustomChargeModeEndMax}},
        CustomChargeThresholdsTestData{
            {ChargeController::kCustomChargeModeStartMin,
             ChargeController::kCustomChargeModeEndMax},
            {ChargeController::kCustomChargeModeStartMin,
             ChargeController::kCustomChargeModeEndMax}},
        CustomChargeThresholdsTestData{
            {ChargeController::kCustomChargeModeStartMin + 1,
             ChargeController::kCustomChargeModeEndMax - 1},
            {ChargeController::kCustomChargeModeStartMin + 1,
             ChargeController::kCustomChargeModeEndMax - 1}},

        // |start| threshold less than min value.
        CustomChargeThresholdsTestData{
            {ChargeController::kCustomChargeModeStartMin - 1,
             ChargeController::kCustomChargeModeEndMax},
            {ChargeController::kCustomChargeModeStartMin,
             ChargeController::kCustomChargeModeEndMax}},

        // |start| threshold greater than max value.
        CustomChargeThresholdsTestData{
            {ChargeController::kCustomChargeModeStartMax + 1,
             ChargeController::kCustomChargeModeEndMax},
            {ChargeController::kCustomChargeModeStartMax,
             ChargeController::kCustomChargeModeEndMax}},

        // |end| threshold less than min value.
        CustomChargeThresholdsTestData{
            {ChargeController::kCustomChargeModeStartMin,
             ChargeController::kCustomChargeModeEndMin - 1},
            {ChargeController::kCustomChargeModeStartMin,
             ChargeController::kCustomChargeModeEndMin}},

        // |end| threshold greater than max value.
        CustomChargeThresholdsTestData{
            {ChargeController::kCustomChargeModeStartMin,
             ChargeController::kCustomChargeModeEndMax + 1},
            {ChargeController::kCustomChargeModeStartMin,
             ChargeController::kCustomChargeModeEndMax}},

        // Diff between |start| and |end| threshold less than allowed min diff.
        // Thresholds close to their min values.
        CustomChargeThresholdsTestData{
            {ChargeController::kCustomChargeModeStartMin + 1,
             ChargeController::kCustomChargeModeEndMin},
            {ChargeController::kCustomChargeModeStartMin,
             ChargeController::kCustomChargeModeEndMin}},

        // Diff between |start| and |end| threshold less than allowed min diff.
        // Also |end| threshold less than min value.
        CustomChargeThresholdsTestData{
            {ChargeController::kCustomChargeModeStartMin,
             ChargeController::kCustomChargeModeEndMin - 1},
            {ChargeController::kCustomChargeModeStartMin,
             ChargeController::kCustomChargeModeEndMin}},

        // Diff between |start| and |end| threshold less than allowed min diff.
        // Thresholds between their min and max values.
        CustomChargeThresholdsTestData{
            {ChargeController::kCustomChargeModeStartMin + 19,
             ChargeController::kCustomChargeModeStartMin + 20},
            {ChargeController::kCustomChargeModeStartMin + 15,
             ChargeController::kCustomChargeModeStartMin + 20}},

        // Diff between |start| and |end| threshold less than allowed min diff.
        // Thresholds close to their max values.
        CustomChargeThresholdsTestData{
            {ChargeController::kCustomChargeModeStartMax,
             ChargeController::kCustomChargeModeEndMax - 1},
            {ChargeController::kCustomChargeModeStartMax - 1,
             ChargeController::kCustomChargeModeEndMax - 1}},

        // Diff between |start| and |end| threshold less than allowed min diff.
        // Also |start| threshold greater than max value.
        CustomChargeThresholdsTestData{
            {ChargeController::kCustomChargeModeStartMax + 1,
             ChargeController::kCustomChargeModeEndMax},
            {ChargeController::kCustomChargeModeStartMax,
             ChargeController::kCustomChargeModeEndMax}}));

class PeakShiftThresholdChargeControllerTest
    : public TestEnvironment,
      public testing::WithParamInterface<std::tuple<int, int>> {
 public:
  int input_threshold() const { return std::get<0>(GetParam()); }

  int expected_threshold() const { return std::get<1>(GetParam()); }
};

// Verifies that display percentage threshold for peak shift will be converted
// into valid actual percentage threshold.
TEST_P(PeakShiftThresholdChargeControllerTest, ValidActualThreshold) {
  const int actual_threshold =
      ChargeController::ClampPeakShiftBatteryThreshold(input_threshold());
  EXPECT_EQ(actual_threshold, expected_threshold());
}

INSTANTIATE_TEST_SUITE_P(
    _,
    PeakShiftThresholdChargeControllerTest,
    testing::Values(
        // Valid values.
        std::make_tuple(ChargeController::kPeakShiftBatteryThresholdMin,
                        ChargeController::kPeakShiftBatteryThresholdMin),
        std::make_tuple(ChargeController::kPeakShiftBatteryThresholdMax,
                        ChargeController::kPeakShiftBatteryThresholdMax),
        std::make_tuple(ChargeController::kPeakShiftBatteryThresholdMin + 20,
                        ChargeController::kPeakShiftBatteryThresholdMin + 20),

        // Threshold less than min value.
        std::make_tuple(ChargeController::kPeakShiftBatteryThresholdMin - 1,
                        ChargeController::kPeakShiftBatteryThresholdMin),

        // Threshold greater than max value.
        std::make_tuple(ChargeController::kPeakShiftBatteryThresholdMax + 1,
                        ChargeController::kPeakShiftBatteryThresholdMax)));

}  // namespace power_manager::policy
