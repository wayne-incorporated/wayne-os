// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <optional>
#include <string>
#include <utility>

#include <base/check.h>
#include <base/json/json_writer.h>
#include <base/values.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "diagnostics/cros_healthd/routines/battery_health/battery_health.h"
#include "diagnostics/cros_healthd/routines/routine_test_utils.h"
#include "diagnostics/cros_healthd/system/mock_context.h"
#include "diagnostics/mojom/public/cros_healthd_diagnostics.mojom.h"

namespace diagnostics {
namespace {

namespace mojom = ::ash::cros_healthd::mojom;

constexpr int kMaximumCycleCount = 5;
constexpr int kPercentBatteryWearAllowed = 10;
constexpr int kHighCycleCount = 6;
constexpr int kLowCycleCount = 4;
constexpr double kHighChargeFull = 91.0;
constexpr int kLowChargeFull = 89;
constexpr double kFakeBatteryChargeFullDesign = 100.0;
constexpr char kFakeManufacturer[] = "Fake Manufacturer";
constexpr double kFakeCurrentNow = 0.512;
constexpr int kFakePresent = 1;
constexpr char kFakeStatus[] = "Full";
constexpr double kFakeVoltageNow = 8.388;
constexpr double kFakeChargeNow = 6.154;

std::string ConstructOutput() {
  std::string output;
  base::Value::Dict result_dict;
  result_dict.Set("wearPercentage",
                  static_cast<int>(100 - (kHighChargeFull * 100 /
                                          kFakeBatteryChargeFullDesign)));
  result_dict.Set("cycleCount", kLowCycleCount);
  result_dict.Set("manufacturer", kFakeManufacturer);
  result_dict.Set("currentNowA", kFakeCurrentNow);
  result_dict.Set("present", kFakePresent);
  result_dict.Set("status", kFakeStatus);
  result_dict.Set("voltageNowV", kFakeVoltageNow);
  result_dict.Set("chargeFullAh", kHighChargeFull);
  result_dict.Set("chargeFullDesignAh", kFakeBatteryChargeFullDesign);
  result_dict.Set("chargeNowAh", kFakeChargeNow);
  base::Value::Dict output_dict;
  output_dict.Set("resultDetails", std::move(result_dict));
  base::JSONWriter::Write(output_dict, &output);
  return output;
}

power_manager::PowerSupplyProperties GetDefaultPowerSupplyProperties() {
  power_manager::PowerSupplyProperties power_supply_proto;
  power_supply_proto.set_battery_vendor(kFakeManufacturer);
  power_supply_proto.set_battery_current(kFakeCurrentNow);
  power_supply_proto.set_battery_state(
      power_manager::PowerSupplyProperties_BatteryState_CHARGING);
  power_supply_proto.set_battery_status(kFakeStatus);
  power_supply_proto.set_battery_voltage(kFakeVoltageNow);
  power_supply_proto.set_battery_charge(kFakeChargeNow);
  return power_supply_proto;
}

class BatteryHealthRoutineTest : public testing::Test {
 protected:
  BatteryHealthRoutineTest() = default;
  BatteryHealthRoutineTest(const BatteryHealthRoutineTest&) = delete;
  BatteryHealthRoutineTest& operator=(const BatteryHealthRoutineTest&) = delete;

  mojom::RoutineUpdate* update() { return &update_; }

  void CreateRoutine(
      uint32_t maximum_cycle_count = kMaximumCycleCount,
      uint32_t percent_battery_wear_allowed = kPercentBatteryWearAllowed) {
    routine_ = CreateBatteryHealthRoutine(&mock_context_, maximum_cycle_count,
                                          percent_battery_wear_allowed);
  }

  void RunRoutineAndWaitForExit() {
    DCHECK(routine_);
    routine_->Start();

    // Since the BatteryHealthRoutine has finished by the time Start() returns,
    // there is no need to wait.
    routine_->PopulateStatusUpdate(&update_, true);
  }

  FakePowerdAdapter* fake_powerd_adapter() {
    return mock_context_.fake_powerd_adapter();
  }

 private:
  MockContext mock_context_;
  std::unique_ptr<DiagnosticRoutine> routine_;
  mojom::RoutineUpdate update_{0, mojo::ScopedHandle(),
                               mojom::RoutineUpdateUnionPtr()};
};

// Test that the battery health routine fails if the cycle count is too high.
TEST_F(BatteryHealthRoutineTest, HighCycleCount) {
  auto power_supply_proto = GetDefaultPowerSupplyProperties();
  power_supply_proto.set_battery_charge_full(kHighChargeFull);
  power_supply_proto.set_battery_charge_full_design(
      kFakeBatteryChargeFullDesign);
  power_supply_proto.set_battery_cycle_count(kHighCycleCount);
  fake_powerd_adapter()->SetPowerSupplyProperties(power_supply_proto);

  CreateRoutine();
  RunRoutineAndWaitForExit();
  VerifyNonInteractiveUpdate(update()->routine_update_union,
                             mojom::DiagnosticRoutineStatusEnum::kFailed,
                             kBatteryHealthExcessiveCycleCountMessage);
}

// Test that the battery health routine fails if cycle_count is not present.
TEST_F(BatteryHealthRoutineTest, NoCycleCount) {
  auto power_supply_proto = GetDefaultPowerSupplyProperties();
  power_supply_proto.set_battery_charge_full(kHighChargeFull);
  power_supply_proto.set_battery_charge_full_design(
      kFakeBatteryChargeFullDesign);
  fake_powerd_adapter()->SetPowerSupplyProperties(power_supply_proto);

  CreateRoutine();
  RunRoutineAndWaitForExit();
  VerifyNonInteractiveUpdate(update()->routine_update_union,
                             mojom::DiagnosticRoutineStatusEnum::kError,
                             kBatteryHealthFailedReadingCycleCountMessage);
}

// Test that the battery health routine fails if the wear percentage is too
// high.
TEST_F(BatteryHealthRoutineTest, HighWearPercentage) {
  auto power_supply_proto = GetDefaultPowerSupplyProperties();
  power_supply_proto.set_battery_charge_full(kLowChargeFull);
  power_supply_proto.set_battery_charge_full_design(
      kFakeBatteryChargeFullDesign);
  power_supply_proto.set_battery_cycle_count(kLowCycleCount);
  fake_powerd_adapter()->SetPowerSupplyProperties(power_supply_proto);

  CreateRoutine();
  RunRoutineAndWaitForExit();
  VerifyNonInteractiveUpdate(update()->routine_update_union,
                             mojom::DiagnosticRoutineStatusEnum::kFailed,
                             kBatteryHealthExcessiveWearMessage);
}

// Test that the battery health routine fails if neither charge_full nor
// energy_full are present.
TEST_F(BatteryHealthRoutineTest, NoWearPercentage) {
  auto power_supply_proto = GetDefaultPowerSupplyProperties();
  power_supply_proto.set_battery_cycle_count(kLowCycleCount);
  fake_powerd_adapter()->SetPowerSupplyProperties(power_supply_proto);

  CreateRoutine();
  RunRoutineAndWaitForExit();
  VerifyNonInteractiveUpdate(
      update()->routine_update_union,
      mojom::DiagnosticRoutineStatusEnum::kError,
      kBatteryHealthFailedCalculatingWearPercentageMessage);
}

// Test that the battery health routine passes if the cycle count and wear
// percentage are within acceptable limits.
TEST_F(BatteryHealthRoutineTest, GoodParameters) {
  auto power_supply_proto = GetDefaultPowerSupplyProperties();
  power_supply_proto.set_battery_charge_full(kHighChargeFull);
  power_supply_proto.set_battery_charge_full_design(
      kFakeBatteryChargeFullDesign);
  power_supply_proto.set_battery_cycle_count(kLowCycleCount);
  fake_powerd_adapter()->SetPowerSupplyProperties(power_supply_proto);

  CreateRoutine();
  RunRoutineAndWaitForExit();
  VerifyNonInteractiveUpdate(update()->routine_update_union,
                             mojom::DiagnosticRoutineStatusEnum::kPassed,
                             kBatteryHealthRoutinePassedMessage);

  EXPECT_EQ(GetStringFromValidReadOnlySharedMemoryMapping(
                std::move(update()->output)),
            ConstructOutput());
}

// Test that the battery health routine catches invalid parameters.
TEST_F(BatteryHealthRoutineTest, InvalidParameters) {
  auto power_supply_proto = GetDefaultPowerSupplyProperties();
  fake_powerd_adapter()->SetPowerSupplyProperties(power_supply_proto);

  constexpr int kInvalidMaximumWearPercentage = 101;
  CreateRoutine(kMaximumCycleCount, kInvalidMaximumWearPercentage);
  RunRoutineAndWaitForExit();
  VerifyNonInteractiveUpdate(update()->routine_update_union,
                             mojom::DiagnosticRoutineStatusEnum::kError,
                             kBatteryHealthInvalidParametersMessage);
}

// Test that the battery health routine handles a battery whose capacity exceeds
// its design capacity.
TEST_F(BatteryHealthRoutineTest, CapacityExceedsDesignCapacity) {
  // Set the capacity to anything higher than the design capacity.
  constexpr int kHigherCapacity = 100;
  constexpr int kLowerDesignCapacity = 20;

  auto power_supply_proto = GetDefaultPowerSupplyProperties();
  power_supply_proto.set_battery_charge_full(kHigherCapacity);
  power_supply_proto.set_battery_charge_full_design(kLowerDesignCapacity);
  power_supply_proto.set_battery_cycle_count(kLowCycleCount);
  fake_powerd_adapter()->SetPowerSupplyProperties(power_supply_proto);

  // When the capacity exceeds the design capacity, the battery shouldn't be
  // worn at all.
  constexpr int kNotWornPercentage = 0;
  CreateRoutine(kMaximumCycleCount, kNotWornPercentage);
  RunRoutineAndWaitForExit();
  VerifyNonInteractiveUpdate(update()->routine_update_union,
                             mojom::DiagnosticRoutineStatusEnum::kPassed,
                             kBatteryHealthRoutinePassedMessage);
}

// Test that the battery health routine fails when powerd returns an error.
TEST_F(BatteryHealthRoutineTest, PowerdError) {
  fake_powerd_adapter()->SetPowerSupplyProperties(std::nullopt);

  CreateRoutine();
  RunRoutineAndWaitForExit();
  VerifyNonInteractiveUpdate(update()->routine_update_union,
                             mojom::DiagnosticRoutineStatusEnum::kError,
                             kPowerdPowerSupplyPropertiesFailedMessage);
}

}  // namespace
}  // namespace diagnostics
