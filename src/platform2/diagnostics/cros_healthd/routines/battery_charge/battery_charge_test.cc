// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <utility>

#include <base/check.h>
#include <base/test/task_environment.h>
#include <base/time/time.h>
#include <gtest/gtest.h>

#include "diagnostics/cros_healthd/routines/battery_charge/battery_charge.h"
#include "diagnostics/cros_healthd/routines/battery_charge/battery_charge_constants.h"
#include "diagnostics/cros_healthd/routines/routine_test_utils.h"
#include "diagnostics/cros_healthd/system/fake_powerd_adapter.h"
#include "diagnostics/cros_healthd/system/mock_context.h"
#include "diagnostics/mojom/public/cros_healthd_diagnostics.mojom.h"

namespace diagnostics {
namespace {

namespace mojom = ::ash::cros_healthd::mojom;

constexpr double kStartingChargePercentage = 55;
constexpr double kEndingChargePercentage = 80;

// With this value for minimum_charge_percent_required, the routine should pass.
constexpr uint32_t kPassingPercent = 19;
// With this value for minimum_charge_percent_required, the routine should fail.
constexpr uint32_t kFailingPercent = 40;
// With this value for minimum_charge_percent_required, the routine should error
// out.
constexpr uint32_t kErrorPercent = 50;

constexpr base::TimeDelta kFullDuration = base::Seconds(12);
constexpr base::TimeDelta kHalfDuration = kFullDuration / 2;
constexpr base::TimeDelta kQuarterDuration = kFullDuration / 4;

power_manager::PowerSupplyProperties GetPowerSupplyProperties() {
  power_manager::PowerSupplyProperties power_supply_proto;
  power_supply_proto.set_battery_percent(kStartingChargePercentage);
  power_supply_proto.set_battery_state(
      power_manager::PowerSupplyProperties_BatteryState_CHARGING);
  return power_supply_proto;
}

class BatteryChargeRoutineTest : public testing::Test {
 protected:
  BatteryChargeRoutineTest() = default;
  BatteryChargeRoutineTest(const BatteryChargeRoutineTest&) = delete;
  BatteryChargeRoutineTest& operator=(const BatteryChargeRoutineTest&) = delete;

  DiagnosticRoutine* routine() { return routine_.get(); }

  void CreateRoutine(uint32_t minimum_charge_percent_required) {
    routine_ = std::make_unique<BatteryChargeRoutine>(
        &mock_context_, kFullDuration, minimum_charge_percent_required,
        task_environment_.GetMockTickClock());
  }

  void StartRoutineAndVerifyInteractiveResponse() {
    DCHECK(routine_);

    routine_->Start();
    auto update = GetUpdate();
    VerifyInteractiveUpdate(
        update->routine_update_union,
        mojom::DiagnosticRoutineUserMessageEnum::kPlugInACPower);
    EXPECT_EQ(update->progress_percent, 0);
  }

  mojom::RoutineUpdatePtr GetUpdate() {
    mojom::RoutineUpdate update{0, mojo::ScopedHandle(),
                                mojom::RoutineUpdateUnionPtr()};
    routine_->PopulateStatusUpdate(&update, true);
    return mojom::RoutineUpdate::New(update.progress_percent,
                                     std::move(update.output),
                                     std::move(update.routine_update_union));
  }

  void FastForwardBy(base::TimeDelta time) {
    task_environment_.FastForwardBy(time);
  }

  MockContext* mock_context() { return &mock_context_; }

  FakePowerdAdapter* fake_powerd_adapter() {
    return mock_context_.fake_powerd_adapter();
  }

 private:
  MockContext mock_context_;
  base::test::TaskEnvironment task_environment_{
      base::test::TaskEnvironment::TimeSource::MOCK_TIME};
  std::unique_ptr<BatteryChargeRoutine> routine_;
};

// Test that the routine can be created with the default tick clock and root
// directory.
TEST_F(BatteryChargeRoutineTest, DefaultConstruction) {
  BatteryChargeRoutine routine{mock_context(), kFullDuration, kPassingPercent};
  EXPECT_EQ(routine.GetStatus(), mojom::DiagnosticRoutineStatusEnum::kReady);
}

// Test that the routine passes when the battery charges more than
// minimum_charge_percent_required.
TEST_F(BatteryChargeRoutineTest, RoutineSuccess) {
  auto power_supply_proto = GetPowerSupplyProperties();
  fake_powerd_adapter()->SetPowerSupplyProperties(power_supply_proto);

  CreateRoutine(kPassingPercent);
  StartRoutineAndVerifyInteractiveResponse();

  routine()->Resume();
  FastForwardBy(kHalfDuration);
  auto update = GetUpdate();
  VerifyNonInteractiveUpdate(update->routine_update_union,
                             mojom::DiagnosticRoutineStatusEnum::kRunning,
                             kBatteryChargeRoutineRunningMessage);
  EXPECT_EQ(update->progress_percent, 50);

  power_supply_proto.set_battery_percent(kEndingChargePercentage);
  fake_powerd_adapter()->SetPowerSupplyProperties(power_supply_proto);

  FastForwardBy(kHalfDuration);
  update = GetUpdate();
  VerifyNonInteractiveUpdate(update->routine_update_union,
                             mojom::DiagnosticRoutineStatusEnum::kPassed,
                             kBatteryChargeRoutineSucceededMessage);
  EXPECT_EQ(update->progress_percent, 100);
}

// Test that the routine fails when the battery charges less than
// minimum_charge_percent_required.
TEST_F(BatteryChargeRoutineTest, InsufficientChargeFailure) {
  auto power_supply_proto = GetPowerSupplyProperties();
  fake_powerd_adapter()->SetPowerSupplyProperties(power_supply_proto);

  CreateRoutine(kFailingPercent);
  StartRoutineAndVerifyInteractiveResponse();

  routine()->Resume();
  FastForwardBy(kHalfDuration);
  auto update = GetUpdate();
  VerifyNonInteractiveUpdate(update->routine_update_union,
                             mojom::DiagnosticRoutineStatusEnum::kRunning,
                             kBatteryChargeRoutineRunningMessage);
  EXPECT_EQ(update->progress_percent, 50);

  power_supply_proto.set_battery_percent(kEndingChargePercentage);
  fake_powerd_adapter()->SetPowerSupplyProperties(power_supply_proto);

  FastForwardBy(kHalfDuration);
  update = GetUpdate();
  VerifyNonInteractiveUpdate(
      update->routine_update_union, mojom::DiagnosticRoutineStatusEnum::kFailed,
      kBatteryChargeRoutineFailedInsufficientChargeMessage);
  EXPECT_EQ(update->progress_percent, 100);
}

// Test that the routine handles an invalid minimum_charge_percent_required
// input.
TEST_F(BatteryChargeRoutineTest, InvalidParameters) {
  auto power_supply_proto = GetPowerSupplyProperties();
  fake_powerd_adapter()->SetPowerSupplyProperties(power_supply_proto);

  CreateRoutine(kErrorPercent);
  StartRoutineAndVerifyInteractiveResponse();

  routine()->Resume();
  auto update = GetUpdate();
  VerifyNonInteractiveUpdate(update->routine_update_union,
                             mojom::DiagnosticRoutineStatusEnum::kError,
                             kBatteryChargeRoutineInvalidParametersMessage);
  EXPECT_EQ(update->progress_percent, 0);
}

// Test that the routine handles the battery not charging.
TEST_F(BatteryChargeRoutineTest, BatteryNotCharging) {
  auto power_supply_proto = GetPowerSupplyProperties();
  power_supply_proto.set_battery_state(
      power_manager::PowerSupplyProperties_BatteryState_DISCHARGING);
  fake_powerd_adapter()->SetPowerSupplyProperties(power_supply_proto);

  CreateRoutine(kPassingPercent);
  StartRoutineAndVerifyInteractiveResponse();

  routine()->Resume();
  auto update = GetUpdate();
  VerifyNonInteractiveUpdate(update->routine_update_union,
                             mojom::DiagnosticRoutineStatusEnum::kError,
                             kBatteryChargeRoutineNotChargingMessage);
  EXPECT_EQ(update->progress_percent, 0);
}

// Test that the routine handles an ending charge lower than the starting
// charge.
TEST_F(BatteryChargeRoutineTest, EndingChargeHigherThanStartingCharge) {
  auto power_supply_proto = GetPowerSupplyProperties();
  power_supply_proto.set_battery_percent(kEndingChargePercentage);
  fake_powerd_adapter()->SetPowerSupplyProperties(power_supply_proto);

  CreateRoutine(kPassingPercent);
  StartRoutineAndVerifyInteractiveResponse();

  routine()->Resume();
  FastForwardBy(kHalfDuration);
  auto update = GetUpdate();
  VerifyNonInteractiveUpdate(update->routine_update_union,
                             mojom::DiagnosticRoutineStatusEnum::kRunning,
                             kBatteryChargeRoutineRunningMessage);
  EXPECT_EQ(update->progress_percent, 50);

  power_supply_proto.set_battery_percent(kStartingChargePercentage);
  fake_powerd_adapter()->SetPowerSupplyProperties(power_supply_proto);

  FastForwardBy(kHalfDuration);
  update = GetUpdate();
  VerifyNonInteractiveUpdate(update->routine_update_union,
                             mojom::DiagnosticRoutineStatusEnum::kError,
                             kBatteryChargeRoutineNotChargingMessage);
  EXPECT_EQ(update->progress_percent, 50);
}

// Test that the routine handles an error from powerd.
TEST_F(BatteryChargeRoutineTest, PowerdError) {
  fake_powerd_adapter()->SetPowerSupplyProperties(std::nullopt);

  CreateRoutine(kPassingPercent);
  StartRoutineAndVerifyInteractiveResponse();

  routine()->Resume();
  FastForwardBy(kHalfDuration);
  auto update = GetUpdate();
  VerifyNonInteractiveUpdate(update->routine_update_union,
                             mojom::DiagnosticRoutineStatusEnum::kError,
                             kPowerdPowerSupplyPropertiesFailedMessage);
  EXPECT_EQ(update->progress_percent, 0);
}

// Test that the routine handles an error from powerd after the delayed task.
TEST_F(BatteryChargeRoutineTest, DelayedTaskPowerdError) {
  auto power_supply_proto = GetPowerSupplyProperties();
  fake_powerd_adapter()->SetPowerSupplyProperties(power_supply_proto);

  CreateRoutine(kPassingPercent);
  StartRoutineAndVerifyInteractiveResponse();

  routine()->Resume();
  FastForwardBy(kHalfDuration);
  auto update = GetUpdate();
  VerifyNonInteractiveUpdate(update->routine_update_union,
                             mojom::DiagnosticRoutineStatusEnum::kRunning,
                             kBatteryChargeRoutineRunningMessage);
  EXPECT_EQ(update->progress_percent, 50);

  fake_powerd_adapter()->SetPowerSupplyProperties(std::nullopt);

  FastForwardBy(kHalfDuration);
  update = GetUpdate();
  VerifyNonInteractiveUpdate(update->routine_update_union,
                             mojom::DiagnosticRoutineStatusEnum::kError,
                             kPowerdPowerSupplyPropertiesFailedMessage);
  EXPECT_EQ(update->progress_percent, 50);
}

// Test that we can cancel the routine in its waiting state.
TEST_F(BatteryChargeRoutineTest, CancelWhileWaiting) {
  auto power_supply_proto = GetPowerSupplyProperties();
  fake_powerd_adapter()->SetPowerSupplyProperties(power_supply_proto);

  CreateRoutine(kPassingPercent);
  routine()->Start();

  EXPECT_EQ(routine()->GetStatus(),
            mojom::DiagnosticRoutineStatusEnum::kWaiting);

  routine()->Cancel();

  auto update = GetUpdate();
  VerifyNonInteractiveUpdate(update->routine_update_union,
                             mojom::DiagnosticRoutineStatusEnum::kCancelled,
                             kBatteryChargeRoutineCancelledMessage);
  EXPECT_EQ(update->progress_percent, 0);

  FastForwardBy(kFullDuration);
  update = GetUpdate();
  VerifyNonInteractiveUpdate(update->routine_update_union,
                             mojom::DiagnosticRoutineStatusEnum::kCancelled,
                             kBatteryChargeRoutineCancelledMessage);
  EXPECT_EQ(update->progress_percent, 0);
}

// Test that we can cancel the routine partway through running.
TEST_F(BatteryChargeRoutineTest, CancelWhileRunning) {
  auto power_supply_proto = GetPowerSupplyProperties();
  fake_powerd_adapter()->SetPowerSupplyProperties(power_supply_proto);

  CreateRoutine(kPassingPercent);
  StartRoutineAndVerifyInteractiveResponse();

  routine()->Resume();
  FastForwardBy(kHalfDuration);
  auto update = GetUpdate();
  VerifyNonInteractiveUpdate(update->routine_update_union,
                             mojom::DiagnosticRoutineStatusEnum::kRunning,
                             kBatteryChargeRoutineRunningMessage);
  EXPECT_EQ(update->progress_percent, 50);

  FastForwardBy(kQuarterDuration);
  routine()->Cancel();

  update = GetUpdate();
  VerifyNonInteractiveUpdate(update->routine_update_union,
                             mojom::DiagnosticRoutineStatusEnum::kCancelled,
                             kBatteryChargeRoutineCancelledMessage);
  EXPECT_EQ(update->progress_percent, 75);

  FastForwardBy(kQuarterDuration);
  update = GetUpdate();
  VerifyNonInteractiveUpdate(update->routine_update_union,
                             mojom::DiagnosticRoutineStatusEnum::kCancelled,
                             kBatteryChargeRoutineCancelledMessage);
  EXPECT_EQ(update->progress_percent, 75);
}

// Test that cancelling a routine in an error state doesn't overwrite the state.
TEST_F(BatteryChargeRoutineTest, CancelWhileInErrorState) {
  fake_powerd_adapter()->SetPowerSupplyProperties(std::nullopt);

  CreateRoutine(kPassingPercent);
  StartRoutineAndVerifyInteractiveResponse();

  routine()->Resume();
  auto update = GetUpdate();
  VerifyNonInteractiveUpdate(update->routine_update_union,
                             mojom::DiagnosticRoutineStatusEnum::kError,
                             kPowerdPowerSupplyPropertiesFailedMessage);
  EXPECT_EQ(update->progress_percent, 0);

  FastForwardBy(kQuarterDuration);
  routine()->Cancel();

  update = GetUpdate();
  VerifyNonInteractiveUpdate(update->routine_update_union,
                             mojom::DiagnosticRoutineStatusEnum::kError,
                             kPowerdPowerSupplyPropertiesFailedMessage);
  EXPECT_EQ(update->progress_percent, 0);
}

}  // namespace
}  // namespace diagnostics
