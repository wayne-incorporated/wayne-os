// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <cstdint>
#include <memory>
#include <optional>
#include <string>

#include <gtest/gtest.h>

#include "diagnostics/cros_healthd/routines/battery_capacity/battery_capacity.h"
#include "diagnostics/cros_healthd/routines/routine_test_utils.h"
#include "diagnostics/cros_healthd/system/fake_powerd_adapter.h"
#include "diagnostics/cros_healthd/system/mock_context.h"
#include "diagnostics/mojom/public/cros_healthd_diagnostics.mojom.h"

namespace diagnostics {
namespace {

namespace mojom = ::ash::cros_healthd::mojom;

constexpr uint32_t kLowmAh = 1000;
constexpr uint32_t kHighmAh = 10000;
constexpr double kGoodBatteryChargeFullDesign = 8.948;
constexpr double kBadBatteryChargeFullDesign = 0.812;

class BatteryCapacityRoutineTest : public testing::Test {
 protected:
  BatteryCapacityRoutineTest() = default;
  BatteryCapacityRoutineTest(const BatteryCapacityRoutineTest&) = delete;
  BatteryCapacityRoutineTest& operator=(const BatteryCapacityRoutineTest&) =
      delete;

  mojom::RoutineUpdate* update() { return &update_; }

  void CreateRoutine(uint32_t low_mah = kLowmAh, uint32_t high_mah = kHighmAh) {
    routine_ = CreateBatteryCapacityRoutine(&mock_context_, low_mah, high_mah);
  }

  void RunRoutineAndWaitForExit() {
    routine_->Start();

    // Since the BatteryCapacityRoutine has finished by the time Start()
    // returns, there is no need to wait.
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

// Test that the battery routine fails if charge_full_design is outside the
// limits.
TEST_F(BatteryCapacityRoutineTest, LowChargeFullDesign) {
  CreateRoutine();
  power_manager::PowerSupplyProperties power_supply_proto;
  power_supply_proto.set_battery_charge_full_design(
      kBadBatteryChargeFullDesign);
  fake_powerd_adapter()->SetPowerSupplyProperties(power_supply_proto);
  RunRoutineAndWaitForExit();
  VerifyNonInteractiveUpdate(update()->routine_update_union,
                             mojom::DiagnosticRoutineStatusEnum::kFailed,
                             kBatteryCapacityRoutineFailedMessage);
}

// Test that the battery routine passes if charge_full_design is within the
// limits.
TEST_F(BatteryCapacityRoutineTest, GoodChargeFullDesign) {
  CreateRoutine();
  power_manager::PowerSupplyProperties power_supply_proto;
  power_supply_proto.set_battery_charge_full_design(
      kGoodBatteryChargeFullDesign);
  fake_powerd_adapter()->SetPowerSupplyProperties(power_supply_proto);
  RunRoutineAndWaitForExit();
  VerifyNonInteractiveUpdate(update()->routine_update_union,
                             mojom::DiagnosticRoutineStatusEnum::kPassed,
                             kBatteryCapacityRoutineSucceededMessage);
}

// Test that the battery routine handles an error from powerd.
TEST_F(BatteryCapacityRoutineTest, PowerdError) {
  CreateRoutine();
  fake_powerd_adapter()->SetPowerSupplyProperties(std::nullopt);
  RunRoutineAndWaitForExit();
  VerifyNonInteractiveUpdate(update()->routine_update_union,
                             mojom::DiagnosticRoutineStatusEnum::kError,
                             kPowerdPowerSupplyPropertiesFailedMessage);
}

// Test that the battery routine handles invalid parameters.
TEST_F(BatteryCapacityRoutineTest, InvalidParameters) {
  constexpr uint32_t kInvalidLowMah = 5;
  constexpr uint32_t kInvalidHighMah = 4;
  CreateRoutine(kInvalidLowMah, kInvalidHighMah);
  RunRoutineAndWaitForExit();
  VerifyNonInteractiveUpdate(update()->routine_update_union,
                             mojom::DiagnosticRoutineStatusEnum::kError,
                             kBatteryCapacityRoutineParametersInvalidMessage);
}

}  // namespace
}  // namespace diagnostics
