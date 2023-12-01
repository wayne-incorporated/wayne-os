// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <utility>

#include <base/test/task_environment.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "diagnostics/cros_healthd/routines/power_button/power_button.h"
#include "diagnostics/cros_healthd/routines/routine_test_utils.h"
#include "diagnostics/cros_healthd/system/mock_context.h"
#include "diagnostics/mojom/public/cros_healthd_diagnostics.mojom.h"

namespace diagnostics {
namespace {

namespace mojom = ::ash::cros_healthd::mojom;

using ::testing::WithArg;

class PowerButtonRoutineTest : public testing::Test {
 protected:
  PowerButtonRoutineTest() = default;
  PowerButtonRoutineTest(const PowerButtonRoutineTest&) = delete;
  PowerButtonRoutineTest& operator=(const PowerButtonRoutineTest&) = delete;

  void ExpectBindEventObserver() {
    EXPECT_CALL(*mock_executor(), MonitorPowerButton)
        .WillOnce(WithArg<0>([=](auto power_button_observer) {
          power_button_observer_.Bind(std::move(power_button_observer));
        }));
  }

  void EmitPowerButtonEvent() {
    // Emit an arbitrary event.
    power_button_observer_->OnEvent(
        mojom::PowerButtonObserver::ButtonState::kUp);
  }

  void VerifyRoutineResult(PowerButtonRoutine& routine,
                           mojom::DiagnosticRoutineStatusEnum expected_status,
                           const std::string& expected_status_message) {
    mojom::RoutineUpdate update_{0, mojo::ScopedHandle(),
                                 mojom::RoutineUpdateUnionPtr()};
    routine.PopulateStatusUpdate(&update_, /*include_output*/ true);
    EXPECT_EQ(update_.progress_percent, 100);
    VerifyNonInteractiveUpdate(update_.routine_update_union, expected_status,
                               expected_status_message);
  }

  MockExecutor* mock_executor() { return mock_context_.mock_executor(); }

  base::test::TaskEnvironment task_environment_{
      base::test::TaskEnvironment::TimeSource::MOCK_TIME};
  MockContext mock_context_;
  mojo::Remote<mojom::PowerButtonObserver> power_button_observer_;
};

TEST_F(PowerButtonRoutineTest, ReadyStateBeforeStart) {
  PowerButtonRoutine routine{&mock_context_, /*timeout_seconds=*/10};
  EXPECT_EQ(routine.GetStatus(), mojom::DiagnosticRoutineStatusEnum::kReady);
}

TEST_F(PowerButtonRoutineTest, ErrorWhenTimeoutTooShort) {
  PowerButtonRoutine routine{&mock_context_, /*timeout_seconds=*/0};
  routine.Start();
  VerifyRoutineResult(routine, mojom::DiagnosticRoutineStatusEnum::kError,
                      "Timeout is not in range [1, 600]");
}

TEST_F(PowerButtonRoutineTest, ErrorWhenTimeoutTooLong) {
  PowerButtonRoutine routine{&mock_context_, /*timeout_seconds=*/601};
  routine.Start();
  VerifyRoutineResult(routine, mojom::DiagnosticRoutineStatusEnum::kError,
                      "Timeout is not in range [1, 600]");
}

TEST_F(PowerButtonRoutineTest, PassedWhenEventReceived) {
  ExpectBindEventObserver();

  PowerButtonRoutine routine{&mock_context_, /*timeout_seconds=*/10};
  routine.Start();
  EmitPowerButtonEvent();

  task_environment_.RunUntilIdle();
  VerifyRoutineResult(routine, mojom::DiagnosticRoutineStatusEnum::kPassed,
                      "Routine passed.");
}

TEST_F(PowerButtonRoutineTest, FailedWhenTimeout) {
  ExpectBindEventObserver();

  const base::TimeDelta timeout = base::Seconds(/*timeout_seconds=*/10);
  PowerButtonRoutine routine{&mock_context_,
                             static_cast<uint32_t>(timeout.InSeconds())};
  routine.Start();

  task_environment_.FastForwardBy(timeout);
  VerifyRoutineResult(routine, mojom::DiagnosticRoutineStatusEnum::kFailed,
                      "Routine failed. No power button event observed.");
}

TEST_F(PowerButtonRoutineTest, PassedShouldNotBeOverridenByTimeout) {
  ExpectBindEventObserver();

  const base::TimeDelta timeout = base::Seconds(/*timeout_seconds=*/10);
  PowerButtonRoutine routine{&mock_context_,
                             static_cast<uint32_t>(timeout.InSeconds())};
  routine.Start();
  EmitPowerButtonEvent();

  task_environment_.RunUntilIdle();
  EXPECT_EQ(routine.GetStatus(), mojom::DiagnosticRoutineStatusEnum::kPassed);

  task_environment_.FastForwardBy(timeout);
  EXPECT_EQ(routine.GetStatus(), mojom::DiagnosticRoutineStatusEnum::kPassed);
}

TEST_F(PowerButtonRoutineTest, ErrorWhenEventSubscriptionFailed) {
  ExpectBindEventObserver();

  PowerButtonRoutine routine{&mock_context_, /*timeout_seconds=*/10};
  routine.Start();
  power_button_observer_.reset();

  task_environment_.RunUntilIdle();
  VerifyRoutineResult(
      routine, mojom::DiagnosticRoutineStatusEnum::kError,
      "Routine error. Unable to listen for power button events.");
}

}  // namespace
}  // namespace diagnostics
