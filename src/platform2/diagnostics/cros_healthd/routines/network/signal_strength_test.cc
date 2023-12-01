// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <string>
#include <utility>

#include <base/check.h>
#include <base/run_loop.h>
#include <base/test/task_environment.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "diagnostics/cros_healthd/network_diagnostics/network_diagnostics_utils.h"
#include "diagnostics/cros_healthd/routines/network/signal_strength.h"
#include "diagnostics/cros_healthd/routines/routine_test_utils.h"
#include "diagnostics/cros_healthd/system/mock_context.h"
#include "diagnostics/mojom/external/network_diagnostics.mojom.h"
#include "diagnostics/mojom/public/cros_healthd_diagnostics.mojom.h"

namespace diagnostics {
namespace {

namespace mojom = ::ash::cros_healthd::mojom;
namespace network_diagnostics_ipc = ::chromeos::network_diagnostics::mojom;
using ::testing::_;
using ::testing::Invoke;
using ::testing::Values;
using ::testing::WithParamInterface;

// POD struct for SignalStrengthProblemTest.
struct SignalStrengthProblemTestParams {
  network_diagnostics_ipc::SignalStrengthProblem problem_enum;
  std::string failure_message;
};

class SignalStrengthRoutineTest : public testing::Test {
 protected:
  SignalStrengthRoutineTest() = default;
  SignalStrengthRoutineTest(const SignalStrengthRoutineTest&) = delete;
  SignalStrengthRoutineTest& operator=(const SignalStrengthRoutineTest&) =
      delete;

  void SetUp() override {
    routine_ = CreateSignalStrengthRoutine(network_diagnostics_adapter());
  }

  mojom::RoutineUpdatePtr RunRoutineAndWaitForExit() {
    DCHECK(routine_);
    mojom::RoutineUpdate update{0, mojo::ScopedHandle(),
                                mojom::RoutineUpdateUnionPtr()};
    routine_->Start();
    routine_->PopulateStatusUpdate(&update, true);
    return mojom::RoutineUpdate::New(update.progress_percent,
                                     std::move(update.output),
                                     std::move(update.routine_update_union));
  }

  MockNetworkDiagnosticsAdapter* network_diagnostics_adapter() {
    return mock_context_.network_diagnostics_adapter();
  }

 private:
  base::test::SingleThreadTaskEnvironment task_environment_;
  MockContext mock_context_;
  std::unique_ptr<DiagnosticRoutine> routine_;
};

// Test that the SignalStrength routine can be run successfully.
TEST_F(SignalStrengthRoutineTest, RoutineSuccess) {
  EXPECT_CALL(*(network_diagnostics_adapter()), RunSignalStrengthRoutine(_))
      .WillOnce(Invoke([&](network_diagnostics_ipc::NetworkDiagnosticsRoutines::
                               RunSignalStrengthCallback callback) {
        auto result = CreateResult(
            network_diagnostics_ipc::RoutineVerdict::kNoProblem,
            network_diagnostics_ipc::RoutineProblems::NewSignalStrengthProblems(
                {}));
        std::move(callback).Run(std::move(result));
      }));

  mojom::RoutineUpdatePtr routine_update = RunRoutineAndWaitForExit();
  VerifyNonInteractiveUpdate(routine_update->routine_update_union,
                             mojom::DiagnosticRoutineStatusEnum::kPassed,
                             kSignalStrengthRoutineNoProblemMessage);
}

// Test that the SignalStrength routine returns a kNotRun status when it is not
// run.
TEST_F(SignalStrengthRoutineTest, RoutineNotRun) {
  EXPECT_CALL(*(network_diagnostics_adapter()), RunSignalStrengthRoutine(_))
      .WillOnce(Invoke([&](network_diagnostics_ipc::NetworkDiagnosticsRoutines::
                               RunSignalStrengthCallback callback) {
        auto result = CreateResult(
            network_diagnostics_ipc::RoutineVerdict::kNotRun,
            network_diagnostics_ipc::RoutineProblems::NewSignalStrengthProblems(
                {}));
        std::move(callback).Run(std::move(result));
      }));

  mojom::RoutineUpdatePtr routine_update = RunRoutineAndWaitForExit();
  VerifyNonInteractiveUpdate(routine_update->routine_update_union,
                             mojom::DiagnosticRoutineStatusEnum::kNotRun,
                             kSignalStrengthRoutineNotRunMessage);
}

// Tests that the SignalStrength routine handles problems.
//
// This is a parameterized test with the following parameters (accessed through
// the SignalStrengthProblemTestParams POD struct):
// * |problem_enum| - The type of SignalStrength problem.
// * |failure_message| - Failure message for a problem.
class SignalStrengthProblemTest
    : public SignalStrengthRoutineTest,
      public WithParamInterface<SignalStrengthProblemTestParams> {
 protected:
  // Accessors to the test parameters returned by gtest's GetParam():
  SignalStrengthProblemTestParams params() const { return GetParam(); }
};

// Test that the SignalStrength routine handles the given signal strength
// problem.
TEST_P(SignalStrengthProblemTest, HandleSignalStrengthProblem) {
  EXPECT_CALL(*(network_diagnostics_adapter()), RunSignalStrengthRoutine(_))
      .WillOnce(Invoke([&](network_diagnostics_ipc::NetworkDiagnosticsRoutines::
                               RunSignalStrengthCallback callback) {
        auto result = CreateResult(
            network_diagnostics_ipc::RoutineVerdict::kProblem,
            network_diagnostics_ipc::RoutineProblems::NewSignalStrengthProblems(
                {params().problem_enum}));
        std::move(callback).Run(std::move(result));
      }));

  mojom::RoutineUpdatePtr routine_update = RunRoutineAndWaitForExit();
  VerifyNonInteractiveUpdate(routine_update->routine_update_union,
                             mojom::DiagnosticRoutineStatusEnum::kFailed,
                             params().failure_message);
}

INSTANTIATE_TEST_SUITE_P(
    ,
    SignalStrengthProblemTest,
    Values(SignalStrengthProblemTestParams{
        network_diagnostics_ipc::SignalStrengthProblem::kWeakSignal,
        kSignalStrengthRoutineWeakSignalProblemMessage}));

}  // namespace
}  // namespace diagnostics
