// Copyright 2021 The ChromiumOS Authors
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
#include "diagnostics/cros_healthd/routines/arc_dns_resolution/arc_dns_resolution.h"
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

// POD struct for ArcDnsResolutionProblemTest.
struct ArcDnsResolutionProblemTestParams {
  network_diagnostics_ipc::ArcDnsResolutionProblem problem_enum;
  std::string failure_message;
};

class ArcDnsResolutionRoutineTest : public testing::Test {
 protected:
  ArcDnsResolutionRoutineTest() = default;
  ArcDnsResolutionRoutineTest(const ArcDnsResolutionRoutineTest&) = delete;
  ArcDnsResolutionRoutineTest& operator=(const ArcDnsResolutionRoutineTest&) =
      delete;

  void SetUp() override {
    routine_ = CreateArcDnsResolutionRoutine(network_diagnostics_adapter());
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

// Test that the ArcDnsResolution routine can be run successfully.
TEST_F(ArcDnsResolutionRoutineTest, RoutineSuccess) {
  EXPECT_CALL(*(network_diagnostics_adapter()), RunArcDnsResolutionRoutine(_))
      .WillOnce(Invoke([&](network_diagnostics_ipc::NetworkDiagnosticsRoutines::
                               RunArcDnsResolutionCallback callback) {
        auto result =
            CreateResult(network_diagnostics_ipc::RoutineVerdict::kNoProblem,
                         network_diagnostics_ipc::RoutineProblems::
                             NewArcDnsResolutionProblems({}));
        std::move(callback).Run(std::move(result));
      }));

  mojom::RoutineUpdatePtr routine_update = RunRoutineAndWaitForExit();
  VerifyNonInteractiveUpdate(routine_update->routine_update_union,
                             mojom::DiagnosticRoutineStatusEnum::kPassed,
                             kArcDnsResolutionRoutineNoProblemMessage);
}

// Test that the ArcDnsResolution routine returns a kNotRun status when it is
// not run.
TEST_F(ArcDnsResolutionRoutineTest, RoutineNotRun) {
  EXPECT_CALL(*(network_diagnostics_adapter()), RunArcDnsResolutionRoutine(_))
      .WillOnce(Invoke([&](network_diagnostics_ipc::NetworkDiagnosticsRoutines::
                               RunArcDnsResolutionCallback callback) {
        auto result =
            CreateResult(network_diagnostics_ipc::RoutineVerdict::kNotRun,
                         network_diagnostics_ipc::RoutineProblems::
                             NewArcDnsResolutionProblems({}));
        std::move(callback).Run(std::move(result));
      }));

  mojom::RoutineUpdatePtr routine_update = RunRoutineAndWaitForExit();
  VerifyNonInteractiveUpdate(routine_update->routine_update_union,
                             mojom::DiagnosticRoutineStatusEnum::kNotRun,
                             kArcDnsResolutionRoutineNotRunMessage);
}

// Tests that the ArcDnsResolution routine handles problems.
//
// This is a parameterized test with the following parameters (accessed through
// the ArcDnsResolutionProblemTestParams POD struct):
// * |problem_enum| - The type of ArcDnsResolution problem.
// * |failure_message| - Failure message for a problem.
class ArcDnsResolutionProblemTest
    : public ArcDnsResolutionRoutineTest,
      public WithParamInterface<ArcDnsResolutionProblemTestParams> {
 protected:
  // Accessors to the test parameters returned by gtest's GetParam():
  ArcDnsResolutionProblemTestParams params() const { return GetParam(); }
};

// Test that the ArcDnsResolution routine handles the given DNS resolution
// problem.
TEST_P(ArcDnsResolutionProblemTest, HandleArcDnsResolutionProblem) {
  EXPECT_CALL(*(network_diagnostics_adapter()), RunArcDnsResolutionRoutine(_))
      .WillOnce(Invoke([&](network_diagnostics_ipc::NetworkDiagnosticsRoutines::
                               RunArcDnsResolutionCallback callback) {
        auto result = CreateResult(
            network_diagnostics_ipc::RoutineVerdict::kProblem,
            network_diagnostics_ipc::RoutineProblems::
                NewArcDnsResolutionProblems({params().problem_enum}));
        std::move(callback).Run(std::move(result));
      }));

  mojom::RoutineUpdatePtr routine_update = RunRoutineAndWaitForExit();
  VerifyNonInteractiveUpdate(routine_update->routine_update_union,
                             mojom::DiagnosticRoutineStatusEnum::kFailed,
                             params().failure_message);
}

INSTANTIATE_TEST_SUITE_P(
    ,
    ArcDnsResolutionProblemTest,
    Values(
        ArcDnsResolutionProblemTestParams{
            network_diagnostics_ipc::ArcDnsResolutionProblem::
                kFailedToGetArcServiceManager,
            kArcDnsResolutionRoutineFailedToGetArcServiceManagerMessage},
        ArcDnsResolutionProblemTestParams{
            network_diagnostics_ipc::ArcDnsResolutionProblem::
                kFailedToGetNetInstanceForDnsResolutionTest,
            kArcDnsResolutionRoutineFailedToGetNetInstanceMessage},
        ArcDnsResolutionProblemTestParams{
            network_diagnostics_ipc::ArcDnsResolutionProblem::kHighLatency,
            kArcDnsResolutionRoutineHighLatencyMessage},
        ArcDnsResolutionProblemTestParams{
            network_diagnostics_ipc::ArcDnsResolutionProblem::kVeryHighLatency,
            kArcDnsResolutionRoutineVeryHighLatencyMessage},
        ArcDnsResolutionProblemTestParams{
            network_diagnostics_ipc::ArcDnsResolutionProblem::kFailedDnsQueries,
            kArcDnsResolutionRoutineFailedDnsQueriesMessage}));

}  // namespace
}  // namespace diagnostics
