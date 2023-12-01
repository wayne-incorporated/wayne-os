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
#include "diagnostics/cros_healthd/routines/network/http_firewall.h"
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

// POD struct for HttpFirewallProblemTest.
struct HttpFirewallProblemTestParams {
  network_diagnostics_ipc::HttpFirewallProblem problem_enum;
  std::string failure_message;
};

class HttpFirewallRoutineTest : public testing::Test {
 protected:
  HttpFirewallRoutineTest() = default;
  HttpFirewallRoutineTest(const HttpFirewallRoutineTest&) = delete;
  HttpFirewallRoutineTest& operator=(const HttpFirewallRoutineTest&) = delete;

  void SetUp() override {
    routine_ = CreateHttpFirewallRoutine(network_diagnostics_adapter());
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

// Test that the HttpFirewall routine can be run successfully.
TEST_F(HttpFirewallRoutineTest, RoutineSuccess) {
  EXPECT_CALL(*(network_diagnostics_adapter()), RunHttpFirewallRoutine(_))
      .WillOnce(Invoke([&](network_diagnostics_ipc::NetworkDiagnosticsRoutines::
                               RunHttpFirewallCallback callback) {
        auto result = CreateResult(
            network_diagnostics_ipc::RoutineVerdict::kNoProblem,
            network_diagnostics_ipc::RoutineProblems::NewHttpFirewallProblems(
                {}));
        std::move(callback).Run(std::move(result));
      }));

  mojom::RoutineUpdatePtr routine_update = RunRoutineAndWaitForExit();
  VerifyNonInteractiveUpdate(routine_update->routine_update_union,
                             mojom::DiagnosticRoutineStatusEnum::kPassed,
                             kHttpFirewallRoutineNoProblemMessage);
}

// Test that the HttpFirewall routine returns a kNotRun status when it is not
// run.
TEST_F(HttpFirewallRoutineTest, RoutineNotRun) {
  EXPECT_CALL(*(network_diagnostics_adapter()), RunHttpFirewallRoutine(_))
      .WillOnce(Invoke([&](network_diagnostics_ipc::NetworkDiagnosticsRoutines::
                               RunHttpFirewallCallback callback) {
        auto result = CreateResult(
            network_diagnostics_ipc::RoutineVerdict::kNotRun,
            network_diagnostics_ipc::RoutineProblems::NewHttpFirewallProblems(
                {}));
        std::move(callback).Run(std::move(result));
      }));

  mojom::RoutineUpdatePtr routine_update = RunRoutineAndWaitForExit();
  VerifyNonInteractiveUpdate(routine_update->routine_update_union,
                             mojom::DiagnosticRoutineStatusEnum::kNotRun,
                             kHttpFirewallRoutineNotRunMessage);
}

// Tests that the HttpFirewall routine handles problems.
//
// This is a parameterized test with the following parameters (accessed through
// the HttpFirewallProblemTestParams POD struct):
// * |problem_enum| - The type of HttpFirewall problem.
// * |failure_message| - Failure message for a problem.
class HttpFirewallProblemTest
    : public HttpFirewallRoutineTest,
      public WithParamInterface<HttpFirewallProblemTestParams> {
 protected:
  // Accessors to the test parameters returned by gtest's GetParam():
  HttpFirewallProblemTestParams params() const { return GetParam(); }
};

// Test that the HttpFirewall routine handles the given HTTP firewall problem.
TEST_P(HttpFirewallProblemTest, HandleHttpFirewallProblem) {
  EXPECT_CALL(*(network_diagnostics_adapter()), RunHttpFirewallRoutine(_))
      .WillOnce(Invoke([&](network_diagnostics_ipc::NetworkDiagnosticsRoutines::
                               RunHttpFirewallCallback callback) {
        auto result = CreateResult(
            network_diagnostics_ipc::RoutineVerdict::kProblem,
            network_diagnostics_ipc::RoutineProblems::NewHttpFirewallProblems(
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
    HttpFirewallProblemTest,
    Values(
        HttpFirewallProblemTestParams{
            network_diagnostics_ipc::HttpFirewallProblem::
                kDnsResolutionFailuresAboveThreshold,
            kHttpFirewallRoutineHighDnsResolutionFailureRateProblemMessage},
        HttpFirewallProblemTestParams{
            network_diagnostics_ipc::HttpFirewallProblem::kFirewallDetected,
            kHttpFirewallRoutineFirewallDetectedProblemMessage},
        HttpFirewallProblemTestParams{
            network_diagnostics_ipc::HttpFirewallProblem::kPotentialFirewall,
            kHttpFirewallRoutinePotentialFirewallProblemMessage}));

}  // namespace
}  // namespace diagnostics
