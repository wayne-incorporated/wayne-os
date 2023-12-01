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
#include "diagnostics/cros_healthd/routines/network/https_firewall.h"
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

// POD struct for HttpsFirewallProblemTest.
struct HttpsFirewallProblemTestParams {
  network_diagnostics_ipc::HttpsFirewallProblem problem_enum;
  std::string failure_message;
};

class HttpsFirewallRoutineTest : public testing::Test {
 protected:
  HttpsFirewallRoutineTest() = default;
  HttpsFirewallRoutineTest(const HttpsFirewallRoutineTest&) = delete;
  HttpsFirewallRoutineTest& operator=(const HttpsFirewallRoutineTest&) = delete;

  void SetUp() override {
    routine_ = CreateHttpsFirewallRoutine(network_diagnostics_adapter());
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

// Test that the HttpsFirewall routine can be run successfully.
TEST_F(HttpsFirewallRoutineTest, RoutineSuccess) {
  EXPECT_CALL(*(network_diagnostics_adapter()), RunHttpsFirewallRoutine(_))
      .WillOnce(Invoke([&](network_diagnostics_ipc::NetworkDiagnosticsRoutines::
                               RunHttpsFirewallCallback callback) {
        auto result = CreateResult(
            network_diagnostics_ipc::RoutineVerdict::kNoProblem,
            network_diagnostics_ipc::RoutineProblems::NewHttpsFirewallProblems(
                {}));
        std::move(callback).Run(std::move(result));
      }));

  mojom::RoutineUpdatePtr routine_update = RunRoutineAndWaitForExit();
  VerifyNonInteractiveUpdate(routine_update->routine_update_union,
                             mojom::DiagnosticRoutineStatusEnum::kPassed,
                             kHttpsFirewallRoutineNoProblemMessage);
}

// Test that the HttpsFirewall routine returns an error when it is not
// run.
TEST_F(HttpsFirewallRoutineTest, RoutineError) {
  EXPECT_CALL(*(network_diagnostics_adapter()), RunHttpsFirewallRoutine(_))
      .WillOnce(Invoke([&](network_diagnostics_ipc::NetworkDiagnosticsRoutines::
                               RunHttpsFirewallCallback callback) {
        auto result = CreateResult(
            network_diagnostics_ipc::RoutineVerdict::kNotRun,
            network_diagnostics_ipc::RoutineProblems::NewHttpsFirewallProblems(
                {}));
        std::move(callback).Run(std::move(result));
      }));

  mojom::RoutineUpdatePtr routine_update = RunRoutineAndWaitForExit();
  VerifyNonInteractiveUpdate(routine_update->routine_update_union,
                             mojom::DiagnosticRoutineStatusEnum::kNotRun,
                             kHttpsFirewallRoutineNotRunMessage);
}

// Tests that the HttpsFirewall routine handles problems.
//
// This is a parameterized test with the following parameters (accessed through
// the HttpsFirewallProblemTestParams POD struct):
// * |problem_enum| - The type of HttpsFirewall problem.
// * |failure_message| - Failure message for a problem.
class HttpsFirewallProblemTest
    : public HttpsFirewallRoutineTest,
      public WithParamInterface<HttpsFirewallProblemTestParams> {
 protected:
  // Accessors to the test parameters returned by gtest's GetParam():
  HttpsFirewallProblemTestParams params() const { return GetParam(); }
};

// Test that the HttpsFirewall routine handles the given HTTPS firewall problem.
TEST_P(HttpsFirewallProblemTest, HandleHttpsFirewallProblem) {
  EXPECT_CALL(*(network_diagnostics_adapter()), RunHttpsFirewallRoutine(_))
      .WillOnce(Invoke([&](network_diagnostics_ipc::NetworkDiagnosticsRoutines::
                               RunHttpsFirewallCallback callback) {
        auto result = CreateResult(
            network_diagnostics_ipc::RoutineVerdict::kProblem,
            network_diagnostics_ipc::RoutineProblems::NewHttpsFirewallProblems(
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
    HttpsFirewallProblemTest,
    Values(
        HttpsFirewallProblemTestParams{
            network_diagnostics_ipc::HttpsFirewallProblem::
                kHighDnsResolutionFailureRate,
            kHttpsFirewallRoutineHighDnsResolutionFailureRateProblemMessage},
        HttpsFirewallProblemTestParams{
            network_diagnostics_ipc::HttpsFirewallProblem::kFirewallDetected,
            kHttpsFirewallRoutineFirewallDetectedProblemMessage},
        HttpsFirewallProblemTestParams{
            network_diagnostics_ipc::HttpsFirewallProblem::kPotentialFirewall,
            kHttpsFirewallRoutinePotentialFirewallProblemMessage}));

}  // namespace
}  // namespace diagnostics
