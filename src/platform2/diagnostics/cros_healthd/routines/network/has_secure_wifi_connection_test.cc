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
#include "diagnostics/cros_healthd/routines/network/has_secure_wifi_connection.h"
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

// POD struct for HasSecureWiFiConnectionProblemTest.
struct HasSecureWiFiConnectionProblemTestParams {
  network_diagnostics_ipc::HasSecureWiFiConnectionProblem problem_enum;
  std::string failure_message;
};

class HasSecureWiFiConnectionRoutineTest : public testing::Test {
 protected:
  HasSecureWiFiConnectionRoutineTest() = default;
  HasSecureWiFiConnectionRoutineTest(
      const HasSecureWiFiConnectionRoutineTest&) = delete;
  HasSecureWiFiConnectionRoutineTest& operator=(
      const HasSecureWiFiConnectionRoutineTest&) = delete;

  void SetUp() override {
    routine_ =
        CreateHasSecureWiFiConnectionRoutine(network_diagnostics_adapter());
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

// Test that the HasSecureWiFiConnection routine can be run successfully.
TEST_F(HasSecureWiFiConnectionRoutineTest, RoutineSuccess) {
  EXPECT_CALL(*(network_diagnostics_adapter()),
              RunHasSecureWiFiConnectionRoutine(_))
      .WillOnce(Invoke([&](network_diagnostics_ipc::NetworkDiagnosticsRoutines::
                               RunHasSecureWiFiConnectionCallback callback) {
        auto result =
            CreateResult(network_diagnostics_ipc::RoutineVerdict::kNoProblem,
                         network_diagnostics_ipc::RoutineProblems::
                             NewHasSecureWifiConnectionProblems({}));
        std::move(callback).Run(std::move(result));
      }));

  mojom::RoutineUpdatePtr routine_update = RunRoutineAndWaitForExit();
  VerifyNonInteractiveUpdate(routine_update->routine_update_union,
                             mojom::DiagnosticRoutineStatusEnum::kPassed,
                             kHasSecureWiFiConnectionRoutineNoProblemMessage);
}

// Test that the HasSecureWiFiConnection routine returns a kNotRun status when
// it is not run.
TEST_F(HasSecureWiFiConnectionRoutineTest, RoutineNotRun) {
  EXPECT_CALL(*(network_diagnostics_adapter()),
              RunHasSecureWiFiConnectionRoutine(_))
      .WillOnce(Invoke([&](network_diagnostics_ipc::NetworkDiagnosticsRoutines::
                               RunHasSecureWiFiConnectionCallback callback) {
        auto result =
            CreateResult(network_diagnostics_ipc::RoutineVerdict::kNotRun,
                         network_diagnostics_ipc::RoutineProblems::
                             NewHasSecureWifiConnectionProblems({}));
        std::move(callback).Run(std::move(result));
      }));

  mojom::RoutineUpdatePtr routine_update = RunRoutineAndWaitForExit();
  VerifyNonInteractiveUpdate(routine_update->routine_update_union,
                             mojom::DiagnosticRoutineStatusEnum::kNotRun,
                             kHasSecureWiFiConnectionRoutineNotRunMessage);
}

// Tests that the HasSecureWiFiConnection routine handles problems.
//
// This is a parameterized test with the following parameters (accessed through
// the HasSecureWiFiConnectionProblemTestParams POD struct):
// * |problem_enum| - The type of HasSecureWiFiConnection problem.
// * |failure_message| - Failure message for a problem.
class HasSecureWiFiConnectionProblemTest
    : public HasSecureWiFiConnectionRoutineTest,
      public WithParamInterface<HasSecureWiFiConnectionProblemTestParams> {
 protected:
  // Accessors to the test parameters returned by gtest's GetParam():
  HasSecureWiFiConnectionProblemTestParams params() const { return GetParam(); }
};

// Test that the HasSecureWiFiConnection routine handles the given has secure
// WiFi connection problem.
TEST_P(HasSecureWiFiConnectionProblemTest,
       HandleHasSecureWiFiConnectionProblem) {
  EXPECT_CALL(*(network_diagnostics_adapter()),
              RunHasSecureWiFiConnectionRoutine(_))
      .WillOnce(Invoke([&](network_diagnostics_ipc::NetworkDiagnosticsRoutines::
                               RunHasSecureWiFiConnectionCallback callback) {
        auto result = CreateResult(
            network_diagnostics_ipc::RoutineVerdict::kProblem,
            network_diagnostics_ipc::RoutineProblems::
                NewHasSecureWifiConnectionProblems({params().problem_enum}));
        std::move(callback).Run(std::move(result));
      }));

  mojom::RoutineUpdatePtr routine_update = RunRoutineAndWaitForExit();
  VerifyNonInteractiveUpdate(routine_update->routine_update_union,
                             mojom::DiagnosticRoutineStatusEnum::kFailed,
                             params().failure_message);
}

INSTANTIATE_TEST_SUITE_P(
    ,
    HasSecureWiFiConnectionProblemTest,
    Values(
        HasSecureWiFiConnectionProblemTestParams{
            network_diagnostics_ipc::HasSecureWiFiConnectionProblem::
                kSecurityTypeNone,
            kHasSecureWiFiConnectionRoutineSecurityTypeNoneProblemMessage},
        HasSecureWiFiConnectionProblemTestParams{
            network_diagnostics_ipc::HasSecureWiFiConnectionProblem::
                kSecurityTypeWep8021x,
            kHasSecureWiFiConnectionRoutineSecurityTypeWep8021xProblemMessage},
        HasSecureWiFiConnectionProblemTestParams{
            network_diagnostics_ipc::HasSecureWiFiConnectionProblem::
                kSecurityTypeWepPsk,
            kHasSecureWiFiConnectionRoutineSecurityTypeWepPskProblemMessage},
        HasSecureWiFiConnectionProblemTestParams{
            network_diagnostics_ipc::HasSecureWiFiConnectionProblem::
                kUnknownSecurityType,
            kHasSecureWiFiConnectionRoutineUnknownSecurityTypeProblemMessage}));

}  // namespace
}  // namespace diagnostics
