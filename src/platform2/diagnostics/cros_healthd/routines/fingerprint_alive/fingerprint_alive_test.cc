// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <utility>

#include <base/check.h>
#include <base/test/task_environment.h>
#include <gtest/gtest.h>

#include "diagnostics/cros_healthd/routines/fingerprint_alive/fingerprint_alive.h"
#include "diagnostics/cros_healthd/system/mock_context.h"
#include "diagnostics/mojom/public/cros_healthd_diagnostics.mojom.h"

namespace diagnostics {
namespace {

namespace mojom = ::ash::cros_healthd::mojom;

using ::testing::_;
using ::testing::Invoke;
using ::testing::WithArg;

class FingerprintAliveRoutineTest : public testing::Test {
 protected:
  FingerprintAliveRoutineTest() = default;
  FingerprintAliveRoutineTest(const FingerprintAliveRoutineTest&) = delete;
  FingerprintAliveRoutineTest& operator=(const FingerprintAliveRoutineTest&) =
      delete;

  void CreateRoutine() {
    routine_ = std::make_unique<FingerprintAliveRoutine>(mock_context());
  }

  void SetExecutorGetFingerprintInfoResponse(
      const std::optional<std::string>& err, bool rw_fw) {
    EXPECT_CALL(*mock_executor(), GetFingerprintInfo(_))
        .WillOnce(WithArg<0>(
            Invoke([=](mojom::Executor::GetFingerprintInfoCallback callback) {
              mojom::FingerprintInfoResult result;
              result.rw_fw = rw_fw;

              std::move(callback).Run(result.Clone(), err);
            })));
  }

  MockContext* mock_context() { return &mock_context_; }
  MockExecutor* mock_executor() { return mock_context_.mock_executor(); }

  MockContext mock_context_;
  std::unique_ptr<FingerprintAliveRoutine> routine_;
  mojom::RoutineUpdate update_{0, mojo::ScopedHandle(),
                               mojom::RoutineUpdateUnionPtr()};
};

TEST_F(FingerprintAliveRoutineTest, DefaultConstruction) {
  CreateRoutine();
  EXPECT_EQ(routine_->GetStatus(), mojom::DiagnosticRoutineStatusEnum::kReady);
}

TEST_F(FingerprintAliveRoutineTest, ResponseErrorCase) {
  CreateRoutine();
  SetExecutorGetFingerprintInfoResponse("err", /*rw_fw=*/true);

  routine_->Start();
  EXPECT_EQ(routine_->GetStatus(), mojom::DiagnosticRoutineStatusEnum::kFailed);
}

TEST_F(FingerprintAliveRoutineTest, SuccessfulCase) {
  CreateRoutine();
  SetExecutorGetFingerprintInfoResponse(/*err=*/std::nullopt, /*rw_fw=*/true);

  routine_->Start();
  EXPECT_EQ(routine_->GetStatus(), mojom::DiagnosticRoutineStatusEnum::kPassed);
}

TEST_F(FingerprintAliveRoutineTest, FailCase) {
  CreateRoutine();
  SetExecutorGetFingerprintInfoResponse(/*err=*/std::nullopt, /*rw_fw=*/false);

  routine_->Start();
  EXPECT_EQ(routine_->GetStatus(), mojom::DiagnosticRoutineStatusEnum::kFailed);
}

}  // namespace
}  // namespace diagnostics
