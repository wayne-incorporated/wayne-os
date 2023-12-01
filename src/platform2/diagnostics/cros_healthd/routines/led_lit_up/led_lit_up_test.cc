// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/routines/led_lit_up/led_lit_up.h"

#include <memory>
#include <optional>
#include <utility>

#include <base/test/task_environment.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <mojo/public/cpp/bindings/pending_receiver.h>
#include <mojo/public/cpp/bindings/receiver.h>

#include "diagnostics/cros_healthd/system/mock_context.h"
#include "diagnostics/mojom/public/cros_healthd_diagnostics.mojom.h"

namespace diagnostics {
namespace {

namespace mojom = ::ash::cros_healthd::mojom;

using ::testing::_;
using ::testing::InvokeWithoutArgs;
using ::testing::WithArg;

class MockLedLitUpRoutineReplier : public mojom::LedLitUpRoutineReplier {
 public:
  explicit MockLedLitUpRoutineReplier(
      mojo::PendingReceiver<mojom::LedLitUpRoutineReplier> receiver)
      : receiver_{this /* impl */, std::move(receiver)} {
    DCHECK(receiver_.is_bound());
  }
  MockLedLitUpRoutineReplier(const MockLedLitUpRoutineReplier&) = delete;
  MockLedLitUpRoutineReplier& operator=(const MockLedLitUpRoutineReplier&) =
      delete;

  void Disconnect() { receiver_.reset(); }

  MOCK_METHOD(void, GetColorMatched, (GetColorMatchedCallback), (override));

 private:
  mojo::Receiver<mojom::LedLitUpRoutineReplier> receiver_;
};

class LedLitUpRoutineTest : public testing::Test {
 protected:
  LedLitUpRoutineTest() = default;
  LedLitUpRoutineTest(const LedLitUpRoutineTest&) = delete;
  LedLitUpRoutineTest& operator=(const LedLitUpRoutineTest&) = delete;

  void CreateRoutine() {
    mojo::PendingReceiver<mojom::LedLitUpRoutineReplier> replier_receiver;
    mojo::PendingRemote<mojom::LedLitUpRoutineReplier> replier_remote(
        replier_receiver.InitWithNewPipeAndPassRemote());
    mock_replier_ =
        std::make_unique<testing::StrictMock<MockLedLitUpRoutineReplier>>(
            std::move(replier_receiver));
    // The LED name and color are arbitrary for testing.
    routine_ = std::make_unique<LedLitUpRoutine>(
        mock_context(), mojom::LedName::kBattery, mojom::LedColor::kRed,
        std::move(replier_remote));
  }

  void StartRoutine() { routine_->Start(); }

  mojom::DiagnosticRoutineStatusEnum GetStatus() {
    return routine_->GetStatus();
  }

  void SetExecutorSetLedColorResponse(const std::optional<std::string>& err) {
    EXPECT_CALL(*mock_executor(), SetLedColor(_, _, _))
        .WillOnce(
            WithArg<2>([=](mojom::Executor::SetLedColorCallback callback) {
              std::move(callback).Run(err);
            }));
  }

  void SetExecutorResetLedColorResponse(const std::optional<std::string>& err) {
    EXPECT_CALL(*mock_executor(), ResetLedColor(_, _))
        .WillOnce(
            WithArg<1>([=](mojom::Executor::ResetLedColorCallback callback) {
              std::move(callback).Run(err);
            }));
  }

  void SetReplierGetColorMatchedResponse(bool matched) {
    EXPECT_CALL(*mock_replier(), GetColorMatched(_))
        .WillOnce([=](mojom::LedLitUpRoutineReplier::GetColorMatchedCallback
                          callback) { std::move(callback).Run(matched); });
  }

  base::test::TaskEnvironment* task_environment() { return &task_environment_; }
  MockContext* mock_context() { return &mock_context_; }
  MockExecutor* mock_executor() { return mock_context_.mock_executor(); }
  MockLedLitUpRoutineReplier* mock_replier() { return mock_replier_.get(); }

 private:
  base::test::SingleThreadTaskEnvironment task_environment_;
  MockContext mock_context_;
  std::unique_ptr<LedLitUpRoutine> routine_;
  std::unique_ptr<MockLedLitUpRoutineReplier> mock_replier_;
};

TEST_F(LedLitUpRoutineTest, CreateRoutine) {
  CreateRoutine();
  EXPECT_EQ(GetStatus(), mojom::DiagnosticRoutineStatusEnum::kReady);
}

TEST_F(LedLitUpRoutineTest, SetLedColorError) {
  CreateRoutine();
  SetExecutorSetLedColorResponse("Set LED color failed");

  StartRoutine();
  task_environment()->RunUntilIdle();
  EXPECT_EQ(GetStatus(), mojom::DiagnosticRoutineStatusEnum::kFailed);
}

TEST_F(LedLitUpRoutineTest, ReplierDisconnectedBeforeMethodCall) {
  CreateRoutine();
  SetExecutorSetLedColorResponse(std::nullopt);
  EXPECT_CALL(*mock_executor(), ResetLedColor(_, _));

  mock_replier()->Disconnect();
  // Wait until the disconnection takes effect.
  task_environment()->RunUntilIdle();

  StartRoutine();
  task_environment()->RunUntilIdle();
  EXPECT_EQ(GetStatus(), mojom::DiagnosticRoutineStatusEnum::kFailed);
}

TEST_F(LedLitUpRoutineTest, ReplierDisconnectedAfterMethodCall) {
  CreateRoutine();
  SetExecutorSetLedColorResponse(std::nullopt);
  // Disconnect the replier when waiting for the response of |GetColorMatched|.
  EXPECT_CALL(*mock_replier(), GetColorMatched(_))
      .WillOnce(InvokeWithoutArgs(mock_replier(),
                                  &MockLedLitUpRoutineReplier::Disconnect));
  EXPECT_CALL(*mock_executor(), ResetLedColor(_, _));

  StartRoutine();
  task_environment()->RunUntilIdle();
  EXPECT_EQ(GetStatus(), mojom::DiagnosticRoutineStatusEnum::kFailed);
}

TEST_F(LedLitUpRoutineTest, ColorNotMatched) {
  CreateRoutine();
  SetExecutorSetLedColorResponse(std::nullopt);
  SetReplierGetColorMatchedResponse(false);
  SetExecutorResetLedColorResponse(std::nullopt);

  StartRoutine();
  task_environment()->RunUntilIdle();
  EXPECT_EQ(GetStatus(), mojom::DiagnosticRoutineStatusEnum::kFailed);
}

TEST_F(LedLitUpRoutineTest, ResetLedColorError) {
  CreateRoutine();
  SetExecutorSetLedColorResponse(std::nullopt);
  SetReplierGetColorMatchedResponse(true);
  SetExecutorResetLedColorResponse("Reset LED color failed");

  StartRoutine();
  task_environment()->RunUntilIdle();
  EXPECT_EQ(GetStatus(), mojom::DiagnosticRoutineStatusEnum::kFailed);
}

TEST_F(LedLitUpRoutineTest, SuccessfulCase) {
  CreateRoutine();
  SetExecutorSetLedColorResponse(std::nullopt);
  SetReplierGetColorMatchedResponse(true);
  SetExecutorResetLedColorResponse(std::nullopt);

  StartRoutine();
  task_environment()->RunUntilIdle();
  EXPECT_EQ(GetStatus(), mojom::DiagnosticRoutineStatusEnum::kPassed);
}

}  // namespace
}  // namespace diagnostics
