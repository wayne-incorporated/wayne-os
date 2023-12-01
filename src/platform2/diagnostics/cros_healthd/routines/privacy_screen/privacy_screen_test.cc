// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <utility>

#include <base/functional/bind.h>
#include <base/functional/callback_forward.h>
#include <base/task/sequenced_task_runner.h>
#include <base/test/task_environment.h>
#include <base/task/thread_pool/thread_pool_instance.h>
#include <base/test/bind.h>

#include "diagnostics/cros_healthd/routines/diag_routine.h"
#include "diagnostics/cros_healthd/routines/privacy_screen/privacy_screen.h"
#include "diagnostics/cros_healthd/routines/routine_test_utils.h"
#include "diagnostics/cros_healthd/system/fake_mojo_service.h"
#include "diagnostics/cros_healthd/system/mock_context.h"

namespace diagnostics {
namespace {

namespace mojom = ::ash::cros_healthd::mojom;
using ::testing::_;
using ::testing::Invoke;
using ::testing::WithArg;

const char kDisplayUtilInitializationError[] =
    "Failed to initialize DisplayUtil";

class PrivacyScreenRoutineTest : public ::testing::Test {
 public:
  PrivacyScreenRoutineTest(const PrivacyScreenRoutineTest&) = delete;
  PrivacyScreenRoutineTest& operator=(const PrivacyScreenRoutineTest&) = delete;

 protected:
  PrivacyScreenRoutineTest() = default;

  void SetUp() override {
    context_.fake_mojo_service()->InitializeFakeMojoService();
  }

  void CreateRoutine(bool target_state) {
    routine_ = std::make_unique<PrivacyScreenRoutine>(&context_, target_state);
  }

  void SetRoutineDestiny(bool display_util_init_success,
                         bool privacy_screen_supported,
                         bool privacy_screen_enabled_before,
                         std::optional<bool> privacy_screen_request_processed,
                         bool privacy_screen_enabled_after) {
    SetDelegateDestiny(display_util_init_success, privacy_screen_supported,
                       privacy_screen_enabled_before);
    context_.fake_mojo_service()
        ->fake_chromium_data_collector()
        .SetPrivacyScreenRequestProcessedBehaviour(
            base::BindOnce(&PrivacyScreenRoutineTest::SetDelegateDestiny,
                           base::Unretained(this), display_util_init_success,
                           privacy_screen_supported,
                           privacy_screen_enabled_after),
            privacy_screen_request_processed);
  }

  void WaitUntilRoutineFinished(base::OnceClosure callback) {
    base::SequencedTaskRunner::GetCurrentDefault()->PostDelayedTask(
        FROM_HERE, std::move(callback),
        // Privacy screen routine should be finished within 1 second. Set 2
        // seconds as a safe timeout.
        base::Milliseconds(2000));
  }

  mojom::RoutineUpdatePtr GetUpdate() {
    mojom::RoutineUpdate update{0, mojo::ScopedHandle(),
                                mojom::RoutineUpdateUnionPtr()};
    routine_->PopulateStatusUpdate(&update, true);
    return mojom::RoutineUpdate::New(update.progress_percent,
                                     std::move(update.output),
                                     std::move(update.routine_update_union));
  }

  DiagnosticRoutine* routine() { return routine_.get(); }

 private:
  void SetDelegateDestiny(bool initialization_success,
                          bool privacy_screen_supported,
                          bool privacy_screen_enabled) {
    std::optional<std::string> error_message =
        initialization_success
            ? std::nullopt
            : std::make_optional(kDisplayUtilInitializationError);
    EXPECT_CALL(*context_.mock_executor(), GetPrivacyScreenInfo(_))
        .WillRepeatedly(WithArg<0>(
            Invoke([=](MockExecutor::GetPrivacyScreenInfoCallback callback) {
              std::move(callback).Run(privacy_screen_supported,
                                      privacy_screen_enabled, error_message);
            })));
  }

  MockContext context_;
  std::unique_ptr<PrivacyScreenRoutine> routine_;
  base::test::TaskEnvironment task_environment_;
};

// Test that routine error occurs if display_util fails to be initialized.
TEST_F(PrivacyScreenRoutineTest, DisplayUtilInitializationFailedError) {
  CreateRoutine(/*target_state=*/true);
  SetRoutineDestiny(/*display_util_init_success=*/false,
                    /*privacy_screen_supported=*/true,
                    /*privacy_screen_enabled_before=*/false,
                    /*privacy_screen_request_processed=*/true,
                    /*privacy_screen_enabled_after=*/true);
  routine()->Start();
  WaitUntilRoutineFinished(base::BindLambdaForTesting([this]() {
    auto update = GetUpdate();
    VerifyNonInteractiveUpdate(update->routine_update_union,
                               mojom::DiagnosticRoutineStatusEnum::kError,
                               kDisplayUtilInitializationError);
  }));
}

// Test that routine fails if browser rejects request.
TEST_F(PrivacyScreenRoutineTest, RequestRejected) {
  CreateRoutine(/*target_state=*/true);
  SetRoutineDestiny(/*display_util_init_success=*/true,
                    /*privacy_screen_supported=*/true,
                    /*privacy_screen_enabled_before=*/false,
                    /*privacy_screen_request_processed=*/false,
                    /*privacy_screen_enabled_after=*/false);
  routine()->Start();
  WaitUntilRoutineFinished(base::BindLambdaForTesting([this]() {
    auto update = GetUpdate();
    VerifyNonInteractiveUpdate(update->routine_update_union,
                               mojom::DiagnosticRoutineStatusEnum::kFailed,
                               kPrivacyScreenRoutineRequestRejectedMessage);
  }));
}

// Test that routine fails if browser does not response.
TEST_F(PrivacyScreenRoutineTest, BrowserResponseTimeoutExceeded) {
  CreateRoutine(/*target_state=*/true);
  SetRoutineDestiny(/*display_util_init_success=*/true,
                    /*privacy_screen_supported=*/true,
                    /*privacy_screen_enabled_before=*/false,
                    /*privacy_screen_request_processed=*/std::nullopt,
                    /*privacy_screen_enabled_after=*/true);
  routine()->Start();
  WaitUntilRoutineFinished(base::BindLambdaForTesting([this]() {
    auto update = GetUpdate();
    VerifyNonInteractiveUpdate(
        update->routine_update_union,
        mojom::DiagnosticRoutineStatusEnum::kFailed,
        kPrivacyScreenRoutineBrowserResponseTimeoutExceededMessage);
  }));
}

// Test that routine fails if privacy screen is not turned on.
TEST_F(PrivacyScreenRoutineTest, TurnOnFailed) {
  CreateRoutine(/*target_state=*/true);
  SetRoutineDestiny(/*display_util_init_success=*/true,
                    /*privacy_screen_supported=*/true,
                    /*privacy_screen_enabled_before=*/false,
                    /*privacy_screen_request_processed=*/true,
                    /*privacy_screen_enabled_after=*/false);
  routine()->Start();
  WaitUntilRoutineFinished(base::BindLambdaForTesting([this]() {
    auto update = GetUpdate();
    VerifyNonInteractiveUpdate(
        update->routine_update_union,
        mojom::DiagnosticRoutineStatusEnum::kFailed,
        kPrivacyScreenRoutineFailedToTurnPrivacyScreenOnMessage);
  }));
}

// Test that routine fails if privacy screen is not turned off.
TEST_F(PrivacyScreenRoutineTest, TurnOffFailed) {
  CreateRoutine(/*target_state=*/false);
  SetRoutineDestiny(/*display_util_init_success=*/true,
                    /*privacy_screen_supported=*/true,
                    /*privacy_screen_enabled_before=*/true,
                    /*privacy_screen_request_processed=*/true,
                    /*privacy_screen_enabled_after=*/false);
  routine()->Start();
  WaitUntilRoutineFinished(base::BindLambdaForTesting([this]() {
    auto update = GetUpdate();
    VerifyNonInteractiveUpdate(
        update->routine_update_union,
        mojom::DiagnosticRoutineStatusEnum::kFailed,
        kPrivacyScreenRoutineFailedToTurnPrivacyScreenOffMessage);
  }));
}

// Test that we can turn privacy screen on.
TEST_F(PrivacyScreenRoutineTest, TurnOnSuccess) {
  CreateRoutine(/*target_state=*/true);
  SetRoutineDestiny(/*display_util_init_success=*/true,
                    /*privacy_screen_supported=*/true,
                    /*privacy_screen_enabled_before=*/false,
                    /*privacy_screen_request_processed=*/true,
                    /*privacy_screen_enabled_after=*/true);
  routine()->Start();
  WaitUntilRoutineFinished(base::BindLambdaForTesting([this]() {
    auto update = GetUpdate();
    VerifyNonInteractiveUpdate(update->routine_update_union,
                               mojom::DiagnosticRoutineStatusEnum::kPassed,
                               kPrivacyScreenRoutineSucceededMessage);
  }));
}

// Test that we can turn privacy screen off.
TEST_F(PrivacyScreenRoutineTest, TurnOffSuccess) {
  CreateRoutine(/*target_state=*/false);
  SetRoutineDestiny(/*display_util_init_success=*/true,
                    /*privacy_screen_supported=*/true,
                    /*privacy_screen_enabled_before=*/true,
                    /*privacy_screen_request_processed=*/true,
                    /*privacy_screen_enabled_after=*/false);
  routine()->Start();
  WaitUntilRoutineFinished(base::BindLambdaForTesting([this]() {
    auto update = GetUpdate();
    VerifyNonInteractiveUpdate(update->routine_update_union,
                               mojom::DiagnosticRoutineStatusEnum::kPassed,
                               kPrivacyScreenRoutineSucceededMessage);
  }));
}

}  // namespace
}  // namespace diagnostics
