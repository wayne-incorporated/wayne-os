// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/routines/led_lit_up/led_lit_up.h"

#include <utility>

#include <base/cancelable_callback.h>
#include <base/functional/callback.h>
#include <base/logging.h>

#include "diagnostics/mojom/public/cros_healthd_diagnostics.mojom.h"

namespace diagnostics {

namespace {

namespace mojom = ::ash::cros_healthd::mojom;

void LogResetColorError(const std::optional<std::string>& err) {
  if (err) {
    LOG(WARNING) << "Reset LED color failed: " << err.value();
  }
}

}  // namespace

LedLitUpRoutine::LedLitUpRoutine(
    Context* context,
    mojom::LedName name,
    mojom::LedColor color,
    mojo::PendingRemote<mojom::LedLitUpRoutineReplier> replier)
    : context_(context),
      name_(name),
      color_(color),
      step_(TestStep::kInitialize) {
  // The disconnection of |replier_| is handled in |RunNextStep| to avoid
  // resetting the LED before the specified color is set.
  replier_.Bind(std::move(replier));
}

LedLitUpRoutine::~LedLitUpRoutine() = default;

void LedLitUpRoutine::Start() {
  RunNextStep();
}

void LedLitUpRoutine::Resume() {}

void LedLitUpRoutine::Cancel() {
  if (GetStatus() == mojom::DiagnosticRoutineStatusEnum::kWaiting) {
    context_->executor()->ResetLedColor(name_,
                                        base::BindOnce(&LogResetColorError));
    UpdateStatus(mojom::DiagnosticRoutineStatusEnum::kCancelled, "Canceled.");
  }
}

void LedLitUpRoutine::PopulateStatusUpdate(mojom::RoutineUpdate* response,
                                           bool include_output) {
  if (step_ == TestStep::kGetColorMatched) {
    // In this step, the client should check the color of the LED.
    auto interactive_update = mojom::InteractiveRoutineUpdate::New();
    interactive_update->user_message =
        mojom::DiagnosticRoutineUserMessageEnum::kCheckLedColor;
    response->routine_update_union =
        mojom::RoutineUpdateUnion::NewInteractiveUpdate(
            std::move(interactive_update));
  } else {
    auto noninteractive_update = mojom::NonInteractiveRoutineUpdate::New();
    noninteractive_update->status = GetStatus();
    noninteractive_update->status_message = GetStatusMessage();

    response->routine_update_union =
        mojom::RoutineUpdateUnion::NewNoninteractiveUpdate(
            std::move(noninteractive_update));
  }

  response->progress_percent = step_ * 100 / TestStep::kComplete;
}

void LedLitUpRoutine::ReplierDisconnectHandler() {
  context_->executor()->ResetLedColor(name_,
                                      base::BindOnce(&LogResetColorError));
  UpdateStatus(mojom::DiagnosticRoutineStatusEnum::kFailed,
               "Replier disconnected.");
}

void LedLitUpRoutine::SetLedColorCallback(
    const std::optional<std::string>& err) {
  if (err) {
    context_->executor()->ResetLedColor(name_,
                                        base::BindOnce(&LogResetColorError));
    UpdateStatus(mojom::DiagnosticRoutineStatusEnum::kFailed, err.value());
    return;
  }
  RunNextStep();
}

void LedLitUpRoutine::GetColorMatchedCallback(bool matched) {
  // No need to handle the disconnection after receiving the response.
  replier_.set_disconnect_handler(base::DoNothing());
  color_matched_response_ = matched;
  RunNextStep();
}

void LedLitUpRoutine::ResetLedColorCallback(
    const std::optional<std::string>& err) {
  if (err) {
    UpdateStatus(mojom::DiagnosticRoutineStatusEnum::kFailed, err.value());
    return;
  }
  RunNextStep();
}

void LedLitUpRoutine::RunNextStep() {
  step_ = static_cast<TestStep>(static_cast<int>(step_) + 1);

  switch (step_) {
    case TestStep::kInitialize:
      UpdateStatus(mojom::DiagnosticRoutineStatusEnum::kError,
                   "Unexpected LED lit up diagnostic flow.");
      break;
    case TestStep::kSetColor:
      UpdateStatus(mojom::DiagnosticRoutineStatusEnum::kRunning, "");
      context_->executor()->SetLedColor(
          name_, color_,
          base::BindOnce(&LedLitUpRoutine::SetLedColorCallback,
                         weak_ptr_factory_.GetWeakPtr()));
      break;
    case TestStep::kGetColorMatched:
      UpdateStatus(mojom::DiagnosticRoutineStatusEnum::kWaiting, "");
      if (!replier_.is_connected()) {
        // Handle the disconnection before calling the remote function.
        ReplierDisconnectHandler();
      } else {
        // Handle the disconnection during calling the remote function.
        replier_.set_disconnect_handler(
            base::BindOnce(&LedLitUpRoutine::ReplierDisconnectHandler,
                           weak_ptr_factory_.GetWeakPtr()));
        replier_->GetColorMatched(
            base::BindOnce(&LedLitUpRoutine::GetColorMatchedCallback,
                           weak_ptr_factory_.GetWeakPtr()));
      }
      break;
    case TestStep::kResetColor:
      UpdateStatus(mojom::DiagnosticRoutineStatusEnum::kRunning, "");
      context_->executor()->ResetLedColor(
          name_, base::BindOnce(&LedLitUpRoutine::ResetLedColorCallback,
                                weak_ptr_factory_.GetWeakPtr()));
      break;
    case TestStep::kComplete:
      if (color_matched_response_) {
        UpdateStatus(mojom::DiagnosticRoutineStatusEnum::kPassed,
                     "Routine passed.");
      } else {
        UpdateStatus(mojom::DiagnosticRoutineStatusEnum::kFailed,
                     "Not lit up in the specified color.");
      }
      break;
  }
}

}  // namespace diagnostics
