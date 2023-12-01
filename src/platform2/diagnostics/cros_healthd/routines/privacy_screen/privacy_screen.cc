// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/routines/privacy_screen/privacy_screen.h"

#include <utility>

#include <base/task/sequenced_task_runner.h>
#include <base/time/time.h>

#include "diagnostics/mojom/external/cros_healthd_internal.mojom.h"

namespace diagnostics {

PrivacyScreenRoutine::PrivacyScreenRoutine(Context* context, bool target_state)
    : context_(context), target_state_(target_state) {}

PrivacyScreenRoutine::~PrivacyScreenRoutine() = default;

void PrivacyScreenRoutine::Start() {
  DCHECK_EQ(GetStatus(), mojom::DiagnosticRoutineStatusEnum::kReady);
  UpdateStatus(mojom::DiagnosticRoutineStatusEnum::kRunning, "");

  // Send a request to browser to set privacy screen state.
  context_->mojo_service()->GetChromiumDataCollector()->SetPrivacyScreenState(
      target_state_, base::BindOnce(&PrivacyScreenRoutine::OnReceiveResponse,
                                    base::Unretained(this)));

  base::SequencedTaskRunner::GetCurrentDefault()->PostDelayedTask(
      FROM_HERE,
      base::BindOnce(&PrivacyScreenRoutine::GatherState,
                     base::Unretained(this)),
      // This delay is working as a timeout. The timeout is concerning two
      // checks, failing either of which leads to the failure of routine.
      //
      // - Browser must response before timeout exceeded.
      // - Privacy screen state must have been refreshed before timeout
      //   exceeded.
      base::Milliseconds(1000));
}

void PrivacyScreenRoutine::Resume() {
  // This routine cannot be resumed.
}

void PrivacyScreenRoutine::Cancel() {
  // This routine cannot be cancelled.
}

void PrivacyScreenRoutine::PopulateStatusUpdate(mojom::RoutineUpdate* response,
                                                bool include_output) {
  auto status = GetStatus();

  auto update = mojom::NonInteractiveRoutineUpdate::New();
  update->status = status;
  update->status_message = GetStatusMessage();
  response->routine_update_union =
      mojom::RoutineUpdateUnion::NewNoninteractiveUpdate(std::move(update));
  if (status == mojom::DiagnosticRoutineStatusEnum::kReady ||
      status == mojom::DiagnosticRoutineStatusEnum::kRunning) {
    response->progress_percent = 0;
  } else {
    response->progress_percent = 100;
  }
}

void PrivacyScreenRoutine::OnReceiveResponse(bool success) {
  request_processed_ = success;
}

void PrivacyScreenRoutine::GatherState() {
  if (request_processed_ == std::nullopt) {
    UpdateStatus(mojom::DiagnosticRoutineStatusEnum::kFailed,
                 kPrivacyScreenRoutineBrowserResponseTimeoutExceededMessage);
    return;
  }

  if (!request_processed_.value()) {
    UpdateStatus(mojom::DiagnosticRoutineStatusEnum::kFailed,
                 kPrivacyScreenRoutineRequestRejectedMessage);
    return;
  }

  context_->executor()->GetPrivacyScreenInfo(base::BindOnce(
      &PrivacyScreenRoutine::ValidateState, weak_factory_.GetWeakPtr()));
}

void PrivacyScreenRoutine::ValidateState(
    bool privacy_screen_supported,
    bool current_state,
    const std::optional<std::string>& error) {
  if (error.has_value()) {
    UpdateStatus(mojom::DiagnosticRoutineStatusEnum::kError, error.value());
    return;
  }
  if (current_state != target_state_) {
    UpdateStatus(
        mojom::DiagnosticRoutineStatusEnum::kFailed,
        target_state_
            ? kPrivacyScreenRoutineFailedToTurnPrivacyScreenOnMessage
            : kPrivacyScreenRoutineFailedToTurnPrivacyScreenOffMessage);
    return;
  }

  UpdateStatus(mojom::DiagnosticRoutineStatusEnum::kPassed,
               kPrivacyScreenRoutineSucceededMessage);
}

}  // namespace diagnostics
