// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/routines/fingerprint_alive/fingerprint_alive.h"

#include <utility>

#include <base/functional/callback.h>
#include <base/logging.h>

#include "diagnostics/mojom/public/cros_healthd_diagnostics.mojom.h"

namespace diagnostics {

namespace {

namespace mojom = ::ash::cros_healthd::mojom;

}  // namespace

FingerprintAliveRoutine::FingerprintAliveRoutine(Context* context)
    : context_(context) {}

FingerprintAliveRoutine::~FingerprintAliveRoutine() = default;

void FingerprintAliveRoutine::Start() {
  UpdateStatus(mojom::DiagnosticRoutineStatusEnum::kRunning, "");
  context_->executor()->GetFingerprintInfo(base::BindOnce(
      &FingerprintAliveRoutine::ExamineInfo, base::Unretained(this)));
}

void FingerprintAliveRoutine::Resume() {}

void FingerprintAliveRoutine::Cancel() {}

void FingerprintAliveRoutine::PopulateStatusUpdate(
    mojom::RoutineUpdate* response, bool include_output) {
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

void FingerprintAliveRoutine::ExamineInfo(
    mojom::FingerprintInfoResultPtr result,
    const std::optional<std::string>& err) {
  if (err.has_value()) {
    UpdateStatus(mojom::DiagnosticRoutineStatusEnum::kFailed, err.value());
    return;
  }

  if (!result) {
    UpdateStatus(mojom::DiagnosticRoutineStatusEnum::kFailed,
                 "Failed to get fingerprint info.");
    return;
  }

  // The firmware copy should be RW in a normal state.
  if (!result->rw_fw) {
    UpdateStatus(mojom::DiagnosticRoutineStatusEnum::kFailed,
                 "Fingerprint does not use a RW firmware copy.");
    return;
  }

  UpdateStatus(mojom::DiagnosticRoutineStatusEnum::kPassed, "");
}

}  // namespace diagnostics
