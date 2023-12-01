// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/routines/power_button/power_button.h"

#include <string>
#include <utility>

#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/strings/stringprintf.h>

#include "diagnostics/mojom/external/cros_healthd_internal.mojom.h"
#include "diagnostics/mojom/public/cros_healthd_diagnostics.mojom.h"

namespace diagnostics {

namespace {

namespace mojom = ::ash::cros_healthd::mojom;

constexpr uint32_t kMinTimeoutSeconds = 1;
constexpr uint32_t kMaxTimeoutSeconds = 600;

}  // namespace

PowerButtonRoutine::PowerButtonRoutine(Context* context,
                                       uint32_t timeout_seconds)
    : timeout_seconds_(timeout_seconds), context_(context) {
  CHECK(context_);
}

PowerButtonRoutine::~PowerButtonRoutine() = default;

void PowerButtonRoutine::Start() {
  if (timeout_seconds_ < kMinTimeoutSeconds ||
      timeout_seconds_ > kMaxTimeoutSeconds) {
    UpdateStatus(mojom::DiagnosticRoutineStatusEnum::kError,
                 base::StringPrintf("Timeout is not in range [%u, %u]",
                                    kMinTimeoutSeconds, kMaxTimeoutSeconds));
    return;
  }

  UpdateStatus(mojom::DiagnosticRoutineStatusEnum::kRunning, "");

  context_->executor()->MonitorPowerButton(
      receiver_.BindNewPipeAndPassRemote(),
      process_control_.BindNewPipeAndPassReceiver());
  receiver_.set_disconnect_with_reason_handler(
      base::BindOnce(&PowerButtonRoutine::OnEventObserverDisconnect,
                     weak_ptr_factory_.GetWeakPtr()));

  timeout_callback_.Reset(base::BindOnce(&PowerButtonRoutine::OnTimeout,
                                         weak_ptr_factory_.GetWeakPtr()));
  base::SingleThreadTaskRunner::GetCurrentDefault()->PostDelayedTask(
      FROM_HERE, timeout_callback_.callback(), base::Seconds(timeout_seconds_));
}

void PowerButtonRoutine::Resume() {}

void PowerButtonRoutine::Cancel() {}

void PowerButtonRoutine::PopulateStatusUpdate(mojom::RoutineUpdate* response,
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

void PowerButtonRoutine::OnEvent(
    mojom::PowerButtonObserver::ButtonState button_state) {
  UpdateStatus(mojom::DiagnosticRoutineStatusEnum::kPassed, "Routine passed.");
  CleanUp();
}

void PowerButtonRoutine::OnTimeout() {
  UpdateStatus(mojom::DiagnosticRoutineStatusEnum::kFailed,
               "Routine failed. No power button event observed.");
  CleanUp();
}

void PowerButtonRoutine::OnEventObserverDisconnect(
    uint32_t custom_reason, const std::string& description) {
  LOG(ERROR) << "Power button monitor disconnect: " << description;
  UpdateStatus(mojom::DiagnosticRoutineStatusEnum::kError,
               "Routine error. Unable to listen for power button events.");
  CleanUp();
}

void PowerButtonRoutine::CleanUp() {
  receiver_.reset();
  process_control_.reset();
  timeout_callback_.Cancel();
}

}  // namespace diagnostics
