// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/routines/diag_routine_with_status.h"

#include <string>
#include <utility>

namespace diagnostics {
namespace {
namespace mojom = ::ash::cros_healthd::mojom;
}  // namespace

mojom::DiagnosticRoutineStatusEnum DiagnosticRoutineWithStatus::GetStatus() {
  return status_;
}

void DiagnosticRoutineWithStatus::RegisterStatusChangedCallback(
    StatusChangedCallback callback) {
  status_changed_callbacks_.push_back(std::move(callback));
}

const std::string& DiagnosticRoutineWithStatus::GetStatusMessage() const {
  return status_message_;
}

void DiagnosticRoutineWithStatus::UpdateStatus(
    mojom::DiagnosticRoutineStatusEnum status, std::string message) {
  bool is_status_changed = status_ != status;

  status_ = status;
  status_message_ = std::move(message);
  if (is_status_changed) {
    NotifyStatusChanged();
  }
}

void DiagnosticRoutineWithStatus::NotifyStatusChanged() {
  auto status = status_;
  for (const auto& callback : status_changed_callbacks_) {
    callback.Run(status);
  }
}

}  // namespace diagnostics
