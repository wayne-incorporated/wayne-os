// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_ROUTINES_DIAG_ROUTINE_WITH_STATUS_H_
#define DIAGNOSTICS_CROS_HEALTHD_ROUTINES_DIAG_ROUTINE_WITH_STATUS_H_

#include <string>
#include <utility>
#include <vector>

#include "diagnostics/cros_healthd/routines/diag_routine.h"
#include "diagnostics/mojom/public/cros_healthd_diagnostics.mojom.h"

namespace diagnostics {

// Provides a unified implementation of status and status_message management
// for diagnostic routines. It doesn't store |progress_percent| because some
// routines calculate progresses on demand instead of storing them as member
// variables.
class DiagnosticRoutineWithStatus : public DiagnosticRoutine {
 public:
  // DiagnosticRoutine overrides:
  ash::cros_healthd::mojom::DiagnosticRoutineStatusEnum GetStatus() override;
  void RegisterStatusChangedCallback(StatusChangedCallback callback) override;

 protected:
  const std::string& GetStatusMessage() const;

  // Set both |status_| and |status_message_| in one function call to ensure
  // that they are updated together.
  void UpdateStatus(
      ash::cros_healthd::mojom::DiagnosticRoutineStatusEnum status,
      std::string message);

 private:
  // Notifies each of |status_changed_callbacks_| when the status changes.
  void NotifyStatusChanged();

  // Status of the routine, reported by GetStatus() or noninteractive routine
  // updates.
  ash::cros_healthd::mojom::DiagnosticRoutineStatusEnum status_ =
      ash::cros_healthd::mojom::DiagnosticRoutineStatusEnum::kReady;
  // Details of the routine's status, reported in non-interactive status
  // updates.
  std::string status_message_;
  // Callbacks to invoke when the status changes.
  std::vector<StatusChangedCallback> status_changed_callbacks_;
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_ROUTINES_DIAG_ROUTINE_WITH_STATUS_H_
