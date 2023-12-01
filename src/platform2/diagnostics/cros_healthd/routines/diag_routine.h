// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_ROUTINES_DIAG_ROUTINE_H_
#define DIAGNOSTICS_CROS_HEALTHD_ROUTINES_DIAG_ROUTINE_H_

#include <base/functional/callback_forward.h>

#include "diagnostics/mojom/public/cros_healthd_diagnostics.mojom.h"

namespace diagnostics {

// An interface for creating a diagnostic routine, which can be run and
// controlled by the platform.
class DiagnosticRoutine {
 public:
  using StatusChangedCallback = base::RepeatingCallback<void(
      ash::cros_healthd::mojom::DiagnosticRoutineStatusEnum)>;
  // Note that the instance of this object may be destroyed before the routine
  // is finished - the implementation must ensure that the destructor
  // terminates all background processes in that case.
  virtual ~DiagnosticRoutine() = default;

  // Starts the diagnostic routine. This function should only be called a
  // single time per instance of DiagnosticRoutine.
  virtual void Start() = 0;
  // This function should only be called to resume interactive routines that are
  // currently in the ROUTINE_STATUS_WAITING state.
  virtual void Resume() = 0;
  // Cancels an active diagnostics routine. Information (status, output, user
  // message) of a cancelled routine can still be accessed, but the routine
  // cannot be restarted.
  virtual void Cancel() = 0;
  // Populates |response| with the current status of the diagnostic routine.
  virtual void PopulateStatusUpdate(
      ash::cros_healthd::mojom::RoutineUpdate* response,
      bool include_output) = 0;
  virtual ash::cros_healthd::mojom::DiagnosticRoutineStatusEnum GetStatus() = 0;
  // Registers a callback that will be invoked each time the status changes.
  // On each status change, the new status will be passed as the argument to
  // |callback|.
  // This function should not be used to observe changes of other properties
  // (e.g., status_message) because the callback could be invoked after the
  // status changes but before other properties are updated.
  virtual void RegisterStatusChangedCallback(
      StatusChangedCallback callback) = 0;
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_ROUTINES_DIAG_ROUTINE_H_
