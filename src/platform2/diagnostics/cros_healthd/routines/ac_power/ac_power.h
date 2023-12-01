// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_ROUTINES_AC_POWER_AC_POWER_H_
#define DIAGNOSTICS_CROS_HEALTHD_ROUTINES_AC_POWER_AC_POWER_H_

#include <cstdint>
#include <optional>
#include <string>

#include <base/files/file_path.h>

#include "diagnostics/cros_healthd/routines/diag_routine_with_status.h"
#include "diagnostics/mojom/public/cros_healthd_diagnostics.mojom.h"

namespace diagnostics {

// Status messages reported by the AC power routine.
extern const char kAcPowerRoutineSucceededMessage[];
extern const char kAcPowerRoutineFailedNotOnlineMessage[];
extern const char kAcPowerRoutineFailedNotOfflineMessage[];
extern const char kAcPowerRoutineFailedMismatchedPowerTypesMessage[];
extern const char kAcPowerRoutineNoValidPowerSupplyMessage[];
extern const char kAcPowerRoutineCancelledMessage[];

// Progress percent reported when the routine is in the waiting state.
extern const uint32_t kAcPowerRoutineWaitingProgressPercent;

// Checks the status of the power supply and optionally checks to see if the
// type of the power supply matches the power_type argument.
class AcPowerRoutine final : public DiagnosticRoutineWithStatus {
 public:
  // Override |root_dir| for testing only.
  AcPowerRoutine(ash::cros_healthd::mojom::AcPowerStatusEnum expected_status,
                 const std::optional<std::string>& expected_power_type,
                 const base::FilePath& root_dir = base::FilePath("/"));
  AcPowerRoutine(const AcPowerRoutine&) = delete;
  AcPowerRoutine& operator=(const AcPowerRoutine&) = delete;

  // DiagnosticRoutine overrides:
  ~AcPowerRoutine() override;
  void Start() override;
  void Resume() override;
  void Cancel() override;
  void PopulateStatusUpdate(ash::cros_healthd::mojom::RoutineUpdate* response,
                            bool include_output) override;

 private:
  // Calculates the progress percent based on the current status.
  void CalculateProgressPercent();
  // Checks the machine state against the input parameters.
  void RunAcPowerRoutine();

  // Expected status of the power supply.
  ash::cros_healthd::mojom::AcPowerStatusEnum expected_power_status_;
  // Expected type of the power supply.
  std::optional<std::string> expected_power_type_;
  // Root directory appended to relative paths used by the routine.
  base::FilePath root_dir_;
  // A measure of how far along the routine is, reported in all status updates.
  uint32_t progress_percent_ = 0;
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_ROUTINES_AC_POWER_AC_POWER_H_
