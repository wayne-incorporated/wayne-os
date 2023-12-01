// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_ROUTINES_FINGERPRINT_ALIVE_FINGERPRINT_ALIVE_H_
#define DIAGNOSTICS_CROS_HEALTHD_ROUTINES_FINGERPRINT_ALIVE_FINGERPRINT_ALIVE_H_

#include <string>

#include "diagnostics/cros_healthd/mojom/executor.mojom.h"
#include "diagnostics/cros_healthd/routines/diag_routine_with_status.h"
#include "diagnostics/cros_healthd/system/context.h"

namespace diagnostics {

class FingerprintAliveRoutine final : public DiagnosticRoutineWithStatus {
 public:
  explicit FingerprintAliveRoutine(Context* context);
  FingerprintAliveRoutine(const FingerprintAliveRoutine&) = delete;
  FingerprintAliveRoutine& operator=(const FingerprintAliveRoutine&) = delete;

  // DiagnosticRoutine overrides:
  ~FingerprintAliveRoutine() override;
  void Start() override;
  void Resume() override;
  void Cancel() override;
  void PopulateStatusUpdate(ash::cros_healthd::mojom::RoutineUpdate* response,
                            bool include_output) override;

 private:
  void ExamineInfo(ash::cros_healthd::mojom::FingerprintInfoResultPtr result,
                   const std::optional<std::string>& err);

  // Context object used to communicate with the executor.
  Context* context_;
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_ROUTINES_FINGERPRINT_ALIVE_FINGERPRINT_ALIVE_H_
