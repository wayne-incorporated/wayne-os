// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_ROUTINES_PRIVACY_SCREEN_PRIVACY_SCREEN_H_
#define DIAGNOSTICS_CROS_HEALTHD_ROUTINES_PRIVACY_SCREEN_PRIVACY_SCREEN_H_

#include <cstdint>
#include <memory>
#include <string>

#include "diagnostics/cros_healthd/routines/diag_routine_with_status.h"
#include "diagnostics/cros_healthd/system/context.h"

namespace diagnostics {

namespace mojom = ::ash::cros_healthd::mojom;

const char kPrivacyScreenRoutineSucceededMessage[] =
    "Privacy screen routine passes.";
const char kPrivacyScreenRoutineFailedToTurnPrivacyScreenOnMessage[] =
    "Expected privacy screen state ON, found OFF.";
const char kPrivacyScreenRoutineFailedToTurnPrivacyScreenOffMessage[] =
    "Expected privacy screen state OFF, found ON.";
const char kPrivacyScreenRoutineRequestRejectedMessage[] =
    "Browser rejected to set privacy screen state.";
const char kPrivacyScreenRoutineBrowserResponseTimeoutExceededMessage[] =
    "Browser response timeout exceeded";

class PrivacyScreenRoutine final : public DiagnosticRoutineWithStatus {
 public:
  PrivacyScreenRoutine(Context* context, bool target_state);
  PrivacyScreenRoutine(const PrivacyScreenRoutine&) = delete;
  PrivacyScreenRoutine& operator=(const PrivacyScreenRoutine&) = delete;

  // DiagnosticRoutine overrides:
  ~PrivacyScreenRoutine() override;
  void Start() override;
  void Resume() override;
  void Cancel() override;
  void PopulateStatusUpdate(mojom::RoutineUpdate* response,
                            bool include_output) override;

 private:
  // Callback function for setting privacy screen state.
  void OnReceiveResponse(bool success);

  // Gathers the current privacy state.
  void GatherState();

  // Validates if the current privacy is set to expected and marks routine
  // status as passing or failed.
  void ValidateState(bool privacy_screen_supported,
                     bool current_state,
                     const std::optional<std::string>& error);

  // Context object used to communicate with the browser and to call executor
  // functions.
  Context* context_;

  // Expected privacy screen target state.
  bool target_state_;

  // Whether request is processed by browser. |std::nullopt| indicates browser
  // has not yet responded.
  std::optional<bool> request_processed_ = std::nullopt;

  // Must be the last member of the class.
  base::WeakPtrFactory<PrivacyScreenRoutine> weak_factory_{this};
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_ROUTINES_PRIVACY_SCREEN_PRIVACY_SCREEN_H_
