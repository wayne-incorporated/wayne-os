// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_ROUTINES_SIMPLE_ROUTINE_H_
#define DIAGNOSTICS_CROS_HEALTHD_ROUTINES_SIMPLE_ROUTINE_H_

#include <string>

#include <base/functional/callback.h>
#include <base/values.h>

#include "diagnostics/cros_healthd/routines/diag_routine_with_status.h"
#include "diagnostics/mojom/public/cros_healthd_diagnostics.mojom.h"

namespace diagnostics {

// Provides a convenient way to construct a simple routine. If your routine has
// any of the following features, this class should NOT be used:
// * User interaction - simple routines are all non-interactive.
// * Running subprocesses - use SubprocRoutine instead.
// * Long runtime - simple routines cannot be cancelled, so only short-lived
//                  routines should use this class.
//
// Adding a new simple routine could be done as follows:
//
// (Header file)
// std::unique_ptr<DiagnosticRoutine> CreateNewSimpleRoutine(Params params);
//
// (Implementation file)
// void DoRoutineWork(
//   Params params,
//   SimpleRoutine::RoutineResultCallback callback) {
//     // Routine-specific logic goes here.
//     // Invoke |callback| with the result of routine once the work is done.
// }
//
// std::unique_ptr<DiagnosticRoutine> CreateNewSimpleRoutine(Params params) {
//   return std::make_unique<SimpleRoutine>(
//       base::BindOnce(&DoRoutineWork, Params));
// }
class SimpleRoutine final : public DiagnosticRoutineWithStatus {
 public:
  struct RoutineResult {
    ash::cros_healthd::mojom::DiagnosticRoutineStatusEnum status;
    std::string status_message;
    base::Value::Dict output_dict;
  };
  using RoutineResultCallback = base::OnceCallback<void(RoutineResult)>;
  using Task = base::OnceCallback<void(RoutineResultCallback)>;

  explicit SimpleRoutine(Task task);
  SimpleRoutine(const SimpleRoutine&) = delete;
  SimpleRoutine& operator=(const SimpleRoutine&) = delete;

  // DiagnosticRoutine overrides:
  ~SimpleRoutine() override;
  void Start() override;
  void Resume() override;
  void Cancel() override;
  void PopulateStatusUpdate(ash::cros_healthd::mojom::RoutineUpdate* response,
                            bool include_output) override;

 private:
  void StoreRoutineResult(RoutineResult result);

  // Task encapsulating the logic of the routine to run.
  Task task_;

  base::Value::Dict output_dict_;

  // Must be the last class member.
  base::WeakPtrFactory<SimpleRoutine> weak_ptr_factory_{this};
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_ROUTINES_SIMPLE_ROUTINE_H_
