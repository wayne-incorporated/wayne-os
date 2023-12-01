// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/routines/network/signal_strength.h"

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/functional/bind.h>

#include "diagnostics/cros_healthd/routines/simple_routine.h"
#include "diagnostics/mojom/external/network_diagnostics.mojom.h"
#include "diagnostics/mojom/public/cros_healthd_diagnostics.mojom.h"

namespace diagnostics {

namespace {

namespace mojom = ::ash::cros_healthd::mojom;
namespace network_diagnostics_ipc = ::chromeos::network_diagnostics::mojom;

std::string GetProblemMessage(
    network_diagnostics_ipc::SignalStrengthProblem problem) {
  switch (problem) {
    case network_diagnostics_ipc::SignalStrengthProblem::kWeakSignal:
      return kSignalStrengthRoutineWeakSignalProblemMessage;
  }
}

// Parses the results of the signal strength routine.
SimpleRoutine::RoutineResult ParseSignalStrengthResult(
    network_diagnostics_ipc::RoutineResultPtr result) {
  switch (result->verdict) {
    case network_diagnostics_ipc::RoutineVerdict::kNoProblem:
      return {
          .status = mojom::DiagnosticRoutineStatusEnum::kPassed,
          .status_message = kSignalStrengthRoutineNoProblemMessage,
      };
    case network_diagnostics_ipc::RoutineVerdict::kNotRun:
      return {
          .status = mojom::DiagnosticRoutineStatusEnum::kNotRun,
          .status_message = kSignalStrengthRoutineNotRunMessage,
      };
    case network_diagnostics_ipc::RoutineVerdict::kProblem:
      auto problems = result->problems->get_signal_strength_problems();
      DCHECK(!problems.empty());
      return {
          .status = mojom::DiagnosticRoutineStatusEnum::kFailed,
          .status_message = GetProblemMessage(problems[0]),
      };
  }
}

void RunSignalStrengthRoutine(
    NetworkDiagnosticsAdapter* network_diagnostics_adapter,
    SimpleRoutine::RoutineResultCallback callback) {
  DCHECK(network_diagnostics_adapter);
  network_diagnostics_adapter->RunSignalStrengthRoutine(
      base::BindOnce(&ParseSignalStrengthResult).Then(std::move(callback)));
}

}  // namespace

const char kSignalStrengthRoutineNoProblemMessage[] =
    "Signal strength routine passed with no problems.";
const char kSignalStrengthRoutineWeakSignalProblemMessage[] =
    "Weak signal detected.";
const char kSignalStrengthRoutineNotRunMessage[] =
    "Signal strength routine did not run.";

std::unique_ptr<DiagnosticRoutine> CreateSignalStrengthRoutine(
    NetworkDiagnosticsAdapter* network_diagnostics_adapter) {
  return std::make_unique<SimpleRoutine>(
      base::BindOnce(&RunSignalStrengthRoutine, network_diagnostics_adapter));
}

}  // namespace diagnostics
