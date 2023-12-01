// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/routines/network/lan_connectivity.h"

#include <string>
#include <utility>

#include <base/check.h>
#include <base/functional/bind.h>
#include <base/logging.h>

#include "diagnostics/cros_healthd/network_diagnostics/network_diagnostics_adapter.h"
#include "diagnostics/cros_healthd/routines/simple_routine.h"
#include "diagnostics/mojom/external/network_diagnostics.mojom.h"
#include "diagnostics/mojom/public/cros_healthd_diagnostics.mojom.h"

namespace diagnostics {

namespace {

namespace mojom = ::ash::cros_healthd::mojom;
namespace network_diagnostics_ipc = ::chromeos::network_diagnostics::mojom;

std::string GetProblemMessage(
    network_diagnostics_ipc::LanConnectivityProblem problem) {
  switch (problem) {
    case network_diagnostics_ipc::LanConnectivityProblem::kNoLanConnectivity:
      return kLanConnectivityRoutineProblemMessage;
  }
}

// Parses the results of the LAN connectivity routine.
SimpleRoutine::RoutineResult ParseLanConnectivityResult(
    network_diagnostics_ipc::RoutineResultPtr result) {
  switch (result->verdict) {
    case network_diagnostics_ipc::RoutineVerdict::kNoProblem:
      return {
          .status = mojom::DiagnosticRoutineStatusEnum::kPassed,
          .status_message = kLanConnectivityRoutineNoProblemMessage,
      };
    case network_diagnostics_ipc::RoutineVerdict::kNotRun:
      return {
          .status = mojom::DiagnosticRoutineStatusEnum::kNotRun,
          .status_message = kLanConnectivityRoutineNotRunMessage,
      };
    case network_diagnostics_ipc::RoutineVerdict::kProblem:
      auto problems = result->problems->get_lan_connectivity_problems();
      DCHECK(!problems.empty());
      return {
          .status = mojom::DiagnosticRoutineStatusEnum::kFailed,
          .status_message = GetProblemMessage(problems[0]),
      };
  }
}

void RunLanConnectivityRoutine(
    NetworkDiagnosticsAdapter* network_diagnostics_adapter,
    SimpleRoutine::RoutineResultCallback callback) {
  DCHECK(network_diagnostics_adapter);
  network_diagnostics_adapter->RunLanConnectivityRoutine(
      base::BindOnce(&ParseLanConnectivityResult).Then(std::move(callback)));
}

}  // namespace

const char kLanConnectivityRoutineNoProblemMessage[] =
    "LAN Connectivity routine passed with no problems.";
const char kLanConnectivityRoutineProblemMessage[] =
    "No LAN Connectivity detected.";
const char kLanConnectivityRoutineNotRunMessage[] =
    "LAN Connectivity routine did not run.";

std::unique_ptr<DiagnosticRoutine> CreateLanConnectivityRoutine(
    NetworkDiagnosticsAdapter* network_diagnostics_adapter) {
  return std::make_unique<SimpleRoutine>(
      base::BindOnce(&RunLanConnectivityRoutine, network_diagnostics_adapter));
}

}  // namespace diagnostics
