// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/routines/arc_http/arc_http.h"

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

std::string GetProblemMessage(network_diagnostics_ipc::ArcHttpProblem problem) {
  switch (problem) {
    case network_diagnostics_ipc::ArcHttpProblem::kFailedToGetArcServiceManager:
      return kArcHttpRoutineFailedToGetArcServiceManagerMessage;
    case network_diagnostics_ipc::ArcHttpProblem::
        kFailedToGetNetInstanceForHttpTest:
      return kArcHttpRoutineFailedToGetNetInstanceForHttpTestMessage;
    case network_diagnostics_ipc::ArcHttpProblem::kFailedHttpRequests:
      return kArcHttpRoutineFailedHttpsRequestsProblemMessage;
    case network_diagnostics_ipc::ArcHttpProblem::kHighLatency:
      return kArcHttpRoutineHighLatencyProblemMessage;
    case network_diagnostics_ipc::ArcHttpProblem::kVeryHighLatency:
      return kArcHttpRoutineVeryHighLatencyProblemMessage;
  }
}

// Parses the results of the ARC HTTP routine.
SimpleRoutine::RoutineResult ParseArcHttpResult(
    network_diagnostics_ipc::RoutineResultPtr result) {
  switch (result->verdict) {
    case network_diagnostics_ipc::RoutineVerdict::kNoProblem:
      return {
          .status = mojom::DiagnosticRoutineStatusEnum::kPassed,
          .status_message = kArcHttpRoutineNoProblemMessage,
      };
    case network_diagnostics_ipc::RoutineVerdict::kNotRun:
      return {
          .status = mojom::DiagnosticRoutineStatusEnum::kNotRun,
          .status_message = kArcHttpRoutineNotRunMessage,
      };
    case network_diagnostics_ipc::RoutineVerdict::kProblem:
      auto problems = result->problems->get_arc_http_problems();
      DCHECK(!problems.empty());
      return {
          .status = mojom::DiagnosticRoutineStatusEnum::kFailed,
          .status_message = GetProblemMessage(problems[0]),
      };
  }
}

void RunArcHttpRoutine(NetworkDiagnosticsAdapter* network_diagnostics_adapter,
                       SimpleRoutine::RoutineResultCallback callback) {
  DCHECK(network_diagnostics_adapter);
  network_diagnostics_adapter->RunArcHttpRoutine(
      base::BindOnce(&ParseArcHttpResult).Then(std::move(callback)));
}

}  // namespace

std::unique_ptr<DiagnosticRoutine> CreateArcHttpRoutine(
    NetworkDiagnosticsAdapter* network_diagnostics_adapter) {
  return std::make_unique<SimpleRoutine>(
      base::BindOnce(&RunArcHttpRoutine, network_diagnostics_adapter));
}

}  // namespace diagnostics
