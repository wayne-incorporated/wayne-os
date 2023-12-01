// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/routines/arc_dns_resolution/arc_dns_resolution.h"

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
    network_diagnostics_ipc::ArcDnsResolutionProblem problem) {
  switch (problem) {
    case network_diagnostics_ipc::ArcDnsResolutionProblem::
        kFailedToGetArcServiceManager:
      return kArcDnsResolutionRoutineFailedToGetArcServiceManagerMessage;
    case network_diagnostics_ipc::ArcDnsResolutionProblem::
        kFailedToGetNetInstanceForDnsResolutionTest:
      return kArcDnsResolutionRoutineFailedToGetNetInstanceMessage;
    case network_diagnostics_ipc::ArcDnsResolutionProblem::kHighLatency:
      return kArcDnsResolutionRoutineHighLatencyMessage;
    case network_diagnostics_ipc::ArcDnsResolutionProblem::kVeryHighLatency:
      return kArcDnsResolutionRoutineVeryHighLatencyMessage;
    case network_diagnostics_ipc::ArcDnsResolutionProblem::kFailedDnsQueries:
      return kArcDnsResolutionRoutineFailedDnsQueriesMessage;
  }
}

// Parses the results of the ARC DNS resolution routine.
SimpleRoutine::RoutineResult ParseArcDnsResolutionResult(
    network_diagnostics_ipc::RoutineResultPtr result) {
  switch (result->verdict) {
    case network_diagnostics_ipc::RoutineVerdict::kNoProblem:
      return {
          .status = mojom::DiagnosticRoutineStatusEnum::kPassed,
          .status_message = kArcDnsResolutionRoutineNoProblemMessage,
      };
    case network_diagnostics_ipc::RoutineVerdict::kNotRun:
      return {
          .status = mojom::DiagnosticRoutineStatusEnum::kNotRun,
          .status_message = kArcDnsResolutionRoutineNotRunMessage,
      };
    case network_diagnostics_ipc::RoutineVerdict::kProblem:
      auto problems = result->problems->get_arc_dns_resolution_problems();
      DCHECK(!problems.empty());
      return {
          .status = mojom::DiagnosticRoutineStatusEnum::kFailed,
          .status_message = GetProblemMessage(problems[0]),
      };
  }
}

void RunArcDnsResolutionRoutine(
    NetworkDiagnosticsAdapter* network_diagnostics_adapter,
    SimpleRoutine::RoutineResultCallback callback) {
  DCHECK(network_diagnostics_adapter);
  network_diagnostics_adapter->RunArcDnsResolutionRoutine(
      base::BindOnce(&ParseArcDnsResolutionResult).Then(std::move(callback)));
}

}  // namespace

std::unique_ptr<DiagnosticRoutine> CreateArcDnsResolutionRoutine(
    NetworkDiagnosticsAdapter* network_diagnostics_adapter) {
  return std::make_unique<SimpleRoutine>(
      base::BindOnce(&RunArcDnsResolutionRoutine, network_diagnostics_adapter));
}

}  // namespace diagnostics
