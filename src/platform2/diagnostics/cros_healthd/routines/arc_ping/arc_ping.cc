// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/routines/arc_ping/arc_ping.h"

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

std::string GetProblemMessage(network_diagnostics_ipc::ArcPingProblem problem) {
  switch (problem) {
    case network_diagnostics_ipc::ArcPingProblem::kFailedToGetArcServiceManager:
      return kArcPingRoutineFailedToGetArcServiceManagerMessage;
    case network_diagnostics_ipc::ArcPingProblem::
        kFailedToGetNetInstanceForPingTest:
      return kArcPingRoutineFailedToGetNetInstanceForPingTestMessage;
    case network_diagnostics_ipc::ArcPingProblem::
        kGetManagedPropertiesTimeoutFailure:
      return kArcPingRoutineGetManagedPropertiesTimeoutFailureMessage;
    case network_diagnostics_ipc::ArcPingProblem::kUnreachableGateway:
      return kArcPingRoutineUnreachableGatewayMessage;
    case network_diagnostics_ipc::ArcPingProblem::kFailedToPingDefaultNetwork:
      return kArcPingRoutineFailedToPingDefaultNetworkMessage;
    case network_diagnostics_ipc::ArcPingProblem::
        kDefaultNetworkAboveLatencyThreshold:
      return kArcPingRoutineDefaultNetworkAboveLatencyThresholdMessage;
    case network_diagnostics_ipc::ArcPingProblem::
        kUnsuccessfulNonDefaultNetworksPings:
      return kArcPingRoutineUnsuccessfulNonDefaultNetworksPingsMessage;
    case network_diagnostics_ipc::ArcPingProblem::
        kNonDefaultNetworksAboveLatencyThreshold:
      return kArcPingRoutineNonDefaultNetworksAboveLatencyThresholdMessage;
  }
}

// Parses the results of ARC ping routine.
SimpleRoutine::RoutineResult ParseArcPingResult(
    network_diagnostics_ipc::RoutineResultPtr result) {
  switch (result->verdict) {
    case network_diagnostics_ipc::RoutineVerdict::kNoProblem:
      return {
          .status = mojom::DiagnosticRoutineStatusEnum::kPassed,
          .status_message = kArcPingRoutineNoProblemMessage,
      };
    case network_diagnostics_ipc::RoutineVerdict::kNotRun:
      return {
          .status = mojom::DiagnosticRoutineStatusEnum::kNotRun,
          .status_message = kArcPingRoutineNotRunMessage,
      };
    case network_diagnostics_ipc::RoutineVerdict::kProblem:
      auto problems = result->problems->get_arc_ping_problems();
      DCHECK(!problems.empty());
      return {
          .status = mojom::DiagnosticRoutineStatusEnum::kFailed,
          .status_message = GetProblemMessage(problems[0]),
      };
  }
}

void RunArcPingRoutine(NetworkDiagnosticsAdapter* network_diagnostics_adapter,
                       SimpleRoutine::RoutineResultCallback callback) {
  DCHECK(network_diagnostics_adapter);
  network_diagnostics_adapter->RunArcPingRoutine(
      base::BindOnce(&ParseArcPingResult).Then(std::move(callback)));
}

}  // namespace

std::unique_ptr<DiagnosticRoutine> CreateArcPingRoutine(
    NetworkDiagnosticsAdapter* network_diagnostics_adapter) {
  return std::make_unique<SimpleRoutine>(
      base::BindOnce(&RunArcPingRoutine, network_diagnostics_adapter));
}

}  // namespace diagnostics
