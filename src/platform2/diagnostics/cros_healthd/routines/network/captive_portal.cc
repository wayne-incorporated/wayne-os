// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/routines/network/captive_portal.h"

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
    network_diagnostics_ipc::CaptivePortalProblem problem) {
  switch (problem) {
    case network_diagnostics_ipc::CaptivePortalProblem::kNoActiveNetworks:
      return kPortalRoutineNoActiveNetworksProblemMessage;
    case network_diagnostics_ipc::CaptivePortalProblem::kUnknownPortalState:
      return kPortalRoutineUnknownPortalStateProblemMessage;
    case network_diagnostics_ipc::CaptivePortalProblem::kPortalSuspected:
      return kPortalRoutinePortalSuspectedProblemMessage;
    case network_diagnostics_ipc::CaptivePortalProblem::kPortal:
      return kPortalRoutinePortalProblemMessage;
    case network_diagnostics_ipc::CaptivePortalProblem::kProxyAuthRequired:
      return kPortalRoutineProxyAuthRequiredProblemMessage;
    case network_diagnostics_ipc::CaptivePortalProblem::kNoInternet:
      return kPortalRoutineNoInternetProblemMessage;
  }
}

// Parses the results of the captive portal routine.
SimpleRoutine::RoutineResult ParseCaptivePortalResult(
    network_diagnostics_ipc::RoutineResultPtr result) {
  switch (result->verdict) {
    case network_diagnostics_ipc::RoutineVerdict::kNoProblem:
      return {
          .status = mojom::DiagnosticRoutineStatusEnum::kPassed,
          .status_message = kPortalRoutineNoProblemMessage,
      };
    case network_diagnostics_ipc::RoutineVerdict::kNotRun:
      return {
          .status = mojom::DiagnosticRoutineStatusEnum::kNotRun,
          .status_message = kPortalRoutineNotRunMessage,
      };
    case network_diagnostics_ipc::RoutineVerdict::kProblem:
      auto problems = result->problems->get_captive_portal_problems();
      DCHECK(!problems.empty());
      return {
          .status = mojom::DiagnosticRoutineStatusEnum::kFailed,
          .status_message = GetProblemMessage(problems[0]),
      };
  }
}

void RunCaptivePortalRoutine(
    NetworkDiagnosticsAdapter* network_diagnostics_adapter,
    SimpleRoutine::RoutineResultCallback callback) {
  DCHECK(network_diagnostics_adapter);
  network_diagnostics_adapter->RunCaptivePortalRoutine(
      base::BindOnce(&ParseCaptivePortalResult).Then(std::move(callback)));
}

}  // namespace

const char kPortalRoutineNoProblemMessage[] =
    "Captive portal routine passed with no problems.";
const char kPortalRoutineNoActiveNetworksProblemMessage[] =
    "No active networks found.";
const char kPortalRoutineUnknownPortalStateProblemMessage[] =
    "The active network is not connected or the portal state is not available.";
const char kPortalRoutinePortalSuspectedProblemMessage[] =
    "A portal is suspected but no redirect was provided.";
const char kPortalRoutinePortalProblemMessage[] =
    "The network is in a portal state with a redirect URL.";
const char kPortalRoutineProxyAuthRequiredProblemMessage[] =
    "A proxy requiring authentication is detected.";
const char kPortalRoutineNoInternetProblemMessage[] =
    "The active network is connected but no internet is available and no proxy "
    "was detected.";
const char kPortalRoutineNotRunMessage[] =
    "Captive portal routine did not run.";

std::unique_ptr<DiagnosticRoutine> CreateCaptivePortalRoutine(
    NetworkDiagnosticsAdapter* network_diagnostics_adapter) {
  return std::make_unique<SimpleRoutine>(
      base::BindOnce(&RunCaptivePortalRoutine, network_diagnostics_adapter));
}

}  // namespace diagnostics
