// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/routines/network/http_firewall.h"

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
    network_diagnostics_ipc::HttpFirewallProblem problem) {
  switch (problem) {
    case network_diagnostics_ipc::HttpFirewallProblem::
        kDnsResolutionFailuresAboveThreshold:
      return kHttpFirewallRoutineHighDnsResolutionFailureRateProblemMessage;
    case network_diagnostics_ipc::HttpFirewallProblem::kFirewallDetected:
      return kHttpFirewallRoutineFirewallDetectedProblemMessage;
    case network_diagnostics_ipc::HttpFirewallProblem::kPotentialFirewall:
      return kHttpFirewallRoutinePotentialFirewallProblemMessage;
  }
}

// Parses the results of the HTTP firewall routine.
SimpleRoutine::RoutineResult ParseHttpFirewallResult(
    network_diagnostics_ipc::RoutineResultPtr result) {
  switch (result->verdict) {
    case network_diagnostics_ipc::RoutineVerdict::kNoProblem:
      return {
          .status = mojom::DiagnosticRoutineStatusEnum::kPassed,
          .status_message = kHttpFirewallRoutineNoProblemMessage,
      };
    case network_diagnostics_ipc::RoutineVerdict::kNotRun:
      return {
          .status = mojom::DiagnosticRoutineStatusEnum::kNotRun,
          .status_message = kHttpFirewallRoutineNotRunMessage,
      };
    case network_diagnostics_ipc::RoutineVerdict::kProblem:
      auto problems = result->problems->get_http_firewall_problems();
      DCHECK(!problems.empty());
      return {
          .status = mojom::DiagnosticRoutineStatusEnum::kFailed,
          .status_message = GetProblemMessage(problems[0]),
      };
  }
}

void RunHttpFirewallRoutine(
    NetworkDiagnosticsAdapter* network_diagnostics_adapter,
    SimpleRoutine::RoutineResultCallback callback) {
  DCHECK(network_diagnostics_adapter);
  network_diagnostics_adapter->RunHttpFirewallRoutine(
      base::BindOnce(&ParseHttpFirewallResult).Then(std::move(callback)));
}

}  // namespace

const char kHttpFirewallRoutineNoProblemMessage[] =
    "HTTP firewall routine passed with no problems.";
const char kHttpFirewallRoutineHighDnsResolutionFailureRateProblemMessage[] =
    "DNS resolution failures above threshold.";
const char kHttpFirewallRoutineFirewallDetectedProblemMessage[] =
    "Firewall detected.";
const char kHttpFirewallRoutinePotentialFirewallProblemMessage[] =
    "A firewall may potentially exist.";
const char kHttpFirewallRoutineNotRunMessage[] =
    "HTTP firewall routine did not run.";

std::unique_ptr<DiagnosticRoutine> CreateHttpFirewallRoutine(
    NetworkDiagnosticsAdapter* network_diagnostics_adapter) {
  return std::make_unique<SimpleRoutine>(
      base::BindOnce(&RunHttpFirewallRoutine, network_diagnostics_adapter));
}

}  // namespace diagnostics
