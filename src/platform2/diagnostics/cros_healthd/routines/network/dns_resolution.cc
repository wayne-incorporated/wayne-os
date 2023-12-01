// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/routines/network/dns_resolution.h"

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
    network_diagnostics_ipc::DnsResolutionProblem problem) {
  switch (problem) {
    case network_diagnostics_ipc::DnsResolutionProblem::kFailedToResolveHost:
      return kDnsResolutionRoutineFailedToResolveHostProblemMessage;
  }
}

// Parses the results of the DNS resolution routine.
SimpleRoutine::RoutineResult ParseDnsResolutionResult(
    network_diagnostics_ipc::RoutineResultPtr result) {
  switch (result->verdict) {
    case network_diagnostics_ipc::RoutineVerdict::kNoProblem:
      return {
          .status = mojom::DiagnosticRoutineStatusEnum::kPassed,
          .status_message = kDnsResolutionRoutineNoProblemMessage,
      };
    case network_diagnostics_ipc::RoutineVerdict::kNotRun:
      return {
          .status = mojom::DiagnosticRoutineStatusEnum::kNotRun,
          .status_message = kDnsResolutionRoutineNotRunMessage,
      };
    case network_diagnostics_ipc::RoutineVerdict::kProblem:
      auto problems = result->problems->get_dns_resolution_problems();
      DCHECK(!problems.empty());
      return {
          .status = mojom::DiagnosticRoutineStatusEnum::kFailed,
          .status_message = GetProblemMessage(problems[0]),
      };
  }
}

void RunDnsResolutionRoutine(
    NetworkDiagnosticsAdapter* network_diagnostics_adapter,
    SimpleRoutine::RoutineResultCallback callback) {
  DCHECK(network_diagnostics_adapter);
  network_diagnostics_adapter->RunDnsResolutionRoutine(
      base::BindOnce(&ParseDnsResolutionResult).Then(std::move(callback)));
}

}  // namespace

const char kDnsResolutionRoutineNoProblemMessage[] =
    "DNS resolution routine passed with no problems.";
const char kDnsResolutionRoutineFailedToResolveHostProblemMessage[] =
    "Failed to resolve host.";
const char kDnsResolutionRoutineNotRunMessage[] =
    "DNS resolution routine did not run.";

std::unique_ptr<DiagnosticRoutine> CreateDnsResolutionRoutine(
    NetworkDiagnosticsAdapter* network_diagnostics_adapter) {
  return std::make_unique<SimpleRoutine>(
      base::BindOnce(&RunDnsResolutionRoutine, network_diagnostics_adapter));
}

}  // namespace diagnostics
