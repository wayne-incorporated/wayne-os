// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/routines/network/dns_latency.h"

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
    network_diagnostics_ipc::DnsLatencyProblem problem) {
  switch (problem) {
    case network_diagnostics_ipc::DnsLatencyProblem::kHostResolutionFailure:
      return kDnsLatencyRoutineHostResolutionFailureProblemMessage;
    case network_diagnostics_ipc::DnsLatencyProblem::kSlightlyAboveThreshold:
      return kDnsLatencyRoutineSlightlyAboveThresholdProblemMessage;
    case network_diagnostics_ipc::DnsLatencyProblem::
        kSignificantlyAboveThreshold:
      return kDnsLatencyRoutineSignificantlyAboveThresholdProblemMessage;
  }
}

// Parses the results of the DNS latency routine.
SimpleRoutine::RoutineResult ParseDnsLatencyResult(
    network_diagnostics_ipc::RoutineResultPtr result) {
  switch (result->verdict) {
    case network_diagnostics_ipc::RoutineVerdict::kNoProblem:
      return {
          .status = mojom::DiagnosticRoutineStatusEnum::kPassed,
          .status_message = kDnsLatencyRoutineNoProblemMessage,
      };
    case network_diagnostics_ipc::RoutineVerdict::kNotRun:
      return {
          .status = mojom::DiagnosticRoutineStatusEnum::kNotRun,
          .status_message = kDnsLatencyRoutineNotRunMessage,
      };
    case network_diagnostics_ipc::RoutineVerdict::kProblem:
      auto problems = result->problems->get_dns_latency_problems();
      DCHECK(!problems.empty());
      return {
          .status = mojom::DiagnosticRoutineStatusEnum::kFailed,
          .status_message = GetProblemMessage(problems[0]),
      };
  }
}

void RunDnsLatencyRoutine(
    NetworkDiagnosticsAdapter* network_diagnostics_adapter,
    SimpleRoutine::RoutineResultCallback callback) {
  DCHECK(network_diagnostics_adapter);
  network_diagnostics_adapter->RunDnsLatencyRoutine(
      base::BindOnce(&ParseDnsLatencyResult).Then(std::move(callback)));
}

}  // namespace

const char kDnsLatencyRoutineNoProblemMessage[] =
    "DNS latency routine passed with no problems.";
const char kDnsLatencyRoutineHostResolutionFailureProblemMessage[] =
    "Failed to resolve one or more hosts.";
const char kDnsLatencyRoutineSlightlyAboveThresholdProblemMessage[] =
    "Average DNS latency across hosts is slightly above expected threshold.";
const char kDnsLatencyRoutineSignificantlyAboveThresholdProblemMessage[] =
    "Average DNS latency across hosts is significantly above expected "
    "threshold.";
const char kDnsLatencyRoutineNotRunMessage[] =
    "DNS latency routine did not run.";

std::unique_ptr<DiagnosticRoutine> CreateDnsLatencyRoutine(
    NetworkDiagnosticsAdapter* network_diagnostics_adapter) {
  return std::make_unique<SimpleRoutine>(
      base::BindOnce(&RunDnsLatencyRoutine, network_diagnostics_adapter));
}

}  // namespace diagnostics
