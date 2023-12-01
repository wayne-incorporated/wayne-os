// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/routines/network/has_secure_wifi_connection.h"

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
    network_diagnostics_ipc::HasSecureWiFiConnectionProblem problem) {
  switch (problem) {
    case network_diagnostics_ipc::HasSecureWiFiConnectionProblem::
        kSecurityTypeNone:
      return kHasSecureWiFiConnectionRoutineSecurityTypeNoneProblemMessage;
    case network_diagnostics_ipc::HasSecureWiFiConnectionProblem::
        kSecurityTypeWep8021x:
      return kHasSecureWiFiConnectionRoutineSecurityTypeWep8021xProblemMessage;
    case network_diagnostics_ipc::HasSecureWiFiConnectionProblem::
        kSecurityTypeWepPsk:
      return kHasSecureWiFiConnectionRoutineSecurityTypeWepPskProblemMessage;
    case network_diagnostics_ipc::HasSecureWiFiConnectionProblem::
        kUnknownSecurityType:
      return kHasSecureWiFiConnectionRoutineUnknownSecurityTypeProblemMessage;
  }
}

// Parses the results of the has secure WiFi connection routine.
SimpleRoutine::RoutineResult ParseHasSecureWiFiConnectionResult(
    network_diagnostics_ipc::RoutineResultPtr result) {
  switch (result->verdict) {
    case network_diagnostics_ipc::RoutineVerdict::kNoProblem:
      return {
          .status = mojom::DiagnosticRoutineStatusEnum::kPassed,
          .status_message = kHasSecureWiFiConnectionRoutineNoProblemMessage,
      };
    case network_diagnostics_ipc::RoutineVerdict::kNotRun:
      return {
          .status = mojom::DiagnosticRoutineStatusEnum::kNotRun,
          .status_message = kHasSecureWiFiConnectionRoutineNotRunMessage,
      };
    case network_diagnostics_ipc::RoutineVerdict::kProblem:
      auto problems =
          result->problems->get_has_secure_wifi_connection_problems();
      DCHECK(!problems.empty());
      return {
          .status = mojom::DiagnosticRoutineStatusEnum::kFailed,
          .status_message = GetProblemMessage(problems[0]),
      };
  }
}

void RunHasSecureWiFiConnectionRoutine(
    NetworkDiagnosticsAdapter* network_diagnostics_adapter,
    SimpleRoutine::RoutineResultCallback callback) {
  DCHECK(network_diagnostics_adapter);
  network_diagnostics_adapter->RunHasSecureWiFiConnectionRoutine(
      base::BindOnce(&ParseHasSecureWiFiConnectionResult)
          .Then(std::move(callback)));
}

}  // namespace

const char kHasSecureWiFiConnectionRoutineNoProblemMessage[] =
    "Has secure WiFi connection routine passed with no problems.";
const char kHasSecureWiFiConnectionRoutineSecurityTypeNoneProblemMessage[] =
    "No security type found.";
const char kHasSecureWiFiConnectionRoutineSecurityTypeWep8021xProblemMessage[] =
    "Insecure security type Wep8021x found.";
const char kHasSecureWiFiConnectionRoutineSecurityTypeWepPskProblemMessage[] =
    "Insecure security type WepPsk found.";
const char kHasSecureWiFiConnectionRoutineUnknownSecurityTypeProblemMessage[] =
    "Unknown security type found.";
const char kHasSecureWiFiConnectionRoutineNotRunMessage[] =
    "Has secure WiFi connection routine did not run.";

std::unique_ptr<DiagnosticRoutine> CreateHasSecureWiFiConnectionRoutine(
    NetworkDiagnosticsAdapter* network_diagnostics_adapter) {
  return std::make_unique<SimpleRoutine>(base::BindOnce(
      &RunHasSecureWiFiConnectionRoutine, network_diagnostics_adapter));
}

}  // namespace diagnostics
