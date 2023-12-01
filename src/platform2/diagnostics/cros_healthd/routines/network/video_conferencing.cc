// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/routines/network/video_conferencing.h"

#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/functional/bind.h>
#include <base/notreached.h>
#include <base/strings/string_util.h>

#include "diagnostics/cros_healthd/routines/simple_routine.h"
#include "diagnostics/mojom/external/network_diagnostics.mojom.h"
#include "diagnostics/mojom/public/cros_healthd_diagnostics.mojom.h"

namespace diagnostics {

namespace {

namespace mojom = ::ash::cros_healthd::mojom;
namespace network_diagnostics_ipc = ::chromeos::network_diagnostics::mojom;

std::string GetProblemMessage(
    const std::vector<network_diagnostics_ipc::VideoConferencingProblem>&
        problems) {
  std::string problem_message = "";
  for (auto problem : problems) {
    switch (problem) {
      case network_diagnostics_ipc::VideoConferencingProblem::kUdpFailure:
        problem_message += (kVideoConferencingRoutineUdpFailureProblemMessage +
                            std::string("\n"));
        break;
      case network_diagnostics_ipc::VideoConferencingProblem::kTcpFailure:
        problem_message += (kVideoConferencingRoutineTcpFailureProblemMessage +
                            std::string("\n"));
        break;
      case network_diagnostics_ipc::VideoConferencingProblem::kMediaFailure:
        problem_message +=
            (kVideoConferencingRoutineMediaFailureProblemMessage +
             std::string("\n"));
        break;
    }
  }

  return std::string(
      base::TrimString(problem_message, "\n", base::TRIM_TRAILING));
}

// Parses the results of the video conferencing routine.
SimpleRoutine::RoutineResult ParseVideoConferencingResult(
    network_diagnostics_ipc::RoutineResultPtr result) {
  switch (result->verdict) {
    case network_diagnostics_ipc::RoutineVerdict::kNoProblem:
      return {
          .status = mojom::DiagnosticRoutineStatusEnum::kPassed,
          .status_message = kVideoConferencingRoutineNoProblemMessage,
      };
    case network_diagnostics_ipc::RoutineVerdict::kNotRun:
      return {
          .status = mojom::DiagnosticRoutineStatusEnum::kNotRun,
          .status_message = kVideoConferencingRoutineNotRunMessage,
      };
    case network_diagnostics_ipc::RoutineVerdict::kProblem:
      auto problems = result->problems->get_video_conferencing_problems();
      DCHECK(!problems.empty());
      return {
          .status = mojom::DiagnosticRoutineStatusEnum::kFailed,
          .status_message = GetProblemMessage(problems),
      };
  }
}

void RunVideoConferencingRoutine(
    const std::optional<std::string>& stun_server_hostname,
    NetworkDiagnosticsAdapter* network_diagnostics_adapter,
    SimpleRoutine::RoutineResultCallback callback) {
  DCHECK(network_diagnostics_adapter);
  network_diagnostics_adapter->RunVideoConferencingRoutine(
      stun_server_hostname,
      base::BindOnce(&ParseVideoConferencingResult).Then(std::move(callback)));
}

}  // namespace

const char kVideoConferencingRoutineNoProblemMessage[] =
    "Video conferencing routine passed with no problems.";
const char kVideoConferencingRoutineUdpFailureProblemMessage[] =
    "Failed requests to a STUN server via UDP.";
const char kVideoConferencingRoutineTcpFailureProblemMessage[] =
    "Failed requests to a STUN server via TCP.";
const char kVideoConferencingRoutineMediaFailureProblemMessage[] =
    "Failed to establish a TLS connection to media hostnames.";
const char kVideoConferencingRoutineNotRunMessage[] =
    "Video conferencing routine did not run.";

std::unique_ptr<DiagnosticRoutine> CreateVideoConferencingRoutine(
    const std::optional<std::string>& stun_server_hostname,
    NetworkDiagnosticsAdapter* network_diagnostics_adapter) {
  return std::make_unique<SimpleRoutine>(
      base::BindOnce(&RunVideoConferencingRoutine, stun_server_hostname,
                     network_diagnostics_adapter));
}

}  // namespace diagnostics
