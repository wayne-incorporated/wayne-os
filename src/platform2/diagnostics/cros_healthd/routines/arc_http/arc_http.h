// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_ROUTINES_ARC_HTTP_ARC_HTTP_H_
#define DIAGNOSTICS_CROS_HEALTHD_ROUTINES_ARC_HTTP_ARC_HTTP_H_

#include <memory>

#include "diagnostics/cros_healthd/network_diagnostics/network_diagnostics_adapter.h"
#include "diagnostics/cros_healthd/routines/diag_routine.h"

namespace diagnostics {

// Status messages reported by the ARC HTTP routine.
inline constexpr char kArcHttpRoutineNoProblemMessage[] =
    "ARC HTTP routine passed with no problems.";
inline constexpr char kArcHttpRoutineFailedToGetArcServiceManagerMessage[] =
    "An internal error has occurred.";
inline constexpr char
    kArcHttpRoutineFailedToGetNetInstanceForHttpTestMessage[] =
        "ARC is not running.";
inline constexpr char kArcHttpRoutineFailedHttpsRequestsProblemMessage[] =
    "One or more HTTP requests resulted in a failure.";
inline constexpr char kArcHttpRoutineHighLatencyProblemMessage[] =
    "HTTP request latency is high.";
inline constexpr char kArcHttpRoutineVeryHighLatencyProblemMessage[] =
    "HTTP request latency is very high.";
inline constexpr char kArcHttpRoutineNotRunMessage[] =
    "ARC HTTP routine did not run.";

// Creates an instance of the ARC HTTP routine.
std::unique_ptr<DiagnosticRoutine> CreateArcHttpRoutine(
    NetworkDiagnosticsAdapter* network_diagnostics_adapter);

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_ROUTINES_ARC_HTTP_ARC_HTTP_H_
