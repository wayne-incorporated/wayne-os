// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_ROUTINES_NETWORK_HTTPS_LATENCY_H_
#define DIAGNOSTICS_CROS_HEALTHD_ROUTINES_NETWORK_HTTPS_LATENCY_H_

#include <memory>

#include "diagnostics/cros_healthd/network_diagnostics/network_diagnostics_adapter.h"
#include "diagnostics/cros_healthd/routines/diag_routine.h"

namespace diagnostics {

// Status messages reported by the HTTPS latency routine.
extern const char kHttpsLatencyRoutineNoProblemMessage[];
extern const char kHttpsLatencyRoutineFailedDnsResolutionsProblemMessage[];
extern const char kHttpsLatencyRoutineFailedHttpsRequestsProblemMessage[];
extern const char kHttpsLatencyRoutineHighLatencyProblemMessage[];
extern const char kHttpsLatencyRoutineVeryHighLatencyProblemMessage[];
extern const char kHttpsLatencyRoutineNotRunMessage[];

// Creates an instance of the HTTPS latency routine.
std::unique_ptr<DiagnosticRoutine> CreateHttpsLatencyRoutine(
    NetworkDiagnosticsAdapter* network_diagnostics_adapter);

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_ROUTINES_NETWORK_HTTPS_LATENCY_H_
