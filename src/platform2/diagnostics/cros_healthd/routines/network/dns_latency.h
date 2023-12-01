// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_ROUTINES_NETWORK_DNS_LATENCY_H_
#define DIAGNOSTICS_CROS_HEALTHD_ROUTINES_NETWORK_DNS_LATENCY_H_

#include <memory>

#include "diagnostics/cros_healthd/network_diagnostics/network_diagnostics_adapter.h"
#include "diagnostics/cros_healthd/routines/diag_routine.h"

namespace diagnostics {

// Status messages reported by the DNS latency routine.
extern const char kDnsLatencyRoutineNoProblemMessage[];
extern const char kDnsLatencyRoutineHostResolutionFailureProblemMessage[];
extern const char kDnsLatencyRoutineSlightlyAboveThresholdProblemMessage[];
extern const char kDnsLatencyRoutineSignificantlyAboveThresholdProblemMessage[];
extern const char kDnsLatencyRoutineNotRunMessage[];

// Creates an instance of the DNS latency routine.
std::unique_ptr<DiagnosticRoutine> CreateDnsLatencyRoutine(
    NetworkDiagnosticsAdapter* network_diagnostics_adapter);

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_ROUTINES_NETWORK_DNS_LATENCY_H_
