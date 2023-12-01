// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_ROUTINES_ARC_DNS_RESOLUTION_ARC_DNS_RESOLUTION_H_
#define DIAGNOSTICS_CROS_HEALTHD_ROUTINES_ARC_DNS_RESOLUTION_ARC_DNS_RESOLUTION_H_

#include <memory>

#include "diagnostics/cros_healthd/network_diagnostics/network_diagnostics_adapter.h"
#include "diagnostics/cros_healthd/routines/diag_routine.h"

namespace diagnostics {

// Status messages reported by the ARC DNS resolution routine.
inline constexpr char kArcDnsResolutionRoutineNoProblemMessage[] =
    "ARC DNS resolution routine passed with no problems.";
inline constexpr char
    kArcDnsResolutionRoutineFailedToGetArcServiceManagerMessage[] =
        "An internal error has occurred.";
inline constexpr char kArcDnsResolutionRoutineFailedToGetNetInstanceMessage[] =
    "ARC is not running.";
inline constexpr char kArcDnsResolutionRoutineHighLatencyMessage[] =
    "DNS latency slightly above allowable threshold.";
inline constexpr char kArcDnsResolutionRoutineVeryHighLatencyMessage[] =
    "DNS latency significantly above allowable threshold.";
inline constexpr char kArcDnsResolutionRoutineFailedDnsQueriesMessage[] =
    "Failed to resolve host.";
inline constexpr char kArcDnsResolutionRoutineNotRunMessage[] =
    "ARC DNS resolution routine did not run.";

// Creates an instance of ARC DNS resolution routine.
std::unique_ptr<DiagnosticRoutine> CreateArcDnsResolutionRoutine(
    NetworkDiagnosticsAdapter* network_diagnostics_adapter);

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_ROUTINES_ARC_DNS_RESOLUTION_ARC_DNS_RESOLUTION_H_
