// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_ROUTINES_NETWORK_HTTP_FIREWALL_H_
#define DIAGNOSTICS_CROS_HEALTHD_ROUTINES_NETWORK_HTTP_FIREWALL_H_

#include <memory>

#include "diagnostics/cros_healthd/network_diagnostics/network_diagnostics_adapter.h"
#include "diagnostics/cros_healthd/routines/diag_routine.h"

namespace diagnostics {

// Status messages reported by the HTTP firewall routine.
extern const char kHttpFirewallRoutineNoProblemMessage[];
extern const char
    kHttpFirewallRoutineHighDnsResolutionFailureRateProblemMessage[];
extern const char kHttpFirewallRoutineFirewallDetectedProblemMessage[];
extern const char kHttpFirewallRoutinePotentialFirewallProblemMessage[];
extern const char kHttpFirewallRoutineNotRunMessage[];

// Creates an instance of the HTTP firewall routine.
std::unique_ptr<DiagnosticRoutine> CreateHttpFirewallRoutine(
    NetworkDiagnosticsAdapter* network_diagnostics_adapter);

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_ROUTINES_NETWORK_HTTP_FIREWALL_H_
