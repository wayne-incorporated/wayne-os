// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_ROUTINES_NETWORK_CAPTIVE_PORTAL_H_
#define DIAGNOSTICS_CROS_HEALTHD_ROUTINES_NETWORK_CAPTIVE_PORTAL_H_

#include <memory>

#include "diagnostics/cros_healthd/network_diagnostics/network_diagnostics_adapter.h"
#include "diagnostics/cros_healthd/routines/diag_routine.h"

namespace diagnostics {

// Status messages reported by the captive portal routine.
extern const char kPortalRoutineNoProblemMessage[];
extern const char kPortalRoutineNoActiveNetworksProblemMessage[];
extern const char kPortalRoutineUnknownPortalStateProblemMessage[];
extern const char kPortalRoutinePortalSuspectedProblemMessage[];
extern const char kPortalRoutinePortalProblemMessage[];
extern const char kPortalRoutineProxyAuthRequiredProblemMessage[];
extern const char kPortalRoutineNoInternetProblemMessage[];
extern const char kPortalRoutineNotRunMessage[];

// Creates an instance of the captive portal routine.
std::unique_ptr<DiagnosticRoutine> CreateCaptivePortalRoutine(
    NetworkDiagnosticsAdapter* network_diagnostics_adapter);

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_ROUTINES_NETWORK_CAPTIVE_PORTAL_H_
