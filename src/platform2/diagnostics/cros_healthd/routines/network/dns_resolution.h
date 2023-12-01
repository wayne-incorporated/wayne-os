// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_ROUTINES_NETWORK_DNS_RESOLUTION_H_
#define DIAGNOSTICS_CROS_HEALTHD_ROUTINES_NETWORK_DNS_RESOLUTION_H_

#include <memory>

#include "diagnostics/cros_healthd/network_diagnostics/network_diagnostics_adapter.h"
#include "diagnostics/cros_healthd/routines/diag_routine.h"

namespace diagnostics {

// Status messages reported by the DNS resolution routine.
extern const char kDnsResolutionRoutineNoProblemMessage[];
extern const char kDnsResolutionRoutineFailedToResolveHostProblemMessage[];
extern const char kDnsResolutionRoutineNotRunMessage[];

// Creates an instance of the DNS resolution routine.
std::unique_ptr<DiagnosticRoutine> CreateDnsResolutionRoutine(
    NetworkDiagnosticsAdapter* network_diagnostics_adapter);

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_ROUTINES_NETWORK_DNS_RESOLUTION_H_
