// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_ROUTINES_NETWORK_DNS_RESOLVER_PRESENT_H_
#define DIAGNOSTICS_CROS_HEALTHD_ROUTINES_NETWORK_DNS_RESOLVER_PRESENT_H_

#include <memory>

#include "diagnostics/cros_healthd/network_diagnostics/network_diagnostics_adapter.h"
#include "diagnostics/cros_healthd/routines/diag_routine.h"

namespace diagnostics {

// Status messages reported by the DNS resolver present routine.
extern const char kDnsResolverPresentRoutineNoProblemMessage[];
extern const char kDnsResolverPresentRoutineNoNameServersFoundProblemMessage[];
extern const char
    kDnsResolverPresentRoutineMalformedNameServersProblemMessage[];
extern const char kDnsResolverPresentRoutineNotRunMessage[];

// Creates the DNS resolver present routine.
std::unique_ptr<DiagnosticRoutine> CreateDnsResolverPresentRoutine(
    NetworkDiagnosticsAdapter* network_diagnostics_adapter);

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_ROUTINES_NETWORK_DNS_RESOLVER_PRESENT_H_
