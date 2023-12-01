// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_ROUTINES_NETWORK_GATEWAY_CAN_BE_PINGED_H_
#define DIAGNOSTICS_CROS_HEALTHD_ROUTINES_NETWORK_GATEWAY_CAN_BE_PINGED_H_

#include <memory>

#include "diagnostics/cros_healthd/network_diagnostics/network_diagnostics_adapter.h"
#include "diagnostics/cros_healthd/routines/diag_routine.h"

namespace diagnostics {

// Status messages reported by the gateway can be pinged routine.
extern const char kPingRoutineNoProblemMessage[];
extern const char kPingRoutineUnreachableGatewayProblemMessage[];
extern const char kPingRoutineFailedPingProblemMessage[];
extern const char kPingRoutineHighPingLatencyProblemMessage[];
extern const char kPingRoutineFailedNonDefaultPingsProblemMessage[];
extern const char kPingRoutineNonDefaultHighLatencyProblemMessage[];
extern const char kPingRoutineNotRunMessage[];

// Creates the gateway can be pinged routine.
std::unique_ptr<DiagnosticRoutine> CreateGatewayCanBePingedRoutine(
    NetworkDiagnosticsAdapter* network_diagnostics_adapter);

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_ROUTINES_NETWORK_GATEWAY_CAN_BE_PINGED_H_
