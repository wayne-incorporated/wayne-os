// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_ROUTINES_ARC_PING_ARC_PING_H_
#define DIAGNOSTICS_CROS_HEALTHD_ROUTINES_ARC_PING_ARC_PING_H_

#include <memory>

#include "diagnostics/cros_healthd/network_diagnostics/network_diagnostics_adapter.h"
#include "diagnostics/cros_healthd/routines/diag_routine.h"

namespace diagnostics {

// Status messages reported by the gateway can be pinged routine.
inline constexpr char kArcPingRoutineNoProblemMessage[] =
    "ARC Ping routine passed with no problems.";
inline constexpr char kArcPingRoutineFailedToGetArcServiceManagerMessage[] =
    "An internal error has occurred.";
inline constexpr char
    kArcPingRoutineFailedToGetNetInstanceForPingTestMessage[] =
        "ARC is not running.";
inline constexpr char
    kArcPingRoutineGetManagedPropertiesTimeoutFailureMessage[] =
        "An internal error has occurred.";
inline constexpr char kArcPingRoutineUnreachableGatewayMessage[] =
    "All gateways are unreachable, hence cannot be pinged.";
inline constexpr char kArcPingRoutineFailedToPingDefaultNetworkMessage[] =
    "The default network cannot be pinged.";
inline constexpr char
    kArcPingRoutineDefaultNetworkAboveLatencyThresholdMessage[] =
        "The default network has a latency above the threshold.";
inline constexpr char
    kArcPingRoutineUnsuccessfulNonDefaultNetworksPingsMessage[] =
        "One or more of the non-default networks has failed pings.";
inline constexpr char
    kArcPingRoutineNonDefaultNetworksAboveLatencyThresholdMessage[] =
        "One or more of the non-default networks has a latency above the "
        "threshold.";
inline constexpr char kArcPingRoutineNotRunMessage[] =
    "ARC Ping routine did not run.";

// Creates an instance of ARC ping routine.
std::unique_ptr<DiagnosticRoutine> CreateArcPingRoutine(
    NetworkDiagnosticsAdapter* network_diagnostics_adapter);

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_ROUTINES_ARC_PING_ARC_PING_H_
