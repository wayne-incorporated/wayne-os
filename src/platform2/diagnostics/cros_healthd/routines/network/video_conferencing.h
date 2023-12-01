// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_ROUTINES_NETWORK_VIDEO_CONFERENCING_H_
#define DIAGNOSTICS_CROS_HEALTHD_ROUTINES_NETWORK_VIDEO_CONFERENCING_H_

#include <memory>
#include <optional>
#include <string>

#include "diagnostics/cros_healthd/network_diagnostics/network_diagnostics_adapter.h"
#include "diagnostics/cros_healthd/routines/diag_routine.h"

namespace diagnostics {

// Status messages reported by the video conferencing routine. The messages
// listed below list track all combinations of problems the routine may return
// in a single run.
extern const char kVideoConferencingRoutineNoProblemMessage[];
extern const char kVideoConferencingRoutineUdpFailureProblemMessage[];
extern const char kVideoConferencingRoutineTcpFailureProblemMessage[];
extern const char kVideoConferencingRoutineMediaFailureProblemMessage[];
extern const char kVideoConferencingRoutineNotRunMessage[];

// Additional support details are provided as output when a problem occurs.
extern const char kVideoConferencingRoutineSupportDetailsKey[];

// Creates an instance of the video conferencing routine.
std::unique_ptr<DiagnosticRoutine> CreateVideoConferencingRoutine(
    const std::optional<std::string>& stun_server_hostname,
    NetworkDiagnosticsAdapter* network_diagnostics_adapter);

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_ROUTINES_NETWORK_VIDEO_CONFERENCING_H_
