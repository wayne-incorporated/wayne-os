// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_ROUTINES_NETWORK_HAS_SECURE_WIFI_CONNECTION_H_
#define DIAGNOSTICS_CROS_HEALTHD_ROUTINES_NETWORK_HAS_SECURE_WIFI_CONNECTION_H_

#include <memory>

#include "diagnostics/cros_healthd/network_diagnostics/network_diagnostics_adapter.h"
#include "diagnostics/cros_healthd/routines/diag_routine.h"

namespace diagnostics {

// Status messages reported by the has secure WiFi connection routine.
extern const char kHasSecureWiFiConnectionRoutineNoProblemMessage[];
extern const char
    kHasSecureWiFiConnectionRoutineSecurityTypeNoneProblemMessage[];
extern const char
    kHasSecureWiFiConnectionRoutineSecurityTypeWep8021xProblemMessage[];
extern const char
    kHasSecureWiFiConnectionRoutineSecurityTypeWepPskProblemMessage[];
extern const char
    kHasSecureWiFiConnectionRoutineUnknownSecurityTypeProblemMessage[];
extern const char kHasSecureWiFiConnectionRoutineNotRunMessage[];

// Creates the has secure WiFi connection routine.
std::unique_ptr<DiagnosticRoutine> CreateHasSecureWiFiConnectionRoutine(
    NetworkDiagnosticsAdapter* network_diagnostics_adapter);

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_ROUTINES_NETWORK_HAS_SECURE_WIFI_CONNECTION_H_
