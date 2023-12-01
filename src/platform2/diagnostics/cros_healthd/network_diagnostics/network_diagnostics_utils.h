// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_NETWORK_DIAGNOSTICS_NETWORK_DIAGNOSTICS_UTILS_H_
#define DIAGNOSTICS_CROS_HEALTHD_NETWORK_DIAGNOSTICS_NETWORK_DIAGNOSTICS_UTILS_H_

#include "diagnostics/mojom/external/network_diagnostics.mojom.h"

namespace diagnostics {

chromeos::network_diagnostics::mojom::RoutineResultPtr CreateResult(
    chromeos::network_diagnostics::mojom::RoutineVerdict verdict,
    chromeos::network_diagnostics::mojom::RoutineProblemsPtr problems);

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_NETWORK_DIAGNOSTICS_NETWORK_DIAGNOSTICS_UTILS_H_
