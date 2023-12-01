// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_ROUTINES_MEMORY_AND_CPU_FLOATING_POINT_ACCURACY_H_
#define DIAGNOSTICS_CROS_HEALTHD_ROUTINES_MEMORY_AND_CPU_FLOATING_POINT_ACCURACY_H_

#include <memory>
#include <optional>

#include <base/time/time.h>

#include "diagnostics/cros_healthd/routines/diag_routine.h"

namespace diagnostics {

std::unique_ptr<DiagnosticRoutine> CreateFloatingPointAccuracyRoutine(
    const std::optional<base::TimeDelta>& exec_duration);

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_ROUTINES_MEMORY_AND_CPU_FLOATING_POINT_ACCURACY_H_
