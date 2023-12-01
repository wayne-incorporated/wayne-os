// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_ROUTINES_MEMORY_AND_CPU_URANDOM_H_
#define DIAGNOSTICS_CROS_HEALTHD_ROUTINES_MEMORY_AND_CPU_URANDOM_H_

#include <memory>
#include <optional>

#include <base/time/time.h>

#include "diagnostics/cros_healthd/routines/diag_routine.h"
#include "diagnostics/cros_healthd/routines/memory_and_cpu/constants.h"

namespace diagnostics {

std::unique_ptr<DiagnosticRoutine> CreateUrandomRoutine(
    const std::optional<base::TimeDelta>& length_seconds);

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_ROUTINES_MEMORY_AND_CPU_URANDOM_H_
