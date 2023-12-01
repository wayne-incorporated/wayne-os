// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/routines/memory_and_cpu/floating_point_accuracy.h"

#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <base/strings/string_number_conversions.h>
#include <base/time/time.h>

#include "diagnostics/cros_healthd/routines/memory_and_cpu/constants.h"
#include "diagnostics/cros_healthd/routines/subproc_routine.h"

namespace diagnostics {

namespace {

constexpr char kFloatingPointAccuracyTestExePath[] =
    "/usr/libexec/diagnostics/floating-point-accuracy";

}  // namespace

std::unique_ptr<DiagnosticRoutine> CreateFloatingPointAccuracyRoutine(
    const std::optional<base::TimeDelta>& exec_duration) {
  base::TimeDelta duration = exec_duration.value_or(kDefaultCpuStressRuntime);
  return std::make_unique<SubprocRoutine>(
      base::CommandLine(std::vector<std::string>{
          kFloatingPointAccuracyTestExePath,
          "--duration=" + base::NumberToString(duration.InSeconds())}),
      duration);
}

}  // namespace diagnostics
