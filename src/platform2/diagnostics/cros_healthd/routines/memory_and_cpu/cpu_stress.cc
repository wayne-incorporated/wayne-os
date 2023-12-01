// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/routines/memory_and_cpu/cpu_stress.h"

#include <optional>
#include <string>
#include <vector>

#include <base/strings/string_number_conversions.h>

#include "diagnostics/cros_healthd/routines/memory_and_cpu/constants.h"
#include "diagnostics/cros_healthd/routines/subproc_routine.h"

namespace diagnostics {

namespace {

constexpr char kCpuRoutineExePath[] = "/usr/bin/stressapptest";

}  // namespace

std::unique_ptr<DiagnosticRoutine> CreateCpuStressRoutine(
    const std::optional<base::TimeDelta>& exec_duration) {
  base::TimeDelta duration = exec_duration.value_or(kDefaultCpuStressRuntime);
  std::vector<std::string> cmd{kCpuRoutineExePath, "-W", "-s",
                               base::NumberToString(duration.InSeconds())};
  if (duration.is_zero()) {
    // Since the execution duration should not be zero, we should let the
    // routine always failed by adding the flag '--force_error' to the
    // stressapptest.
    cmd.push_back("--force_error");
  }

  return std::make_unique<SubprocRoutine>(base::CommandLine(cmd), duration);
}

}  // namespace diagnostics
