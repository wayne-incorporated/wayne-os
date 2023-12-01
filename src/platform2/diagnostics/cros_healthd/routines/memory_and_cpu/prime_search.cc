// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/routines/memory_and_cpu/prime_search.h"

#include <optional>
#include <string>
#include <vector>

#include <base/command_line.h>
#include <base/strings/string_number_conversions.h>
#include <base/time/time.h>

#include "diagnostics/cros_healthd/routines/memory_and_cpu/constants.h"
#include "diagnostics/cros_healthd/routines/subproc_routine.h"

namespace diagnostics {

namespace {

constexpr char kPrimeSearchExePath[] = "/usr/libexec/diagnostics/prime-search";

}  // namespace

const uint64_t kPrimeSearchDefaultMaxNum = 1000000;

std::unique_ptr<DiagnosticRoutine> CreatePrimeSearchRoutine(
    const std::optional<base::TimeDelta>& exec_duration,
    const std::optional<uint64_t>& max_num) {
  base::TimeDelta duration = exec_duration.value_or(kDefaultCpuStressRuntime);
  return std::make_unique<SubprocRoutine>(
      base::CommandLine(std::vector<std::string>{
          kPrimeSearchExePath,
          "--time=" + base::NumberToString(duration.InSeconds()),
          "--max_num=" + base::NumberToString(
                             max_num.value_or(kPrimeSearchDefaultMaxNum))}),
      duration);
}

}  // namespace diagnostics
