// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/network_diagnostics/network_diagnostics_utils.h"

#include <utility>

#include <base/time/time.h>

#include "diagnostics/mojom/external/network_diagnostics.mojom.h"

namespace {

namespace network_diagnostics_ipc = ::chromeos::network_diagnostics::mojom;

}  // namespace

namespace diagnostics {

network_diagnostics_ipc::RoutineResultPtr CreateResult(
    network_diagnostics_ipc::RoutineVerdict verdict,
    network_diagnostics_ipc::RoutineProblemsPtr problems) {
  auto result = network_diagnostics_ipc::RoutineResult::New();
  result->verdict = verdict;
  result->problems = std::move(problems);
  result->timestamp = base::Time::Now();
  return result;
}

}  // namespace diagnostics
