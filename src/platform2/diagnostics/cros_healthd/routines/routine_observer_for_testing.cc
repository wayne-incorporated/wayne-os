// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/routines/routine_observer_for_testing.h"

#include <utility>

namespace diagnostics {

namespace {

namespace mojom = ::ash::cros_healthd::mojom;

}  // namespace

RoutineObserverForTesting::RoutineObserverForTesting(
    base::OnceClosure on_finished)
    : on_finished_(std::move(on_finished)) {}

void RoutineObserverForTesting::OnRoutineStateChange(
    mojom::RoutineStatePtr state) {
  CHECK(state);
  state_ = std::move(state);
  if (state_->state_union->is_finished()) {
    CHECK(on_finished_);
    std::move(on_finished_).Run();
  }
}

}  // namespace diagnostics
