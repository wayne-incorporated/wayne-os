// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_ROUTINES_ROUTINE_OBSERVER_FOR_TESTING_H_
#define DIAGNOSTICS_CROS_HEALTHD_ROUTINES_ROUTINE_OBSERVER_FOR_TESTING_H_

#include <mojo/public/cpp/bindings/receiver.h>

#include "diagnostics/mojom/public/cros_healthd_routines.mojom.h"

namespace diagnostics {

class RoutineObserverForTesting
    : public ash::cros_healthd::mojom::RoutineObserver {
 public:
  explicit RoutineObserverForTesting(base::OnceClosure on_finished);
  RoutineObserverForTesting(const RoutineObserverForTesting&) = delete;
  RoutineObserverForTesting& operator=(const RoutineObserverForTesting&) =
      delete;
  ~RoutineObserverForTesting() override = default;

  void OnRoutineStateChange(
      ash::cros_healthd::mojom::RoutineStatePtr state) override;

  ash::cros_healthd::mojom::RoutineStatePtr state_;
  mojo::Receiver<ash::cros_healthd::mojom::RoutineObserver> receiver_{this};

 private:
  base::OnceClosure on_finished_;
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_ROUTINES_ROUTINE_OBSERVER_FOR_TESTING_H_
