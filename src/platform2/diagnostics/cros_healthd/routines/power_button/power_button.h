// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_ROUTINES_POWER_BUTTON_POWER_BUTTON_H_
#define DIAGNOSTICS_CROS_HEALTHD_ROUTINES_POWER_BUTTON_POWER_BUTTON_H_

#include <string>

#include <base/cancelable_callback.h>
#include <base/memory/weak_ptr.h>
#include <mojo/public/cpp/bindings/pending_remote.h>
#include <mojo/public/cpp/bindings/receiver.h>

#include "diagnostics/cros_healthd/routines/diag_routine_with_status.h"
#include "diagnostics/cros_healthd/system/context.h"

namespace diagnostics {

class PowerButtonRoutine final
    : public DiagnosticRoutineWithStatus,
      public ash::cros_healthd::mojom::PowerButtonObserver {
 public:
  explicit PowerButtonRoutine(Context* context, uint32_t timeout_seconds);
  PowerButtonRoutine(const PowerButtonRoutine&) = delete;
  PowerButtonRoutine& operator=(const PowerButtonRoutine&) = delete;

  // DiagnosticRoutine overrides:
  ~PowerButtonRoutine() override;
  void Start() override;
  void Resume() override;
  void Cancel() override;
  void PopulateStatusUpdate(ash::cros_healthd::mojom::RoutineUpdate* response,
                            bool include_output) override;

  // ash::cros_healthd::mojom::PowerButtonObserver overrides:
  void OnEvent(ash::cros_healthd::mojom::PowerButtonObserver::ButtonState
                   button_state) override;

 private:
  void OnTimeout();
  void OnEventObserverDisconnect(uint32_t custom_reason,
                                 const std::string& description);
  void CleanUp();

  // The observer of power button events.
  mojo::Receiver<ash::cros_healthd::mojom::PowerButtonObserver> receiver_{this};
  // This is used to control the monitor process.
  mojo::Remote<ash::cros_healthd::mojom::ProcessControl> process_control_;
  // The callback to stop monitoring and report failure on timeout.
  base::CancelableOnceClosure timeout_callback_;
  // Maximum time to wait for a power button event.
  uint32_t timeout_seconds_{0};
  // Context object used to communicate with the executor.
  Context* context_ = nullptr;
  // Must be the last class member.
  base::WeakPtrFactory<PowerButtonRoutine> weak_ptr_factory_{this};
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_ROUTINES_POWER_BUTTON_POWER_BUTTON_H_
