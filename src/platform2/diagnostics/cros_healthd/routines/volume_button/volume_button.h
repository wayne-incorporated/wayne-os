// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_ROUTINES_VOLUME_BUTTON_VOLUME_BUTTON_H_
#define DIAGNOSTICS_CROS_HEALTHD_ROUTINES_VOLUME_BUTTON_VOLUME_BUTTON_H_

#include <string>

#include <base/cancelable_callback.h>
#include <base/memory/weak_ptr.h>
#include <base/time/time.h>
#include <mojo/public/cpp/bindings/pending_remote.h>
#include <mojo/public/cpp/bindings/receiver.h>

#include "diagnostics/cros_healthd/routines/base_routine_control.h"
#include "diagnostics/cros_healthd/system/context.h"
#include "diagnostics/mojom/public/cros_healthd_routines.mojom.h"

namespace diagnostics {

class VolumeButtonRoutine final
    : public BaseRoutineControl,
      public ash::cros_healthd::mojom::VolumeButtonObserver {
 public:
  explicit VolumeButtonRoutine(
      Context* context,
      const ash::cros_healthd::mojom::VolumeButtonRoutineArgumentPtr& arg);
  VolumeButtonRoutine(const VolumeButtonRoutine&) = delete;
  VolumeButtonRoutine& operator=(const VolumeButtonRoutine&) = delete;
  ~VolumeButtonRoutine() override;

  // BaseRoutineControl overrides:
  void OnStart() override;

  // ash::cros_healthd::mojom::VolumeButtonObserver overrides:
  void OnEvent(ash::cros_healthd::mojom::VolumeButtonObserver::Button button,
               ash::cros_healthd::mojom::VolumeButtonObserver::ButtonState
                   button_state) override;

 private:
  void OnTimeout();
  void OnEventObserverDisconnect(uint32_t custom_reason,
                                 const std::string& description);
  void CleanUp();

  // The observer of volume button events.
  mojo::Receiver<ash::cros_healthd::mojom::VolumeButtonObserver> receiver_{
      this};
  // This is used to control the monitor process.
  mojo::Remote<ash::cros_healthd::mojom::ProcessControl> process_control_;
  // The callback to stop monitoring and report failure on timeout.
  base::CancelableOnceClosure timeout_callback_;
  // The button type under test.
  ash::cros_healthd::mojom::VolumeButtonRoutineArgument::ButtonType
      target_button_type_;
  // Maximum time to wait for a volume button event.
  const base::TimeDelta timeout_;
  // Context object used to communicate with the executor.
  Context* context_ = nullptr;
  // Must be the last class member.
  base::WeakPtrFactory<VolumeButtonRoutine> weak_ptr_factory_{this};
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_ROUTINES_VOLUME_BUTTON_VOLUME_BUTTON_H_
