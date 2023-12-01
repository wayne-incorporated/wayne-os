// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_ROUTINES_MEMORY_AND_CPU_CPU_STRESS_V2_H_
#define DIAGNOSTICS_CROS_HEALTHD_ROUTINES_MEMORY_AND_CPU_CPU_STRESS_V2_H_

#include <base/functional/callback_helpers.h>
#include <base/memory/weak_ptr.h>
#include <base/time/default_tick_clock.h>
#include <base/time/time.h>

#include "diagnostics/cros_healthd/executor/utils/scoped_process_control.h"
#include "diagnostics/cros_healthd/mojom/executor.mojom.h"
#include "diagnostics/cros_healthd/routines/base_routine_control.h"
#include "diagnostics/cros_healthd/system/context.h"
#include "diagnostics/mojom/public/cros_healthd_diagnostics.mojom.h"
#include "diagnostics/mojom/public/cros_healthd_routines.mojom.h"

namespace diagnostics {

// The cpu stress routine checks that the device's cpu system is working
// correctly.
class CpuStressRoutineV2 final : public BaseRoutineControl {
 public:
  explicit CpuStressRoutineV2(
      Context* context,
      const ash::cros_healthd::mojom::CpuStressRoutineArgumentPtr& arg);
  CpuStressRoutineV2(const CpuStressRoutineV2&) = delete;
  CpuStressRoutineV2& operator=(const CpuStressRoutineV2&) = delete;
  ~CpuStressRoutineV2() override;

  // BaseRoutineControl overrides:
  void OnStart() override;

 private:
  // The |Run| function is added to the cpu and memory resource queue as a
  // callback and will be called when resource is available.
  void Run(base::ScopedClosureRunner notify_resource_queue_finished);

  // Accepts a return code and return the result.
  void HandleGetReturnCode(int return_code);

  // Update the percentage progress of the routine.
  void UpdatePercentage();

  // Unowned. Should outlive this instance.
  Context* const context_ = nullptr;
  // A scoped version of process control that manages the lifetime of the
  // stressapptest process.
  ScopedProcessControl scoped_process_control_;
  // The execution duration of the stressapptest program.
  base::TimeDelta exec_duration_;
  // |start_ticks_| records the time when the routine began. This is used with
  // |exec_duration_| to report on progress percentage.
  base::TimeTicks start_ticks_;
  // |tick_clock_| is used to get the current time tick for percentage
  // calculation.
  base::DefaultTickClock tick_clock_;

  // Must be the last class member.
  base::WeakPtrFactory<CpuStressRoutineV2> weak_ptr_factory_{this};
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_ROUTINES_MEMORY_AND_CPU_CPU_STRESS_V2_H_
