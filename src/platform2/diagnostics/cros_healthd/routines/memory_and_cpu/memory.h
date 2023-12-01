// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_ROUTINES_MEMORY_AND_CPU_MEMORY_H_
#define DIAGNOSTICS_CROS_HEALTHD_ROUTINES_MEMORY_AND_CPU_MEMORY_H_

#include <memory>
#include <string>

#include <base/memory/weak_ptr.h>
#include <base/time/default_tick_clock.h>
#include <base/time/tick_clock.h>
#include <base/time/time.h>
#include <base/values.h>

#include "diagnostics/cros_healthd/mojom/executor.mojom.h"
#include "diagnostics/cros_healthd/routines/diag_routine_with_status.h"
#include "diagnostics/cros_healthd/system/context.h"
#include "diagnostics/mojom/public/cros_healthd_diagnostics.mojom.h"

namespace diagnostics {

// The memory routine checks that the device's memory is working correctly.
class MemoryRoutine final : public DiagnosticRoutineWithStatus {
 public:
  // Override |tick_clock| for testing only.
  explicit MemoryRoutine(Context* context,
                         const base::TickClock* tick_clock = nullptr);
  MemoryRoutine(const MemoryRoutine&) = delete;
  MemoryRoutine& operator=(const MemoryRoutine&) = delete;
  ~MemoryRoutine() override;

  // DiagnosticRoutine overrides:
  void Start() override;
  void Resume() override;
  void Cancel() override;
  void PopulateStatusUpdate(ash::cros_healthd::mojom::RoutineUpdate* response,
                            bool include_output) override;

 private:
  // Takes the memtester result code from |process| and parses it to determine
  // whether or not the routine succeeded.
  void DetermineRoutineResult(
      ash::cros_healthd::mojom::ExecutedProcessResultPtr process);

  // Takes raw output from memtester and parses it into |output_dict_|.
  void ParseMemtesterOutput(const std::string& raw_output);

  // Unowned. Should outlive this instance.
  Context* const context_ = nullptr;

  // Details about the routine's execution. Reported in status updates when
  // requested.
  base::Value::Dict output_dict_;

  // Expected duration of the routine, in microseconds.
  double expected_duration_us_ = 0;
  // When the routine started. Used to calculate the routine's progress percent.
  base::TimeTicks start_ticks_;
  // Tracks the passage of time. Should never be used directly - instead, use
  // |tick_clock_|.
  std::unique_ptr<base::DefaultTickClock> default_tick_clock_;
  // Unowned pointer which should outlive this instance. Allows the default tick
  // clock to be overridden for testing.
  const base::TickClock* tick_clock_;

  // Must be the last class member.
  base::WeakPtrFactory<MemoryRoutine> weak_ptr_factory_{this};
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_ROUTINES_MEMORY_AND_CPU_MEMORY_H_
