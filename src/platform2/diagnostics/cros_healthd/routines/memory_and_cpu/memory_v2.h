// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_ROUTINES_MEMORY_AND_CPU_MEMORY_V2_H_
#define DIAGNOSTICS_CROS_HEALTHD_ROUTINES_MEMORY_AND_CPU_MEMORY_V2_H_

#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <base/files/file.h>
#include <base/functional/callback_forward.h>
#include <base/functional/callback_helpers.h>
#include <base/memory/weak_ptr.h>
#include <base/time/default_tick_clock.h>
#include <base/time/tick_clock.h>
#include <base/time/time.h>

#include "diagnostics/cros_healthd/executor/utils/scoped_process_control.h"
#include "diagnostics/cros_healthd/mojom/executor.mojom.h"
#include "diagnostics/cros_healthd/routines/base_routine_control.h"
#include "diagnostics/cros_healthd/system/context.h"
#include "diagnostics/mojom/public/cros_healthd_diagnostics.mojom.h"

namespace diagnostics {

// Update the progress bar every kMemoryRoutineUpdatePeriod.
inline constexpr base::TimeDelta kMemoryRoutineUpdatePeriod = base::Seconds(1);

// The memory routine checks that the device's memory is working correctly.
class MemoryRoutineV2 final : public BaseRoutineControl {
 public:
  explicit MemoryRoutineV2(
      Context* context,
      const ash::cros_healthd::mojom::MemoryRoutineArgumentPtr& arg);
  MemoryRoutineV2(const MemoryRoutineV2&) = delete;
  MemoryRoutineV2& operator=(const MemoryRoutineV2&) = delete;
  ~MemoryRoutineV2() override;

  // BaseRoutineControl overrides:
  void OnStart() override;

 private:
  // The |Run| function is added to the memory resource queue as a callback and
  // will be called when memory resource is available.
  void Run(base::ScopedClosureRunner notify_resource_queue_finished);

  // Initialize variables needed to read stdout.
  void SetUpStdout(mojo::ScopedHandle handle);

  // Read memtester return code and parses memtester output.
  void DetermineRoutineResult();

  // Accepts a return code and store it inside a class variable.
  void HandleGetReturnCode(int return_code);

  // Update the percentage progress of the routine.
  void UpdatePercentage();

  // Read and parse the memtester stdout from read_stdout_size_ to
  // current_stdout_size.
  void ReadNewMemtesterResult();

  // Parse the memtester output to determine the results.
  ash::cros_healthd::mojom::MemoryRoutineDetailPtr ParseMemtesterResult();

  // Calculate the percentage progress based on the current parsed output.
  std::optional<int8_t> CalculatePercentage();

  // Unowned. Should outlive this instance.
  Context* const context_ = nullptr;
  // Once the memory resource is finished (when memtester finish running), run
  // this callback to notify the resource queue of resource availability.
  base::ScopedClosureRunner notify_resource_queue_finished_;
  // A scoped version of process control that manages the lifetime of the
  // memtester process.
  ScopedProcessControl scoped_process_control_;
  // The return code of memtester process.
  int memtester_return_code_;
  // A file descriptor that points to memtester stdout to allow for real time
  // output capturing.
  base::File stdout_file_;
  // Stores the number of bytes the stdout file has been read so far.
  int64_t read_stdout_size_;
  // Stores the parsed stdout result.
  std::vector<std::vector<std::string>> parsed_memtester_result_;
  // Stores the number of kib the memtester should test for as requested by the
  // user. Has value of std::nullopt if the user did not specify.
  std::optional<uint32_t> max_testing_mem_kib_;

  // Must be the last class member.
  base::WeakPtrFactory<MemoryRoutineV2> weak_ptr_factory_{this};
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_ROUTINES_MEMORY_AND_CPU_MEMORY_V2_H_
