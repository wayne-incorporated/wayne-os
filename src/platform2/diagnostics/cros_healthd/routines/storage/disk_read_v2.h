// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_ROUTINES_STORAGE_DISK_READ_V2_H_
#define DIAGNOSTICS_CROS_HEALTHD_ROUTINES_STORAGE_DISK_READ_V2_H_

#include <memory>
#include <string>

#include <base/cancelable_callback.h>
#include <base/files/file.h>
#include <base/files/file_path.h>
#include <base/memory/weak_ptr.h>
#include <base/time/tick_clock.h>
#include <base/types/expected.h>

#include "diagnostics/cros_healthd/executor/utils/scoped_process_control.h"
#include "diagnostics/cros_healthd/mojom/executor.mojom.h"
#include "diagnostics/cros_healthd/routines/base_routine_control.h"
#include "diagnostics/cros_healthd/system/context.h"
#include "diagnostics/mojom/public/cros_healthd_routines.mojom.h"

namespace diagnostics {

// The disk read routine create a test file with md5 checksum and read the test
// file either randomly or linearly for a dedicated duration.
class DiskReadRoutineV2 final : public BaseRoutineControl {
 public:
  static base::expected<std::unique_ptr<DiskReadRoutineV2>, std::string> Create(
      Context* context,
      const ash::cros_healthd::mojom::DiskReadRoutineArgumentPtr& arg);
  DiskReadRoutineV2(const DiskReadRoutineV2&) = delete;
  DiskReadRoutineV2& operator=(const DiskReadRoutineV2&) = delete;
  ~DiskReadRoutineV2() override;

  // BaseRoutineControl overrides:
  void OnStart() override;

 protected:
  explicit DiskReadRoutineV2(
      Context* context,
      const ash::cros_healthd::mojom::DiskReadRoutineArgumentPtr& arg);

 private:
  void RunNextStep();

  // Handle the response of cleaning fio test file from the executor.
  void HandleRemoveTestFileResponse(
      ash::cros_healthd::mojom::ExecutedProcessResultPtr result);

  // Handle the response of free disk space of cache directory from the executor
  // and check if the storage is sufficient to run the routine.
  void CheckStorageSpace(std::optional<uint64_t> free_space_byte);

  // Handle the response of running fio prepare from the executor.
  void HandleFioPrepareResponse(ScopedProcessControl& process_control,
                                int return_code,
                                const std::string& err);

  // Handle the response of running fio read from the executor.
  void HandleFioReadResponse(ScopedProcessControl& process_control,
                             int return_code,
                             const std::string& err);

  // Handle the response of fio return code.
  void HandleReturnCodeResponse(
      ScopedProcessControl& process_control,
      base::OnceCallback<void(int, const std::string&)> response_cb,
      int return_code);

  // Handle the response of fio stderr.
  void HandleStderrResponse(
      base::OnceCallback<void(const std::string&)> response_cb,
      mojo::ScopedHandle handle);

  // Update the routine percentage.
  void UpdatePercentage();

  // Unowned. Should outlive this instance.
  Context* const context_ = nullptr;

  // A scoped version of process control that manages the lifetime of the fio
  // process.
  ScopedProcessControl scoped_process_control_prepare_;
  ScopedProcessControl scoped_process_control_read_;

  // Routine arguments:
  // Type of how disk reading is performed, either linear or random.
  const ash::cros_healthd::mojom::DiskReadTypeEnum disk_read_type_;
  // Expected duration to read the test file.
  const base::TimeDelta disk_read_duration_;
  // Test file size, in megabytes (MiB), to test with the routine
  const uint32_t file_size_mib_;

  // Start time of each step, used to calculate the progress percentage.
  base::TimeTicks start_ticks_;

  // Expected duration for fio to prepare the test file.
  const base::TimeDelta fio_prepare_duration_;

  enum TestStep {
    kInitialize = 0,
    kCleanUpBeforeTest = 1,
    kCheckFreeSpace = 2,
    kFioPrepare = 3,
    kFioRead = 4,
    kCleanUp = 5,
    kComplete = 6,  // Should be the last one. New step should be added before
                    // it.
  };
  TestStep step_ = TestStep::kInitialize;

  // Cancelable task to update the routine percentage.
  base::CancelableOnceClosure percentage_update_task_;

  // Must be the last class member.
  base::WeakPtrFactory<DiskReadRoutineV2> weak_ptr_factory_{this};
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_ROUTINES_STORAGE_DISK_READ_V2_H_
