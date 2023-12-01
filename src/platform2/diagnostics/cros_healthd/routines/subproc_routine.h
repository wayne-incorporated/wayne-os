// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_ROUTINES_SUBPROC_ROUTINE_H_
#define DIAGNOSTICS_CROS_HEALTHD_ROUTINES_SUBPROC_ROUTINE_H_

#include <cstdint>
#include <list>
#include <memory>
#include <string>
#include <vector>

#include <base/command_line.h>
#include <base/process/process.h>
#include <base/time/default_tick_clock.h>
#include <base/time/time.h>

#include "diagnostics/cros_healthd/routines/diag_process_adapter.h"
#include "diagnostics/cros_healthd/routines/diag_routine.h"

namespace diagnostics {

// Output messages for the routine when in various states.
extern const char kSubprocRoutineCancelledMessage[];
extern const char kSubprocRoutineErrorMessage[];
extern const char kSubprocRoutineFailedMessage[];
extern const char kSubprocRoutineFailedToLaunchProcessMessage[];
extern const char kSubprocRoutineFailedToStopMessage[];
extern const char kSubprocRoutineProcessCancellingMessage[];
extern const char kSubprocRoutineProcessRunningMessage[];
extern const char kSubprocRoutineReadyMessage[];
extern const char kSubprocRoutineSucceededMessage[];

// We don't always know when a SubprocRoutine should finish. Sometimes we have
// to fake our prediction of percent complete.
extern const uint32_t kSubprocRoutineFakeProgressPercentUnknown;

// The SubprocRoutine takes a command line to run. It is non-interactive, and
// this does not fully support Pause and Resume. Pause will simply kill the
// process. The exit code of the process is used to determine success or failure
// of the test. So, the "check" portion of the Routine must live inside the
// sub-process.
class SubprocRoutine final : public DiagnosticRoutine {
 public:
  // The state of the SubprocRoutine is modeled in the SubprocStatus enum.
  enum SubprocStatus {
    kSubprocStatusCancelled,
    kSubprocStatusCancelling,
    kSubprocStatusCompleteFailure,
    kSubprocStatusCompleteSuccess,
    kSubprocStatusError,
    kSubprocStatusLaunchFailed,
    kSubprocStatusReady,
    kSubprocStatusRunning,
  };

  // Constructor to run a single executable.
  SubprocRoutine(const base::CommandLine& command_line,
                 base::TimeDelta predicted_duration);
  // Constructor to run multiple executables.
  SubprocRoutine(const std::list<base::CommandLine>& command_lines,
                 base::TimeDelta predicted_duration);
  // Constructor only for facilitating the unit test.
  SubprocRoutine(std::unique_ptr<DiagProcessAdapter> process_adapter,
                 std::unique_ptr<base::TickClock> tick_clock,
                 const std::list<base::CommandLine>& command_lines,
                 base::TimeDelta predicted_duration);
  SubprocRoutine(const SubprocRoutine&) = delete;
  SubprocRoutine& operator=(const SubprocRoutine&) = delete;
  ~SubprocRoutine() override;

  // DiagnosticRoutine overrides:
  void Start() override;
  void Resume() override;
  void Cancel() override;
  void PopulateStatusUpdate(ash::cros_healthd::mojom::RoutineUpdate* response,
                            bool include_output) override;
  ash::cros_healthd::mojom::DiagnosticRoutineStatusEnum GetStatus() override;
  void RegisterStatusChangedCallback(StatusChangedCallback callback) override;

  // Registers a callback that will execute before processes start. The routine
  // will stop and set status to failure if this callback returns false.
  // This function should be called only once.
  void RegisterPreStartCallback(base::OnceCallback<bool()> callback);
  // Registers a callback that will execute after process is finished.
  // This function should be called only once.
  void RegisterPostStopCallback(base::OnceClosure callback);

 private:
  // Functions to manipulate the child process.
  void StartProcess();
  void KillProcess(bool from_dtor);
  // Handle state transitions due to process state within this object.
  void UpdateSubprocessStatus(SubprocStatus subproc_status);
  void CheckProcessStatus();
  void CheckActiveProcessStatus();
  uint32_t CalculateProgressPercent();

  // |subproc_status_| is the state of the subproc as understood by the
  // SubprocRoutine object's state machine. Essentially, this variable stores
  // which state we are in.
  SubprocStatus subproc_status_;

  // |pre_start_callback_| can be registered via RegisterPreStartCallback()
  base::OnceCallback<bool()> pre_start_callback_;

  // |post_stop_callback_| can be registered via RegisterPostStopCallback()
  base::OnceClosure post_stop_callback_;

  // |process_adapter_| is a dependency that is injected at object creation time
  // which enables swapping out process control functionality for the main
  // purpose of facilitating Unit tests.
  std::unique_ptr<DiagProcessAdapter> process_adapter_;

  // |tick_clock_| is a dependency that is injected at object creation time
  // which enables swapping out time-tracking functionality for the main
  // purpose of facilitating Unit tests.
  std::unique_ptr<base::TickClock> tick_clock_;

  // |command_lines_| is a list of processes which run to test the diagnostic
  // in question.
  std::list<base::CommandLine> command_lines_;

  // |predicted_duration_| is used to calculate progress percentage when it is
  // non-zero.
  base::TimeDelta predicted_duration_{};

  // |last_reported_progress_percent_| is used to save the last reported
  // progress percentage for handling progress reported across status changes.
  uint32_t last_reported_progress_percent_ = 0;

  // |handle_| keeps track of the running process.
  base::ProcessHandle handle_ = base::kNullProcessHandle;

  // |start_ticks_| records the time when the routine began. This is used with
  // |predicted_duration_| to report on progress percentate.
  base::TimeTicks start_ticks_;

  // Callbacks to invoke when the routine status changes.
  std::vector<StatusChangedCallback> status_changed_callbacks_;
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_ROUTINES_SUBPROC_ROUTINE_H_
