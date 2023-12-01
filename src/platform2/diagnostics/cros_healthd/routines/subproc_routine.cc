// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/routines/subproc_routine.h"

#include <algorithm>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/check_op.h>
#include <base/logging.h>
#include <base/process/process_handle.h>
#include <base/strings/string_util.h>
#include <base/time/time.h>

#include "diagnostics/cros_healthd/routines/diag_process_adapter_impl.h"

namespace diagnostics {

namespace mojom = ::ash::cros_healthd::mojom;

constexpr char kSubprocRoutineCancelledMessage[] = "The routine was cancelled.";
constexpr char kSubprocRoutineErrorMessage[] =
    "The routine crashed or was killed.";
constexpr char kSubprocRoutineFailedMessage[] = "Routine failed.";
constexpr char kSubprocRoutineFailedToLaunchProcessMessage[] =
    "Could not launch the process.";
constexpr char kSubprocRoutineFailedToStopMessage[] =
    "Failed to stop the routine.";
constexpr char kSubprocRoutineProcessCancellingMessage[] =
    "Cancelled routine. Waiting for cleanup...";
constexpr char kSubprocRoutineProcessRunningMessage[] =
    "Routine is still running.";
constexpr char kSubprocRoutineReadyMessage[] = "Routine is ready.";
constexpr char kSubprocRoutineSucceededMessage[] = "Routine passed.";

constexpr uint32_t kSubprocRoutineFakeProgressPercentUnknown = 33;

mojom::DiagnosticRoutineStatusEnum
GetDiagnosticRoutineStatusFromSubprocRoutineStatus(
    SubprocRoutine::SubprocStatus subproc_status) {
  switch (subproc_status) {
    case SubprocRoutine::kSubprocStatusReady:
      return mojom::DiagnosticRoutineStatusEnum::kReady;
    case SubprocRoutine::kSubprocStatusLaunchFailed:
      return mojom::DiagnosticRoutineStatusEnum::kFailedToStart;
    case SubprocRoutine::kSubprocStatusRunning:
      return mojom::DiagnosticRoutineStatusEnum::kRunning;
    case SubprocRoutine::kSubprocStatusCancelling:
      return mojom::DiagnosticRoutineStatusEnum::kCancelling;
    case SubprocRoutine::kSubprocStatusCompleteSuccess:
      return mojom::DiagnosticRoutineStatusEnum::kPassed;
    case SubprocRoutine::kSubprocStatusCompleteFailure:
      return mojom::DiagnosticRoutineStatusEnum::kFailed;
    case SubprocRoutine::kSubprocStatusError:
      return mojom::DiagnosticRoutineStatusEnum::kError;
    case SubprocRoutine::kSubprocStatusCancelled:
      return mojom::DiagnosticRoutineStatusEnum::kCancelled;
  }
}

std::string GetStatusMessageFromSubprocRoutineStatus(
    SubprocRoutine::SubprocStatus subproc_status) {
  switch (subproc_status) {
    case SubprocRoutine::kSubprocStatusReady:
      return kSubprocRoutineReadyMessage;
    case SubprocRoutine::kSubprocStatusLaunchFailed:
      return kSubprocRoutineFailedToLaunchProcessMessage;
    case SubprocRoutine::kSubprocStatusRunning:
      return kSubprocRoutineProcessRunningMessage;
    case SubprocRoutine::kSubprocStatusCancelling:
      return kSubprocRoutineProcessCancellingMessage;
    case SubprocRoutine::kSubprocStatusCompleteSuccess:
      return kSubprocRoutineSucceededMessage;
    case SubprocRoutine::kSubprocStatusCompleteFailure:
      return kSubprocRoutineFailedMessage;
    case SubprocRoutine::kSubprocStatusError:
      return kSubprocRoutineErrorMessage;
    case SubprocRoutine::kSubprocStatusCancelled:
      return kSubprocRoutineCancelledMessage;
  }
}

SubprocRoutine::SubprocRoutine(const base::CommandLine& command_line,
                               base::TimeDelta predicted_duration)
    : SubprocRoutine(std::make_unique<DiagProcessAdapterImpl>(),
                     std::make_unique<base::DefaultTickClock>(),
                     std::list<base::CommandLine>{command_line},
                     predicted_duration) {}

SubprocRoutine::SubprocRoutine(
    const std::list<base::CommandLine>& command_lines,
    base::TimeDelta total_predicted_duration)
    : SubprocRoutine(std::make_unique<DiagProcessAdapterImpl>(),
                     std::make_unique<base::DefaultTickClock>(),
                     command_lines,
                     total_predicted_duration) {}

SubprocRoutine::SubprocRoutine(
    std::unique_ptr<DiagProcessAdapter> process_adapter,
    std::unique_ptr<base::TickClock> tick_clock,
    const std::list<base::CommandLine>& command_lines,
    base::TimeDelta predicted_duration)
    : subproc_status_(kSubprocStatusReady),
      process_adapter_(std::move(process_adapter)),
      tick_clock_(std::move(tick_clock)),
      command_lines_(std::move(command_lines)),
      predicted_duration_(predicted_duration) {}

SubprocRoutine::~SubprocRoutine() {
  // If the routine is still running, make sure to stop it so we aren't left
  // with a zombie process.
  KillProcess(true /*from_dtor*/);
  if (!post_stop_callback_.is_null())
    std::move(post_stop_callback_).Run();
}

void SubprocRoutine::Start() {
  DCHECK_EQ(handle_, base::kNullProcessHandle);

  bool pre_start_callback_result = true;
  if (!pre_start_callback_.is_null())
    pre_start_callback_result = std::move(pre_start_callback_).Run();

  if (!pre_start_callback_result) {
    UpdateSubprocessStatus(kSubprocStatusLaunchFailed);
    LOG(ERROR) << kSubprocRoutineFailedToLaunchProcessMessage;
    return;
  }
  StartProcess();
}

void SubprocRoutine::Resume() {
  // Resume functionality is intended to be used by interactive routines.
  // Subprocess routines are non-interactive.
  LOG(ERROR) << "SubprocRoutine::Resume : subprocess diagnostic routines "
                "cannot be resumed";
}

void SubprocRoutine::Cancel() {
  KillProcess(false /*from_dtor*/);
}

void SubprocRoutine::PopulateStatusUpdate(mojom::RoutineUpdate* response,
                                          bool include_output) {
  // Because the subproc_routine routine is non-interactive, we will never
  // include a user message.
  CheckProcessStatus();

  auto update = mojom::NonInteractiveRoutineUpdate::New();
  update->status =
      GetDiagnosticRoutineStatusFromSubprocRoutineStatus(subproc_status_);
  update->status_message =
      GetStatusMessageFromSubprocRoutineStatus(subproc_status_);

  response->routine_update_union =
      mojom::RoutineUpdateUnion::NewNoninteractiveUpdate(std::move(update));
  response->progress_percent = CalculateProgressPercent();
}

mojom::DiagnosticRoutineStatusEnum SubprocRoutine::GetStatus() {
  CheckProcessStatus();
  return GetDiagnosticRoutineStatusFromSubprocRoutineStatus(subproc_status_);
}

void SubprocRoutine::RegisterStatusChangedCallback(
    StatusChangedCallback callback) {
  status_changed_callbacks_.push_back(std::move(callback));
}

void SubprocRoutine::RegisterPreStartCallback(
    base::OnceCallback<bool()> callback) {
  DCHECK(pre_start_callback_.is_null());
  pre_start_callback_ = std::move(callback);
}

void SubprocRoutine::RegisterPostStopCallback(base::OnceClosure callback) {
  DCHECK(post_stop_callback_.is_null());
  post_stop_callback_ = std::move(callback);
}

void SubprocRoutine::StartProcess() {
  DCHECK_EQ(command_lines_.empty(), false);
  DCHECK(subproc_status_ == kSubprocStatusReady ||
         subproc_status_ == kSubprocStatusRunning);
  if (subproc_status_ == kSubprocStatusReady) {
    // Keep track of when we began the routine, in case we need to predict
    // progress.
    start_ticks_ = tick_clock_->NowTicks();
    UpdateSubprocessStatus(kSubprocStatusRunning);
  }

  // Multiple executables will be run in sequence and one at a time.
  auto command_line = command_lines_.front();
  command_lines_.pop_front();

  VLOG(1) << "Starting command " << base::JoinString(command_line.argv(), " ");

  if (!process_adapter_->StartProcess(command_line.argv(), &handle_)) {
    UpdateSubprocessStatus(kSubprocStatusLaunchFailed);
    LOG(ERROR) << kSubprocRoutineFailedToLaunchProcessMessage;
  }
}

void SubprocRoutine::KillProcess(bool from_dtor) {
  CheckProcessStatus();

  switch (subproc_status_) {
    case kSubprocStatusRunning:
      DCHECK(handle_ != base::kNullProcessHandle);
      if (from_dtor) {
        // We will not be able to keep track of this child process.
        LOG(ERROR) << "Cancelling process " << handle_
                   << " from diagnostics::SubprocRoutine destructor, cannot "
                      "guarantee process will die.";
      }
      UpdateSubprocessStatus(kSubprocStatusCancelling);
      process_adapter_->KillProcess(handle_);
      break;
    case kSubprocStatusCancelling:
      // The process is already being killed. Do nothing.
      DCHECK_NE(handle_, base::kNullProcessHandle);
      break;
    case kSubprocStatusCancelled:
    case kSubprocStatusCompleteFailure:
    case kSubprocStatusCompleteSuccess:
    case kSubprocStatusError:
    case kSubprocStatusLaunchFailed:
    case kSubprocStatusReady:
      // If the process has already exited, is exiting, or never started,
      // there's no need to kill it.
      DCHECK_EQ(handle_, base::kNullProcessHandle);
      break;
  }
}

void SubprocRoutine::UpdateSubprocessStatus(SubprocStatus subproc_status) {
  auto old_routine_status =
      GetDiagnosticRoutineStatusFromSubprocRoutineStatus(subproc_status_);
  auto new_routine_status =
      GetDiagnosticRoutineStatusFromSubprocRoutineStatus(subproc_status);

  subproc_status_ = subproc_status;

  if (new_routine_status != old_routine_status) {
    for (const auto& callback : status_changed_callbacks_) {
      callback.Run(new_routine_status);
    }
  }
}

void SubprocRoutine::CheckActiveProcessStatus() {
  DCHECK_NE(handle_, base::kNullProcessHandle);
  switch (process_adapter_->GetStatus(handle_)) {
    case base::TERMINATION_STATUS_STILL_RUNNING:
      DCHECK(subproc_status_ == kSubprocStatusCancelling ||
             subproc_status_ == kSubprocStatusRunning);
      break;
    case base::TERMINATION_STATUS_NORMAL_TERMINATION:
      // The process is gone.
      handle_ = base::kNullProcessHandle;
      if (subproc_status_ == kSubprocStatusCancelling) {
        UpdateSubprocessStatus(kSubprocStatusCancelled);
      } else {
        if (command_lines_.size())
          StartProcess();
        else
          UpdateSubprocessStatus(kSubprocStatusCompleteSuccess);
      }
      break;
    case base::TERMINATION_STATUS_ABNORMAL_TERMINATION:
      // The process is gone.
      handle_ = base::kNullProcessHandle;

      UpdateSubprocessStatus((subproc_status_ == kSubprocStatusCancelling)
                                 ? kSubprocStatusCancelled
                                 : kSubprocStatusCompleteFailure);
      break;
    case base::TERMINATION_STATUS_LAUNCH_FAILED:
      // The process never really was.
      handle_ = base::kNullProcessHandle;

      UpdateSubprocessStatus(kSubprocStatusLaunchFailed);
      break;
    default:
      // The process is mysteriously just missing.
      handle_ = base::kNullProcessHandle;
      UpdateSubprocessStatus(kSubprocStatusError);
      break;
  }
}

void SubprocRoutine::CheckProcessStatus() {
  switch (subproc_status_) {
    case kSubprocStatusCancelled:
    case kSubprocStatusCompleteFailure:
    case kSubprocStatusCompleteSuccess:
    case kSubprocStatusError:
    case kSubprocStatusLaunchFailed:
    case kSubprocStatusReady:
      DCHECK_EQ(handle_, base::kNullProcessHandle);
      break;
    case kSubprocStatusCancelling:
    case kSubprocStatusRunning:
      CheckActiveProcessStatus();
      break;
  }
}

uint32_t SubprocRoutine::CalculateProgressPercent() {
  switch (subproc_status_) {
    case kSubprocStatusCompleteSuccess:
    case kSubprocStatusCompleteFailure:
      last_reported_progress_percent_ = 100;
      break;
    case kSubprocStatusRunning:
      if (predicted_duration_.is_zero()) {
        /* when we don't know the progress, we fake at a low percentage */
        last_reported_progress_percent_ =
            kSubprocRoutineFakeProgressPercentUnknown;
      } else {
        last_reported_progress_percent_ = std::min<uint32_t>(
            100, std::max<uint32_t>(
                     0, static_cast<uint32_t>(
                            100 * (tick_clock_->NowTicks() - start_ticks_) /
                            predicted_duration_)));
      }
      break;
    case kSubprocStatusCancelled:
    case kSubprocStatusCancelling:
    case kSubprocStatusError:
    case kSubprocStatusLaunchFailed:
    case kSubprocStatusReady:
      break;
  }
  return last_reported_progress_percent_;
}

}  // namespace diagnostics
