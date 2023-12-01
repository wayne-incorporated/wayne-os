// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/routines/storage/disk_read_v2.h"

#include <algorithm>
#include <cmath>
#include <memory>
#include <utility>

#include <base/check.h>
#include <base/cancelable_callback.h>
#include <base/functional/bind.h>
#include <base/functional/callback_forward.h>
#include <base/memory/ptr_util.h>
#include <base/time/time.h>
#include <base/types/expected.h>
#include <mojo/public/cpp/bindings/callback_helpers.h>

#include "diagnostics/cros_healthd/executor/utils/scoped_process_control.h"
#include "diagnostics/cros_healthd/mojom/executor.mojom.h"
#include "diagnostics/cros_healthd/system/context.h"
#include "diagnostics/cros_healthd/utils/callback_barrier.h"
#include "diagnostics/cros_healthd/utils/mojo_utils.h"

namespace diagnostics {

namespace {

namespace mojom = ::ash::cros_healthd::mojom;

// The minimum free space size not to be in a low state during the test.
constexpr uint32_t kDiskReadRoutineReservedSpaceMiB = 1024;
// Frequency to update the routine percentage.
constexpr base::TimeDelta kDiskReadRoutineUpdatePeriod =
    base::Milliseconds(300);
// Buffer size for reading stderr from file.
constexpr size_t kStderrBufSize = 1024;
// Estimated time for fio prepare job. This value is determined arbitrarily by
// testing on the DUT.
constexpr double kFileCreationSecondsPerMiB = 0.012;
static_assert(kFileCreationSecondsPerMiB <= 1.0,
              "This value should not be higher than 1 to avoid overflow.");

}  // namespace

base::expected<std::unique_ptr<DiskReadRoutineV2>, std::string>
DiskReadRoutineV2::Create(Context* context,
                          const mojom::DiskReadRoutineArgumentPtr& arg) {
  CHECK(!arg.is_null());
  if (arg->disk_read_duration.InSeconds() <= 0) {
    return base::unexpected(
        "Disk read duration should not be zero after rounding towards zero to "
        "the nearest second");
  }

  if (arg->file_size_mib == 0) {
    return base::unexpected("Test file size should not be zero");
  }

  if (arg->type == mojom::DiskReadTypeEnum::kUnmappedEnumField) {
    return base::unexpected("Unexpected disk read type");
  }

  return base::ok(base::WrapUnique(new DiskReadRoutineV2(context, arg)));
}

DiskReadRoutineV2::DiskReadRoutineV2(
    Context* context, const mojom::DiskReadRoutineArgumentPtr& arg)
    : context_(context),
      disk_read_type_(arg->type),
      disk_read_duration_(arg->disk_read_duration),
      file_size_mib_(arg->file_size_mib),
      fio_prepare_duration_(base::Seconds(static_cast<uint32_t>(
          std::ceil(arg->file_size_mib * kFileCreationSecondsPerMiB)))) {
  CHECK(context_);
  CHECK(fio_prepare_duration_.is_positive());
}

DiskReadRoutineV2::~DiskReadRoutineV2() {
  // Remove test file if the routine unexpectedly fails.
  context_->executor()->RemoveFioTestFile(base::DoNothing());
}

void DiskReadRoutineV2::OnStart() {
  CHECK(step_ == kInitialize);
  SetRunningState();
  RunNextStep();
}

void DiskReadRoutineV2::RunNextStep() {
  step_ = static_cast<TestStep>(static_cast<int>(step_) + 1);
  start_ticks_ = base::TimeTicks::Now();
  UpdatePercentage();

  switch (step_) {
    case kInitialize:
      RaiseException("Unexpected flow in disk read routine");
      break;
    case kCleanUpBeforeTest:
    case kCleanUp:
      context_->executor()->RemoveFioTestFile(
          base::BindOnce(&DiskReadRoutineV2::HandleRemoveTestFileResponse,
                         weak_ptr_factory_.GetWeakPtr()));
      break;
    case kCheckFreeSpace:
      context_->executor()->GetFioTestDirectoryFreeSpace(
          base::BindOnce(&DiskReadRoutineV2::CheckStorageSpace,
                         weak_ptr_factory_.GetWeakPtr()));
      break;
    case kFioPrepare:
      context_->executor()->RunFio(
          mojom::FioJobArgument::NewPrepare(
              mojom::PrepareJobArgument::New(file_size_mib_)),
          scoped_process_control_prepare_.BindNewPipeAndPassReceiver());
      scoped_process_control_prepare_->GetReturnCode(
          mojo::WrapCallbackWithDefaultInvokeIfNotRun(
              base::BindOnce(
                  &DiskReadRoutineV2::HandleReturnCodeResponse,
                  weak_ptr_factory_.GetWeakPtr(),
                  std::ref(scoped_process_control_prepare_),
                  base::BindOnce(&DiskReadRoutineV2::HandleFioPrepareResponse,
                                 weak_ptr_factory_.GetWeakPtr(),
                                 std::ref(scoped_process_control_prepare_))),
              EXIT_FAILURE));
      break;
    case kFioRead:
      context_->executor()->RunFio(
          mojom::FioJobArgument::NewRead(mojom::ReadJobArgument::New(
              disk_read_duration_, disk_read_type_)),
          scoped_process_control_read_.BindNewPipeAndPassReceiver());
      scoped_process_control_read_->GetReturnCode(
          mojo::WrapCallbackWithDefaultInvokeIfNotRun(
              base::BindOnce(
                  &DiskReadRoutineV2::HandleReturnCodeResponse,
                  weak_ptr_factory_.GetWeakPtr(),
                  std::ref(scoped_process_control_read_),
                  base::BindOnce(&DiskReadRoutineV2::HandleFioReadResponse,
                                 weak_ptr_factory_.GetWeakPtr(),
                                 std::ref(scoped_process_control_read_))),
              EXIT_FAILURE));
      break;
    case kComplete:
      // The routine will pass if all fio jobs complete successfully.
      SetFinishedState(true, mojom::RoutineDetail::NewDiskRead(
                                 mojom::DiskReadRoutineDetail::New()));
      break;
  }
}

void DiskReadRoutineV2::HandleRemoveTestFileResponse(
    mojom::ExecutedProcessResultPtr result) {
  CHECK(step_ == kCleanUpBeforeTest || step_ == kCleanUp);

  if (!result->err.empty() || result->return_code != EXIT_SUCCESS) {
    LOG(ERROR) << "RemoveFioTestFile failed with return code: "
               << result->return_code << " and err: " << result->err;
    RaiseException("Failed to clean up storage");
    return;
  }
  RunNextStep();
}

void DiskReadRoutineV2::CheckStorageSpace(
    std::optional<uint64_t> free_space_byte) {
  CHECK(step_ == kCheckFreeSpace);

  if (!free_space_byte.has_value()) {
    RaiseException("Failed to retrieve free storage space");
    return;
  }
  const uint32_t free_space_mib =
      static_cast<uint32_t>(free_space_byte.value() / 1024 / 1024);

  // Ensure DUT has sufficient storage space and prevent storage space state
  // from falling into low state during test.
  if (free_space_mib < file_size_mib_ ||
      free_space_mib - file_size_mib_ < kDiskReadRoutineReservedSpaceMiB) {
    RaiseException("Failed to reserve sufficient storage space");
    return;
  }

  RunNextStep();
}

void DiskReadRoutineV2::HandleFioPrepareResponse(
    ScopedProcessControl& process_control,
    int return_code,
    const std::string& err) {
  CHECK(step_ == kFioPrepare);

  process_control.Reset();
  if (!err.empty() || return_code != EXIT_SUCCESS) {
    LOG(ERROR) << "RunFioPrepare failed with return code: " << return_code
               << " and error: " << err;
    RaiseException("Failed to complete fio prepare job");
    return;
  }

  percentage_update_task_.Cancel();
  SetPercentage(50);
  RunNextStep();
}

void DiskReadRoutineV2::HandleFioReadResponse(
    ScopedProcessControl& process_control,
    int return_code,
    const std::string& err) {
  CHECK(step_ == kFioRead);

  process_control.Reset();
  if (!err.empty() || return_code != EXIT_SUCCESS) {
    LOG(ERROR) << "RunFioRead failed with return code: " << return_code
               << " and error: " << err;
    RaiseException("Failed to complete fio read job");
    return;
  }

  percentage_update_task_.Cancel();
  RunNextStep();
}

void DiskReadRoutineV2::HandleReturnCodeResponse(
    ScopedProcessControl& process_control,
    base::OnceCallback<void(int, const std::string&)> response_cb,
    int return_code) {
  process_control->GetStderr(mojo::WrapCallbackWithDefaultInvokeIfNotRun(
      base::BindOnce(&DiskReadRoutineV2::HandleStderrResponse,
                     weak_ptr_factory_.GetWeakPtr(),
                     base::BindOnce(std::move(response_cb), return_code)),
      mojo::ScopedHandle()));
}

void DiskReadRoutineV2::HandleStderrResponse(
    base::OnceCallback<void(const std::string&)> response_cb,
    mojo::ScopedHandle handle) {
  auto stderr_fd = mojo_utils::UnwrapMojoHandle(std::move(handle));
  if (!stderr_fd.is_valid()) {
    std::move(response_cb).Run("Failed to access fio stderr");
    return;
  }

  auto stderr_file = base::File(std::move(stderr_fd));
  // We only care about at most the first |kStderrBufSize| bytes of stderr.
  char buf[kStderrBufSize];
  int64_t stderr_file_len = stderr_file.GetLength();
  if (stderr_file_len < 0) {
    std::move(response_cb).Run("Failed to read fio stderr");
    return;
  }

  int read_len = stderr_file.Read(
      0, buf, std::min(static_cast<int64_t>(kStderrBufSize), stderr_file_len));
  if (read_len < 0) {
    std::move(response_cb).Run("Failed to read fio stderr");
    return;
  }

  std::move(response_cb).Run(std::string(buf, read_len));
}

void DiskReadRoutineV2::UpdatePercentage() {
  base::TimeDelta expected_running_time;
  switch (step_) {
    case kFioPrepare:
      expected_running_time = fio_prepare_duration_;
      break;
    case kFioRead:
      expected_running_time = disk_read_duration_;
      break;
    case kInitialize:
    case kCleanUpBeforeTest:
    case kCleanUp:
    case kCheckFreeSpace:
    case kComplete:
      // We don't update percentage during other steps.
      return;
  }
  CHECK(expected_running_time.is_positive());

  double running_time_ratio =
      (base::TimeTicks::Now() - start_ticks_) / expected_running_time;
  // The routine has two stages. Each stage is 50 percentage.
  int new_percentage = std::min(49, static_cast<int>(50 * running_time_ratio));
  if (new_percentage < 49) {
    percentage_update_task_.Reset(base::BindOnce(
        &DiskReadRoutineV2::UpdatePercentage, weak_ptr_factory_.GetWeakPtr()));
    base::SingleThreadTaskRunner::GetCurrentDefault()->PostDelayedTask(
        FROM_HERE, percentage_update_task_.callback(),
        kDiskReadRoutineUpdatePeriod);
  }

  // Update the percentage if the fio prepare job is finished.
  if (step_ == kFioRead)
    new_percentage += 50;

  // Update the percentage.
  if (new_percentage > state()->percentage && new_percentage < 100)
    SetPercentage(new_percentage);
}

}  // namespace diagnostics
