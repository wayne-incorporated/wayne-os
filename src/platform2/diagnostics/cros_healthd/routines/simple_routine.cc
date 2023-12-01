// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/routines/simple_routine.h"

#include <cstdint>
#include <string>
#include <utility>

#include <base/check_op.h>
#include <base/json/json_writer.h>
#include <base/logging.h>
#include <base/strings/string_piece.h>
#include <base/strings/stringprintf.h>

#include "diagnostics/base/mojo_utils.h"
#include "diagnostics/mojom/public/cros_healthd_diagnostics.mojom.h"

namespace diagnostics {

namespace {

namespace mojom = ::ash::cros_healthd::mojom;

uint32_t CalculateProgressPercent(mojom::DiagnosticRoutineStatusEnum status) {
  // Since simple routines cannot be cancelled, the progress percent can only be
  // 0 or 100.
  if (status == mojom::DiagnosticRoutineStatusEnum::kPassed ||
      status == mojom::DiagnosticRoutineStatusEnum::kFailed ||
      status == mojom::DiagnosticRoutineStatusEnum::kError)
    return 100;
  return 0;
}

}  // namespace

SimpleRoutine::SimpleRoutine(Task task) : task_(std::move(task)) {}

SimpleRoutine::~SimpleRoutine() = default;

void SimpleRoutine::Start() {
  DCHECK_EQ(GetStatus(), mojom::DiagnosticRoutineStatusEnum::kReady);
  UpdateStatus(mojom::DiagnosticRoutineStatusEnum::kRunning, "");
  std::move(task_).Run(base::BindOnce(&SimpleRoutine::StoreRoutineResult,
                                      weak_ptr_factory_.GetWeakPtr()));
}

// Simple routines can only be started.
void SimpleRoutine::Resume() {}
void SimpleRoutine::Cancel() {}

void SimpleRoutine::PopulateStatusUpdate(mojom::RoutineUpdate* response,
                                         bool include_output) {
  auto status = GetStatus();
  // Because simple routines are non-interactive, we will never include a user
  // message.
  auto update = mojom::NonInteractiveRoutineUpdate::New();
  update->status = status;
  update->status_message = GetStatusMessage();

  response->routine_update_union =
      mojom::RoutineUpdateUnion::NewNoninteractiveUpdate(std::move(update));
  response->progress_percent = CalculateProgressPercent(status);

  if (include_output && !output_dict_.empty()) {
    std::string json;
    base::JSONWriter::Write(output_dict_, &json);
    response->output =
        CreateReadOnlySharedMemoryRegionMojoHandle(base::StringPiece(json));
  }
}

void SimpleRoutine::StoreRoutineResult(RoutineResult result) {
  UpdateStatus(result.status, std::move(result.status_message));
  output_dict_ = std::move(result.output_dict);
}

}  // namespace diagnostics
