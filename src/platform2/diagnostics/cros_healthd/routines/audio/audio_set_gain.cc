// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/routines/audio/audio_set_gain.h"

#include <algorithm>
#include <utility>
#include <vector>

#include <base/logging.h>
#include <chromeos/dbus/service_constants.h>
#include <cras/dbus-proxies.h>

#include "diagnostics/mojom/public/cros_healthd_diagnostics.mojom.h"

namespace diagnostics {

namespace {

namespace mojom = ::ash::cros_healthd::mojom;

}  // namespace

AudioSetGainRoutine::AudioSetGainRoutine(Context* context,
                                         uint64_t node_id,
                                         uint8_t gain)
    : node_id_(node_id), gain_(gain), context_(context) {
  gain_ = std::min(gain_, (uint8_t)100);
}

AudioSetGainRoutine::~AudioSetGainRoutine() = default;

void AudioSetGainRoutine::Start() {
  UpdateStatus(mojom::DiagnosticRoutineStatusEnum::kRunning, "");
  brillo::ErrorPtr error;

  if (!context_->cras_proxy()->SetInputNodeGain(node_id_, gain_, &error)) {
    LOG(ERROR) << "Failed to set audio input node[" << node_id_ << "] to gain["
               << gain_ << "]: " << error->GetMessage();
    UpdateStatus(mojom::DiagnosticRoutineStatusEnum::kError,
                 "Failed to set audio input node gain");
    return;
  }

  UpdateStatus(mojom::DiagnosticRoutineStatusEnum::kPassed, "");
}

void AudioSetGainRoutine::Resume() {}

void AudioSetGainRoutine::Cancel() {}

void AudioSetGainRoutine::PopulateStatusUpdate(mojom::RoutineUpdate* response,
                                               bool include_output) {
  auto status = GetStatus();

  auto update = mojom::NonInteractiveRoutineUpdate::New();
  update->status = status;
  update->status_message = GetStatusMessage();
  response->routine_update_union =
      mojom::RoutineUpdateUnion::NewNoninteractiveUpdate(std::move(update));
  if (status == mojom::DiagnosticRoutineStatusEnum::kReady ||
      status == mojom::DiagnosticRoutineStatusEnum::kRunning) {
    response->progress_percent = 0;
  } else {
    response->progress_percent = 100;
  }
}

}  // namespace diagnostics
