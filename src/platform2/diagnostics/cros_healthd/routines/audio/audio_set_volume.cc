// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/routines/audio/audio_set_volume.h"

#include <algorithm>
#include <utility>
#include <vector>

#include <base/logging.h>
#include <chromeos/dbus/service_constants.h>
#include <cras/dbus-proxies.h>

#include "diagnostics/mojom/external/cros_healthd_internal.mojom.h"
#include "diagnostics/mojom/public/cros_healthd_diagnostics.mojom.h"

namespace diagnostics {

namespace {

namespace mojom = ::ash::cros_healthd::mojom;

}  // namespace

AudioSetVolumeRoutine::AudioSetVolumeRoutine(Context* context,
                                             uint64_t node_id,
                                             uint8_t volume,
                                             bool mute_on)
    : node_id_(node_id), volume_(volume), mute_on_(mute_on), context_(context) {
  DCHECK(context_);
  volume_ = std::min(volume_, (uint8_t)100);
}

AudioSetVolumeRoutine::~AudioSetVolumeRoutine() = default;

void AudioSetVolumeRoutine::Start() {
  UpdateStatus(mojom::DiagnosticRoutineStatusEnum::kRunning, "");

  brillo::ErrorPtr error;
  if (!context_->cras_proxy()->SetOutputNodeVolume(node_id_, volume_, &error)) {
    LOG(ERROR) << "Failed to set audio active output node[" << node_id_
               << "] to volume[" << volume_ << "]: " << error->GetMessage();
    UpdateStatus(mojom::DiagnosticRoutineStatusEnum::kError,
                 "Failed to set audio active output node volume");
    return;
  }

  context_->mojo_service()->GetChromiumDataCollector()->SetAudioOutputMute(
      mute_on_,
      base::BindOnce(&AudioSetVolumeRoutine::SetAudioOutputMuteCallback,
                     weak_ptr_factory_.GetWeakPtr()));
}

void AudioSetVolumeRoutine::Resume() {}

void AudioSetVolumeRoutine::Cancel() {}

void AudioSetVolumeRoutine::PopulateStatusUpdate(mojom::RoutineUpdate* response,
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

void AudioSetVolumeRoutine::SetAudioOutputMuteCallback(bool success) {
  if (success) {
    UpdateStatus(mojom::DiagnosticRoutineStatusEnum::kPassed, "");
  } else {
    UpdateStatus(mojom::DiagnosticRoutineStatusEnum::kError,
                 "Failed to unmute audio output. (Force muted)");
  }
}

}  // namespace diagnostics
