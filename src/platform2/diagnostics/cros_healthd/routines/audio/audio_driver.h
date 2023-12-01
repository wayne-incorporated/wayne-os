// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_ROUTINES_AUDIO_AUDIO_DRIVER_H_
#define DIAGNOSTICS_CROS_HEALTHD_ROUTINES_AUDIO_AUDIO_DRIVER_H_

#include "diagnostics/cros_healthd/routines/base_routine_control.h"
#include "diagnostics/cros_healthd/system/context.h"
#include "diagnostics/mojom/public/cros_healthd_routines.mojom.h"

namespace diagnostics {

// The audio driver routine checks that the device's audio driver is working
// correctly.
class AudioDriverRoutine final : public BaseRoutineControl {
 public:
  explicit AudioDriverRoutine(
      Context* context,
      const ash::cros_healthd::mojom::AudioDriverRoutineArgumentPtr& arg);
  AudioDriverRoutine(const AudioDriverRoutine&) = delete;
  AudioDriverRoutine& operator=(const AudioDriverRoutine&) = delete;
  ~AudioDriverRoutine() override;

  // BaseRoutineControl overrides:
  void OnStart() override;

 private:
  // Check if CRAS can detect at least one internal audio card.
  // Return false when there is any error when calling the CRAS D-Bus API.
  bool CheckInternalCardDetected(bool& internal_card_detected);

  // Check if all audio devices succeed to open. As long as any of the audio
  // device fails to open, |audio_devices_succeed_to_open| will be set to false.
  // Return false when there is any error when calling the CRAS D-Bus API.
  bool CheckAudioDevicesSucceedToOpen(bool& audio_devices_succeed_to_open);

  // Unowned. Should outlive this instance.
  Context* const context_ = nullptr;
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_ROUTINES_AUDIO_AUDIO_DRIVER_H_
