// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_ROUTINES_AUDIO_AUDIO_SET_GAIN_H_
#define DIAGNOSTICS_CROS_HEALTHD_ROUTINES_AUDIO_AUDIO_SET_GAIN_H_

#include <string>

#include "diagnostics/cros_healthd/routines/diag_routine_with_status.h"
#include "diagnostics/cros_healthd/system/context.h"

namespace diagnostics {

class AudioSetGainRoutine final : public DiagnosticRoutineWithStatus {
 public:
  explicit AudioSetGainRoutine(Context* context,
                               uint64_t node_id,
                               uint8_t gain);
  AudioSetGainRoutine(const AudioSetGainRoutine&) = delete;
  AudioSetGainRoutine& operator=(const AudioSetGainRoutine&) = delete;

  // DiagnosticRoutine overrides:
  ~AudioSetGainRoutine() override;
  void Start() override;
  void Resume() override;
  void Cancel() override;
  void PopulateStatusUpdate(ash::cros_healthd::mojom::RoutineUpdate* response,
                            bool include_output) override;

 private:
  // Tartget node id.
  uint64_t node_id_;
  // Target gain value.
  uint8_t gain_;
  // Context object used to communicate with the executor.
  Context* context_;
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_ROUTINES_AUDIO_AUDIO_SET_GAIN_H_
