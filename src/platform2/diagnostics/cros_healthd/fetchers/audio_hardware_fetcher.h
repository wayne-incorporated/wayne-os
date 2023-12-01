// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_FETCHERS_AUDIO_HARDWARE_FETCHER_H_
#define DIAGNOSTICS_CROS_HEALTHD_FETCHERS_AUDIO_HARDWARE_FETCHER_H_

#include "diagnostics/cros_healthd/system/context.h"
#include "diagnostics/mojom/public/cros_healthd_probe.mojom.h"

namespace diagnostics {

// Fetch audio hardware info and pass the result to the callback.
using FetchAudioHardwareInfoCallback =
    base::OnceCallback<void(ash::cros_healthd::mojom::AudioHardwareResultPtr)>;
void FetchAudioHardwareInfo(Context* context,
                            FetchAudioHardwareInfoCallback callback);

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_FETCHERS_AUDIO_HARDWARE_FETCHER_H_
