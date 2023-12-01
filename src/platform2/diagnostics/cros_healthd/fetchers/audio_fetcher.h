// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_FETCHERS_AUDIO_FETCHER_H_
#define DIAGNOSTICS_CROS_HEALTHD_FETCHERS_AUDIO_FETCHER_H_

#include "diagnostics/cros_healthd/system/context.h"
#include "diagnostics/mojom/public/cros_healthd_probe.mojom.h"

namespace diagnostics {

// Fetch audio info and pass the result to the callback. The result is either
// the device's audio info or the error that occurred fetching the information.
using FetchAudioInfoCallback =
    base::OnceCallback<void(ash::cros_healthd::mojom::AudioResultPtr)>;
void FetchAudioInfo(Context* context, FetchAudioInfoCallback callback);

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_FETCHERS_AUDIO_FETCHER_H_
