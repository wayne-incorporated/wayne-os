// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_FETCHERS_SENSOR_FETCHER_H_
#define DIAGNOSTICS_CROS_HEALTHD_FETCHERS_SENSOR_FETCHER_H_

#include "diagnostics/cros_healthd/system/context.h"
#include "diagnostics/mojom/public/cros_healthd_probe.mojom.h"

namespace diagnostics {

// Fetch sensor info and pass the result to the callback.
using FetchSensorInfoCallback =
    base::OnceCallback<void(ash::cros_healthd::mojom::SensorResultPtr)>;
void FetchSensorInfo(Context* context, FetchSensorInfoCallback callback);

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_FETCHERS_SENSOR_FETCHER_H_
