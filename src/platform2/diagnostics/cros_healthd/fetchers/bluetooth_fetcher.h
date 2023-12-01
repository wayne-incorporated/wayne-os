// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_FETCHERS_BLUETOOTH_FETCHER_H_
#define DIAGNOSTICS_CROS_HEALTHD_FETCHERS_BLUETOOTH_FETCHER_H_

#include "diagnostics/cros_healthd/system/context.h"
#include "diagnostics/mojom/public/cros_healthd_probe.mojom.h"

namespace diagnostics {

// Returns a structure with either the Bluetooth information or the error that
// occurred fetching the information.
ash::cros_healthd::mojom::BluetoothResultPtr FetchBluetoothInfo(
    Context* context);

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_FETCHERS_BLUETOOTH_FETCHER_H_
