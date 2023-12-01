// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_DELEGATE_FETCHERS_DISPLAY_FETCHER_H_
#define DIAGNOSTICS_CROS_HEALTHD_DELEGATE_FETCHERS_DISPLAY_FETCHER_H_

#include "diagnostics/mojom/public/cros_healthd_probe.mojom.h"

namespace diagnostics {

// Returns a structure with either the device's display info or the
// error that occurred fetching the information.
ash::cros_healthd::mojom::DisplayResultPtr GetDisplayInfo();

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_DELEGATE_FETCHERS_DISPLAY_FETCHER_H_
