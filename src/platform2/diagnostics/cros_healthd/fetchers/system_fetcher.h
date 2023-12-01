// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_FETCHERS_SYSTEM_FETCHER_H_
#define DIAGNOSTICS_CROS_HEALTHD_FETCHERS_SYSTEM_FETCHER_H_

#include <string>

#include <base/files/file_path.h>
#include <base/functional/callback_forward.h>

#include "diagnostics/cros_healthd/fetchers/base_fetcher.h"
#include "diagnostics/mojom/public/cros_healthd_probe.mojom.h"

namespace diagnostics {

// Fetches system info and pass the result to the callback. Returns either a
// structure with the system information or the error that occurred fetching the
// information.
using FetchSystemInfoCallback =
    base::OnceCallback<void(ash::cros_healthd::mojom::SystemResultPtr)>;
void FetchSystemInfo(Context* context, FetchSystemInfoCallback callback);

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_FETCHERS_SYSTEM_FETCHER_H_
