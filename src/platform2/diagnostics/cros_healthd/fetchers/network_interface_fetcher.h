// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_FETCHERS_NETWORK_INTERFACE_FETCHER_H_
#define DIAGNOSTICS_CROS_HEALTHD_FETCHERS_NETWORK_INTERFACE_FETCHER_H_

#include <base/files/file_path.h>
#include <base/functional/callback_forward.h>
#include <base/memory/weak_ptr.h>
#include <string>
#include <vector>

#include "diagnostics/cros_healthd/mojom/executor.mojom.h"
#include "diagnostics/mojom/public/cros_healthd_probe.mojom.h"

namespace diagnostics {

class Context;

using FetchNetworkInterfaceInfoCallback = base::OnceCallback<void(
    ash::cros_healthd::mojom::NetworkInterfaceResultPtr)>;
void FetchNetworkInterfaceInfo(Context* context,
                               FetchNetworkInterfaceInfoCallback callback);

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_FETCHERS_NETWORK_INTERFACE_FETCHER_H_
