// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/fetchers/network_fetcher.h"

#include <optional>
#include <utility>

#include <base/check.h>
#include <base/functional/callback.h>

#include "diagnostics/cros_healthd/utils/error_utils.h"
#include "diagnostics/mojom/external/network_health_types.mojom.h"
#include "diagnostics/mojom/public/cros_healthd_probe.mojom.h"

namespace diagnostics {

namespace {

namespace cros_healthd_ipc = ::ash::cros_healthd::mojom;
namespace network_health_ipc = ::chromeos::network_health::mojom;

// Forwards the response from Chrome's NetworkHealthService to the caller.
void HandleNetworkInfoResponse(
    base::OnceCallback<void(cros_healthd_ipc::NetworkResultPtr)> callback,
    std::optional<network_health_ipc::NetworkHealthStatePtr> result) {
  if (result == std::nullopt) {
    std::move(callback).Run(cros_healthd_ipc::NetworkResult::NewError(
        CreateAndLogProbeError(cros_healthd_ipc::ErrorType::kServiceUnavailable,
                               "Network Health Service unavailable")));
    return;
  }

  auto info = cros_healthd_ipc::NetworkResult::NewNetworkHealth(
      std::move(result.value()));
  std::move(callback).Run(std::move(info));
}

}  // namespace

void NetworkFetcher::FetchNetworkInfo(FetchNetworkInfoCallback callback) {
  context_->network_health_adapter()->GetNetworkHealthState(
      base::BindOnce(&HandleNetworkInfoResponse, std::move(callback)));
}

}  // namespace diagnostics
