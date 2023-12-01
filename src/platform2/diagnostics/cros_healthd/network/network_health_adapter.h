// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_NETWORK_NETWORK_HEALTH_ADAPTER_H_
#define DIAGNOSTICS_CROS_HEALTHD_NETWORK_NETWORK_HEALTH_ADAPTER_H_

#include <optional>

#include <base/functional/callback_forward.h>
#include <mojo/public/cpp/bindings/pending_remote.h>

#include "diagnostics/mojom/external/network_health.mojom.h"
#include "diagnostics/mojom/external/network_health_types.mojom.h"

namespace diagnostics {

// Interface for interacting with the NetworkHealthService in Chrome.
class NetworkHealthAdapter {
 public:
  using FetchNetworkStateCallback = base::OnceCallback<void(
      std::optional<chromeos::network_health::mojom::NetworkHealthStatePtr>)>;

  virtual ~NetworkHealthAdapter() = default;

  // Request to get the NetworkHealthState snapshot. Will return the
  // NetworkHealthState if the remote is bound, or std::nullopt if the remote
  // is not bound through the callback.
  virtual void GetNetworkHealthState(FetchNetworkStateCallback callback) = 0;

  // Method that sets the internal NetworkHealthService remote.
  virtual void SetServiceRemote(
      mojo::PendingRemote<chromeos::network_health::mojom::NetworkHealthService>
          remote) = 0;

  // Adds a new observer to be notified when network-related events occur.
  virtual void AddObserver(
      mojo::PendingRemote<
          chromeos::network_health::mojom::NetworkEventsObserver> observer) = 0;

  // Method that checks if the internal NetworkHealthService remote is bound.
  virtual bool ServiceRemoteBound() = 0;
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_NETWORK_NETWORK_HEALTH_ADAPTER_H_
