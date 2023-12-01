// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/network/network_health_adapter_impl.h"

#include <optional>
#include <utility>

#include <base/functional/callback.h>
#include <base/logging.h>

#include "diagnostics/mojom/external/network_health.mojom.h"
#include "diagnostics/mojom/external/network_health_types.mojom.h"

namespace diagnostics {

namespace {

namespace network_health_ipc = chromeos::network_health::mojom;

// Forwards the response from the network health remote to |callback|.
void OnNetworkHealthStateReceived(
    base::OnceCallback<void(
        std::optional<network_health_ipc::NetworkHealthStatePtr>)> callback,
    network_health_ipc::NetworkHealthStatePtr response) {
  std::move(callback).Run(std::move(response));
}

}  // namespace

NetworkHealthAdapterImpl::NetworkHealthAdapterImpl() = default;
NetworkHealthAdapterImpl::~NetworkHealthAdapterImpl() = default;

void NetworkHealthAdapterImpl::GetNetworkHealthState(
    FetchNetworkStateCallback callback) {
  if (!network_health_remote_.is_bound()) {
    std::move(callback).Run(std::nullopt);
    return;
  }

  network_health_remote_->GetHealthSnapshot(
      base::BindOnce(&OnNetworkHealthStateReceived, std::move(callback)));
}

void NetworkHealthAdapterImpl::SetServiceRemote(
    mojo::PendingRemote<network_health_ipc::NetworkHealthService> remote) {
  if (network_health_remote_.is_bound())
    network_health_remote_.reset();
  network_health_remote_.Bind(std::move(remote));
}

void NetworkHealthAdapterImpl::AddObserver(
    mojo::PendingRemote<network_health_ipc::NetworkEventsObserver> observer) {
  if (!network_health_remote_.is_bound()) {
    LOG(ERROR) << "Failed to add NetworkEventsObserver remote: unbound "
                  "NetworkHealthService remote";
    return;
  }

  if (!network_events_observer_receiver_.is_bound()) {
    network_health_remote_->AddObserver(
        network_events_observer_receiver_.BindNewPipeAndPassRemote());
  }
  observers_.Add(std::move(observer));
}

void NetworkHealthAdapterImpl::OnConnectionStateChanged(
    const std::string& guid, network_health_ipc::NetworkState state) {
  for (auto& observer : observers_)
    observer->OnConnectionStateChanged(guid, state);
}

void NetworkHealthAdapterImpl::OnSignalStrengthChanged(
    const std::string& guid,
    network_health_ipc::UInt32ValuePtr signal_strength) {
  uint32_t value = signal_strength->value;
  for (auto& observer : observers_) {
    observer->OnSignalStrengthChanged(
        guid, network_health_ipc::UInt32Value::New(value));
  }
}

bool NetworkHealthAdapterImpl::ServiceRemoteBound() {
  return network_health_remote_.is_bound();
}

}  // namespace diagnostics
