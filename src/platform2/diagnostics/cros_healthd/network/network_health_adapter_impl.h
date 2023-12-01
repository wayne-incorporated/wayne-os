// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_NETWORK_NETWORK_HEALTH_ADAPTER_IMPL_H_
#define DIAGNOSTICS_CROS_HEALTHD_NETWORK_NETWORK_HEALTH_ADAPTER_IMPL_H_

#include <string>

#include <base/memory/weak_ptr.h>
#include <mojo/public/cpp/bindings/pending_remote.h>
#include <mojo/public/cpp/bindings/receiver.h>
#include <mojo/public/cpp/bindings/remote.h>
#include <mojo/public/cpp/bindings/remote_set.h>

#include "diagnostics/cros_healthd/network/network_health_adapter.h"
#include "diagnostics/mojom/external/network_health.mojom.h"

namespace diagnostics {

// Production implementation of the NetworkHealthAdapter.
class NetworkHealthAdapterImpl final
    : public NetworkHealthAdapter,
      public chromeos::network_health::mojom::NetworkEventsObserver {
 public:
  NetworkHealthAdapterImpl();
  NetworkHealthAdapterImpl(const NetworkHealthAdapterImpl&) = delete;
  NetworkHealthAdapterImpl& operator=(const NetworkHealthAdapterImpl&) = delete;
  ~NetworkHealthAdapterImpl() override;

  // NetworkHealthAdapterInterface overrides:
  void GetNetworkHealthState(FetchNetworkStateCallback callback) override;
  void SetServiceRemote(
      mojo::PendingRemote<chromeos::network_health::mojom::NetworkHealthService>
          remote) override;
  void AddObserver(mojo::PendingRemote<
                   chromeos::network_health::mojom::NetworkEventsObserver>
                       observer) override;
  bool ServiceRemoteBound() override;

 private:
  // network_health::mojom::NetworkEventsObserver overrides:
  void OnConnectionStateChanged(
      const std::string& guid,
      chromeos::network_health::mojom::NetworkState state) override;
  void OnSignalStrengthChanged(
      const std::string& guid,
      chromeos::network_health::mojom::UInt32ValuePtr signal_strength) override;

  // Each observer in |observers_| will be notified of any network event in
  // the chromeos::network_health::mojom::NetworkEventsObserver interface.
  // The RemoteSet manages the lifetime of the endpoints, which are
  // automatically destroyed and removed when the pipe they are bound to is
  // destroyed.
  mojo::RemoteSet<chromeos::network_health::mojom::NetworkEventsObserver>
      observers_;

  mojo::Remote<chromeos::network_health::mojom::NetworkHealthService>
      network_health_remote_;
  mojo::Receiver<chromeos::network_health::mojom::NetworkEventsObserver>
      network_events_observer_receiver_{this};

  // Must be the last member of the class.
  base::WeakPtrFactory<NetworkHealthAdapterImpl> weak_factory_{this};
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_NETWORK_NETWORK_HEALTH_ADAPTER_IMPL_H_
