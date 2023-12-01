// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/network/fake_network_health_adapter.h"

#include <optional>
#include <utility>

#include "diagnostics/mojom/external/network_health_types.mojom.h"

using ::chromeos::network_health::mojom::NetworkHealthStatePtr;

namespace diagnostics {

FakeNetworkHealthAdapter::FakeNetworkHealthAdapter() = default;
FakeNetworkHealthAdapter::~FakeNetworkHealthAdapter() = default;

void FakeNetworkHealthAdapter::GetNetworkHealthState(
    FetchNetworkStateCallback callback) {
  if (!bound_) {
    std::move(callback).Run(std::nullopt);
    return;
  }

  std::move(callback).Run(network_health_state_.Clone());
}

bool FakeNetworkHealthAdapter::ServiceRemoteBound() {
  return bound_;
}

void FakeNetworkHealthAdapter::SetRemoteBound(bool bound) {
  bound_ = bound;
}

void FakeNetworkHealthAdapter::SetNetworkHealthStateResponse(
    NetworkHealthStatePtr network_health_state) {
  network_health_state_ = std::move(network_health_state);
}

}  // namespace diagnostics
