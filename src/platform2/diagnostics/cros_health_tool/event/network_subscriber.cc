// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_health_tool/event/network_subscriber.h"

#include <iostream>
#include <utility>

#include <base/check.h>
#include <base/logging.h>

#include "diagnostics/mojom/external/network_health.mojom.h"
#include "diagnostics/mojom/external/network_health_types.mojom.h"

namespace diagnostics {

const char kHumanReadableOnConnectionStateChangedEvent[] =
    "Connection state changed";
const char kHumanReadableOnSignalStrengthChangedEvent[] =
    "Signal strength changed";

NetworkSubscriber::NetworkSubscriber(
    mojo::PendingReceiver<
        chromeos::network_health::mojom::NetworkEventsObserver>
        pending_receiver)
    : receiver_{this /* impl */, std::move(pending_receiver)} {
  DCHECK(receiver_.is_bound());
}

NetworkSubscriber::~NetworkSubscriber() = default;

void NetworkSubscriber::OnConnectionStateChanged(
    const std::string& guid,
    chromeos::network_health::mojom::NetworkState state) {
  std::cout << "Network event received: "
            << kHumanReadableOnConnectionStateChangedEvent
            << ", Network guid: " << guid << ", Connection state: " << state
            << "\n";
}

void NetworkSubscriber::OnSignalStrengthChanged(
    const std::string& guid,
    chromeos::network_health::mojom::UInt32ValuePtr signal_strength) {
  std::cout << "Network event received: "
            << kHumanReadableOnSignalStrengthChangedEvent
            << ", Network guid: " << guid << ", "
            << "Signal strength: " << signal_strength->value << "\n";
}

}  // namespace diagnostics
