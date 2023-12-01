// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTH_TOOL_EVENT_NETWORK_SUBSCRIBER_H_
#define DIAGNOSTICS_CROS_HEALTH_TOOL_EVENT_NETWORK_SUBSCRIBER_H_

#include <string>

#include <mojo/public/cpp/bindings/pending_receiver.h>
#include <mojo/public/cpp/bindings/receiver.h>

#include "diagnostics/mojom/external/network_health.mojom.h"

namespace diagnostics {

extern const char kHumanReadableOnConnectionStateChangedEvent[];
extern const char kHumanReadableOnSignalStrengthChangedEvent[];

// This class subscribes to cros_healthd's network notifications and outputs any
// notifications received to stdout.
class NetworkSubscriber final
    : public chromeos::network_health::mojom::NetworkEventsObserver {
 public:
  explicit NetworkSubscriber(
      mojo::PendingReceiver<
          chromeos::network_health::mojom::NetworkEventsObserver>
          pending_receiver);
  NetworkSubscriber(const NetworkSubscriber&) = delete;
  NetworkSubscriber& operator=(const NetworkSubscriber&) = delete;
  ~NetworkSubscriber();

  // chromeos::network_health::mojom::NetworkEventsObserver overrides:
  void OnConnectionStateChanged(
      const std::string& guid,
      chromeos::network_health::mojom::NetworkState state) override;
  void OnSignalStrengthChanged(
      const std::string& guid,
      chromeos::network_health::mojom::UInt32ValuePtr signal_strength) override;

 private:
  // Allows the remote cros_healthd to call NetworkSubscriber's
  // NetworkEventsObserver methods.
  mojo::Receiver<chromeos::network_health::mojom::NetworkEventsObserver>
      receiver_;
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTH_TOOL_EVENT_NETWORK_SUBSCRIBER_H_
