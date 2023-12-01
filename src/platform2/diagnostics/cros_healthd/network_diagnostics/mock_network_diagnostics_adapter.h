// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_NETWORK_DIAGNOSTICS_MOCK_NETWORK_DIAGNOSTICS_ADAPTER_H_
#define DIAGNOSTICS_CROS_HEALTHD_NETWORK_DIAGNOSTICS_MOCK_NETWORK_DIAGNOSTICS_ADAPTER_H_

#include <optional>
#include <string>

#include <gmock/gmock.h>

#include "diagnostics/cros_healthd/network_diagnostics/network_diagnostics_adapter.h"

namespace diagnostics {

// Mock implementation of the NetworkDiagnosticsAdapter interface.
class MockNetworkDiagnosticsAdapter final : public NetworkDiagnosticsAdapter {
 public:
  MockNetworkDiagnosticsAdapter();
  MockNetworkDiagnosticsAdapter(const MockNetworkDiagnosticsAdapter&) = delete;
  MockNetworkDiagnosticsAdapter& operator=(
      const MockNetworkDiagnosticsAdapter&) = delete;
  ~MockNetworkDiagnosticsAdapter() override;

  MOCK_METHOD(
      void,
      SetNetworkDiagnosticsRoutines,
      (mojo::PendingRemote<
          chromeos::network_diagnostics::mojom::NetworkDiagnosticsRoutines>),
      (override));
  MOCK_METHOD(bool, ServiceRemoteBound, (), (override));
  MOCK_METHOD(void,
              RunLanConnectivityRoutine,
              (chromeos::network_diagnostics::mojom::
                   NetworkDiagnosticsRoutines::RunLanConnectivityCallback),
              (override));
  MOCK_METHOD(void,
              RunSignalStrengthRoutine,
              (chromeos::network_diagnostics::mojom::
                   NetworkDiagnosticsRoutines::RunSignalStrengthCallback),
              (override));
  MOCK_METHOD(void,
              RunGatewayCanBePingedRoutine,
              (chromeos::network_diagnostics::mojom::
                   NetworkDiagnosticsRoutines::RunGatewayCanBePingedCallback),
              (override));
  MOCK_METHOD(
      void,
      RunHasSecureWiFiConnectionRoutine,
      (chromeos::network_diagnostics::mojom::NetworkDiagnosticsRoutines::
           RunHasSecureWiFiConnectionCallback),
      (override));
  MOCK_METHOD(void,
              RunDnsResolverPresentRoutine,
              (chromeos::network_diagnostics::mojom::
                   NetworkDiagnosticsRoutines::RunDnsResolverPresentCallback),
              (override));
  MOCK_METHOD(void,
              RunDnsLatencyRoutine,
              (chromeos::network_diagnostics::mojom::
                   NetworkDiagnosticsRoutines::RunDnsLatencyCallback),
              (override));
  MOCK_METHOD(void,
              RunDnsResolutionRoutine,
              (chromeos::network_diagnostics::mojom::
                   NetworkDiagnosticsRoutines::RunDnsResolutionCallback),
              (override));
  MOCK_METHOD(void,
              RunCaptivePortalRoutine,
              (chromeos::network_diagnostics::mojom::
                   NetworkDiagnosticsRoutines::RunCaptivePortalCallback),
              (override));
  MOCK_METHOD(void,
              RunHttpFirewallRoutine,
              (chromeos::network_diagnostics::mojom::
                   NetworkDiagnosticsRoutines::RunHttpFirewallCallback),
              (override));
  MOCK_METHOD(void,
              RunHttpsFirewallRoutine,
              (chromeos::network_diagnostics::mojom::
                   NetworkDiagnosticsRoutines::RunHttpsFirewallCallback),
              (override));
  MOCK_METHOD(void,
              RunHttpsLatencyRoutine,
              (chromeos::network_diagnostics::mojom::
                   NetworkDiagnosticsRoutines::RunHttpsLatencyCallback),
              (override));
  MOCK_METHOD(void,
              RunVideoConferencingRoutine,
              (const std::optional<std::string>&,
               chromeos::network_diagnostics::mojom::
                   NetworkDiagnosticsRoutines::RunVideoConferencingCallback),
              (override));
  MOCK_METHOD(void,
              RunArcHttpRoutine,
              (chromeos::network_diagnostics::mojom::
                   NetworkDiagnosticsRoutines::RunArcHttpCallback),
              (override));
  MOCK_METHOD(void,
              RunArcPingRoutine,
              (chromeos::network_diagnostics::mojom::
                   NetworkDiagnosticsRoutines::RunArcPingCallback),
              (override));
  MOCK_METHOD(void,
              RunArcDnsResolutionRoutine,
              (chromeos::network_diagnostics::mojom::
                   NetworkDiagnosticsRoutines::RunArcDnsResolutionCallback),
              (override));
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_NETWORK_DIAGNOSTICS_MOCK_NETWORK_DIAGNOSTICS_ADAPTER_H_
