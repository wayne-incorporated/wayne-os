// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_NETWORK_DIAGNOSTICS_NETWORK_DIAGNOSTICS_ADAPTER_IMPL_H_
#define DIAGNOSTICS_CROS_HEALTHD_NETWORK_DIAGNOSTICS_NETWORK_DIAGNOSTICS_ADAPTER_IMPL_H_

#include <optional>
#include <string>

#include <mojo/public/cpp/bindings/remote.h>

#include "diagnostics/cros_healthd/network_diagnostics/network_diagnostics_adapter.h"

namespace diagnostics {

// Production implementation of the NetworkDiagnosticsAdapter interface.
class NetworkDiagnosticsAdapterImpl final : public NetworkDiagnosticsAdapter {
 public:
  NetworkDiagnosticsAdapterImpl();
  NetworkDiagnosticsAdapterImpl(const NetworkDiagnosticsAdapterImpl&) = delete;
  NetworkDiagnosticsAdapterImpl& operator=(
      const NetworkDiagnosticsAdapterImpl&) = delete;
  ~NetworkDiagnosticsAdapterImpl() override;

  // NetworkDiagnosticsAdapter overrides:
  void SetNetworkDiagnosticsRoutines(
      mojo::PendingRemote<
          chromeos::network_diagnostics::mojom::NetworkDiagnosticsRoutines>
          network_diagnostics_routines) override;
  bool ServiceRemoteBound() override;
  void RunLanConnectivityRoutine(
      chromeos::network_diagnostics::mojom::NetworkDiagnosticsRoutines::
          RunLanConnectivityCallback) override;
  void RunSignalStrengthRoutine(
      chromeos::network_diagnostics::mojom::NetworkDiagnosticsRoutines::
          RunSignalStrengthCallback) override;
  void RunGatewayCanBePingedRoutine(
      chromeos::network_diagnostics::mojom::NetworkDiagnosticsRoutines::
          RunGatewayCanBePingedCallback) override;
  void RunHasSecureWiFiConnectionRoutine(
      chromeos::network_diagnostics::mojom::NetworkDiagnosticsRoutines::
          RunHasSecureWiFiConnectionCallback) override;
  void RunDnsResolverPresentRoutine(
      chromeos::network_diagnostics::mojom::NetworkDiagnosticsRoutines::
          RunDnsResolverPresentCallback) override;
  void RunDnsLatencyRoutine(
      chromeos::network_diagnostics::mojom::NetworkDiagnosticsRoutines::
          RunDnsLatencyCallback) override;
  void RunDnsResolutionRoutine(
      chromeos::network_diagnostics::mojom::NetworkDiagnosticsRoutines::
          RunDnsResolutionCallback) override;
  void RunCaptivePortalRoutine(
      chromeos::network_diagnostics::mojom::NetworkDiagnosticsRoutines::
          RunCaptivePortalCallback) override;
  void RunHttpFirewallRoutine(
      chromeos::network_diagnostics::mojom::NetworkDiagnosticsRoutines::
          RunHttpFirewallCallback) override;
  void RunHttpsFirewallRoutine(
      chromeos::network_diagnostics::mojom::NetworkDiagnosticsRoutines::
          RunHttpsFirewallCallback) override;
  void RunHttpsLatencyRoutine(
      chromeos::network_diagnostics::mojom::NetworkDiagnosticsRoutines::
          RunHttpsLatencyCallback) override;
  void RunVideoConferencingRoutine(
      const std::optional<std::string>& stun_server_hostname,
      chromeos::network_diagnostics::mojom::NetworkDiagnosticsRoutines::
          RunVideoConferencingCallback) override;
  void RunArcHttpRoutine(
      chromeos::network_diagnostics::mojom::NetworkDiagnosticsRoutines::
          RunArcHttpCallback) override;
  void RunArcPingRoutine(
      chromeos::network_diagnostics::mojom::NetworkDiagnosticsRoutines::
          RunArcPingCallback) override;
  void RunArcDnsResolutionRoutine(
      chromeos::network_diagnostics::mojom::NetworkDiagnosticsRoutines::
          RunArcDnsResolutionCallback) override;

 private:
  // NetworkDiagnosticsRoutines remote used to run network diagnostics.
  // In production, this interface is implemented by the browser.
  mojo::Remote<chromeos::network_diagnostics::mojom::NetworkDiagnosticsRoutines>
      network_diagnostics_routines_;
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_NETWORK_DIAGNOSTICS_NETWORK_DIAGNOSTICS_ADAPTER_IMPL_H_
