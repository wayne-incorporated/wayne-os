// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_NETWORK_DIAGNOSTICS_NETWORK_DIAGNOSTICS_ADAPTER_H_
#define DIAGNOSTICS_CROS_HEALTHD_NETWORK_DIAGNOSTICS_NETWORK_DIAGNOSTICS_ADAPTER_H_

#include <optional>
#include <string>

#include <mojo/public/cpp/bindings/pending_remote.h>

#include "diagnostics/mojom/external/network_diagnostics.mojom.h"

namespace diagnostics {

// Interface which allows cros_healthd to access the browser's
// NetworkDiagnosticsRoutines interface.
class NetworkDiagnosticsAdapter {
 public:
  virtual ~NetworkDiagnosticsAdapter() = default;

  // Sets the NetworkDiagnosticsRoutines remote sent by the browser.
  virtual void SetNetworkDiagnosticsRoutines(
      mojo::PendingRemote<
          chromeos::network_diagnostics::mojom::NetworkDiagnosticsRoutines>
          network_diagnostics_routines) = 0;

  // Checks to see if the internal NetworkDiagnostics remote is bound.
  virtual bool ServiceRemoteBound() = 0;

  // Requests that the browser invokes the LanConnectivity routine.
  virtual void RunLanConnectivityRoutine(
      chromeos::network_diagnostics::mojom::NetworkDiagnosticsRoutines::
          RunLanConnectivityCallback) = 0;

  // Requests the browser to invoke the SignalStrength routine.
  virtual void RunSignalStrengthRoutine(
      chromeos::network_diagnostics::mojom::NetworkDiagnosticsRoutines::
          RunSignalStrengthCallback) = 0;

  // Requests the browser to invoke the GatewayCanBePinged routine.
  virtual void RunGatewayCanBePingedRoutine(
      chromeos::network_diagnostics::mojom::NetworkDiagnosticsRoutines::
          RunGatewayCanBePingedCallback) = 0;

  // Requests the browser to invoke the HasSecureWiFiConnection routine.
  virtual void RunHasSecureWiFiConnectionRoutine(
      chromeos::network_diagnostics::mojom::NetworkDiagnosticsRoutines::
          RunHasSecureWiFiConnectionCallback) = 0;

  // Requests the browser to invoke the DnsResolverPresent routine.
  virtual void RunDnsResolverPresentRoutine(
      chromeos::network_diagnostics::mojom::NetworkDiagnosticsRoutines::
          RunDnsResolverPresentCallback) = 0;

  // Requests the browser to invoke the DnsLatency routine.
  virtual void RunDnsLatencyRoutine(
      chromeos::network_diagnostics::mojom::NetworkDiagnosticsRoutines::
          RunDnsLatencyCallback) = 0;

  // Requests the browser to invoke the DnsResolution routine.
  virtual void RunDnsResolutionRoutine(
      chromeos::network_diagnostics::mojom::NetworkDiagnosticsRoutines::
          RunDnsResolutionCallback) = 0;

  // Requests the browser to invoke the CaptivePortal routine.
  virtual void RunCaptivePortalRoutine(
      chromeos::network_diagnostics::mojom::NetworkDiagnosticsRoutines::
          RunCaptivePortalCallback) = 0;

  // Requests the browser to invoke the HttpFirewall routine.
  virtual void RunHttpFirewallRoutine(
      chromeos::network_diagnostics::mojom::NetworkDiagnosticsRoutines::
          RunHttpFirewallCallback) = 0;

  // Requests the browser to invoke the HttpsFirewall routine.
  virtual void RunHttpsFirewallRoutine(
      chromeos::network_diagnostics::mojom::NetworkDiagnosticsRoutines::
          RunHttpsFirewallCallback) = 0;

  // Requests the browser to invoke the HttpsLatency routine.
  virtual void RunHttpsLatencyRoutine(
      chromeos::network_diagnostics::mojom::NetworkDiagnosticsRoutines::
          RunHttpsLatencyCallback) = 0;

  // Requests the browser to invoke the VideoConferencing routine.
  virtual void RunVideoConferencingRoutine(
      const std::optional<std::string>& stun_server_hostname,
      chromeos::network_diagnostics::mojom::NetworkDiagnosticsRoutines::
          RunVideoConferencingCallback) = 0;

  // Requests the browser to invoke the ArcHttp routine.
  virtual void RunArcHttpRoutine(
      chromeos::network_diagnostics::mojom::NetworkDiagnosticsRoutines::
          RunArcHttpCallback) = 0;

  // Requests the browser to invoke the ArcPing routine.
  virtual void RunArcPingRoutine(
      chromeos::network_diagnostics::mojom::NetworkDiagnosticsRoutines::
          RunArcPingCallback) = 0;

  // Requests the browser to invoke the ArcDnsResolution routine.
  virtual void RunArcDnsResolutionRoutine(
      chromeos::network_diagnostics::mojom::NetworkDiagnosticsRoutines::
          RunArcDnsResolutionCallback) = 0;
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_NETWORK_DIAGNOSTICS_NETWORK_DIAGNOSTICS_ADAPTER_H_
