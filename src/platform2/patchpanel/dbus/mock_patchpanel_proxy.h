// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef PATCHPANEL_DBUS_MOCK_PATCHPANEL_PROXY_H_
#define PATCHPANEL_DBUS_MOCK_PATCHPANEL_PROXY_H_

#include <gmock/gmock.h>

#include <patchpanel/proto_bindings/patchpanel_service.pb.h>

#include "patchpanel/dbus-proxies.h"

namespace patchpanel {

class MockPatchPanelProxy : public org::chromium::PatchPanelProxyInterface {
 public:
  MockPatchPanelProxy();
  ~MockPatchPanelProxy() override;

  MOCK_METHOD(
      bool,
      ArcShutdown,
      (const ArcShutdownRequest&, ArcShutdownResponse*, brillo::ErrorPtr*, int),
      (override));

  MOCK_METHOD(void,
              ArcShutdownAsync,
              (const ArcShutdownRequest&,
               base::OnceCallback<void(const ArcShutdownResponse&)>,
               base::OnceCallback<void(brillo::Error*)>,
               int),
              (override));

  MOCK_METHOD(
      bool,
      ArcStartup,
      (const ArcStartupRequest&, ArcStartupResponse*, brillo::ErrorPtr*, int),
      (override));

  MOCK_METHOD(void,
              ArcStartupAsync,
              (const ArcStartupRequest&,
               base::OnceCallback<void(const ArcStartupResponse&)>,
               base::OnceCallback<void(brillo::Error*)>,
               int),
              (override));

  MOCK_METHOD(bool,
              ArcVmShutdown,
              (const ArcVmShutdownRequest&,
               ArcVmShutdownResponse*,
               brillo::ErrorPtr*,
               int),
              (override));

  MOCK_METHOD(void,
              ArcVmShutdownAsync,
              (const ArcVmShutdownRequest&,
               base::OnceCallback<void(const ArcVmShutdownResponse&)>,
               base::OnceCallback<void(brillo::Error*)>,
               int),
              (override));

  MOCK_METHOD(bool,
              ArcVmStartup,
              (const ArcVmStartupRequest&,
               ArcVmStartupResponse*,
               brillo::ErrorPtr*,
               int),
              (override));

  MOCK_METHOD(void,
              ArcVmStartupAsync,
              (const ArcVmStartupRequest&,
               base::OnceCallback<void(const ArcVmStartupResponse&)>,
               base::OnceCallback<void(brillo::Error*)>,
               int),
              (override));

  MOCK_METHOD(bool,
              ConnectNamespace,
              (const ConnectNamespaceRequest&,
               const base::ScopedFD&,
               ConnectNamespaceResponse*,
               brillo::ErrorPtr*,
               int),
              (override));

  MOCK_METHOD(void,
              ConnectNamespaceAsync,
              (const ConnectNamespaceRequest&,
               const base::ScopedFD&,
               base::OnceCallback<void(const ConnectNamespaceResponse&)>,
               base::OnceCallback<void(brillo::Error*)>,
               int),
              (override));

  MOCK_METHOD(bool,
              CreateLocalOnlyNetwork,
              (const LocalOnlyNetworkRequest&,
               const base::ScopedFD&,
               LocalOnlyNetworkResponse*,
               brillo::ErrorPtr*,
               int),
              (override));

  MOCK_METHOD(void,
              CreateLocalOnlyNetworkAsync,
              (const LocalOnlyNetworkRequest&,
               const base::ScopedFD&,
               base::OnceCallback<void(const LocalOnlyNetworkResponse&)>,
               base::OnceCallback<void(brillo::Error*)>,
               int),
              (override));

  MOCK_METHOD(bool,
              CreateTetheredNetwork,
              (const TetheredNetworkRequest&,
               const base::ScopedFD&,
               TetheredNetworkResponse*,
               brillo::ErrorPtr*,
               int),
              (override));

  MOCK_METHOD(void,
              CreateTetheredNetworkAsync,
              (const TetheredNetworkRequest&,
               const base::ScopedFD&,
               base::OnceCallback<void(const TetheredNetworkResponse&)>,
               base::OnceCallback<void(brillo::Error*)>,
               int),
              (override));

  MOCK_METHOD(
      bool,
      GetDevices,
      (const GetDevicesRequest&, GetDevicesResponse*, brillo::ErrorPtr*, int),
      (override));

  MOCK_METHOD(void,
              GetDevicesAsync,
              (const GetDevicesRequest&,
               base::OnceCallback<void(const GetDevicesResponse&)>,
               base::OnceCallback<void(brillo::Error*)>,
               int),
              (override));

  MOCK_METHOD(bool,
              GetDownstreamNetworkInfo,
              (const GetDownstreamNetworkInfoRequest&,
               GetDownstreamNetworkInfoResponse*,
               brillo::ErrorPtr*,
               int),
              (override));

  MOCK_METHOD(
      void,
      GetDownstreamNetworkInfoAsync,
      (const GetDownstreamNetworkInfoRequest&,
       base::OnceCallback<void(const GetDownstreamNetworkInfoResponse&)>,
       base::OnceCallback<void(brillo::Error*)>,
       int),
      (override));

  MOCK_METHOD(bool,
              GetTrafficCounters,
              (const TrafficCountersRequest&,
               TrafficCountersResponse*,
               brillo::ErrorPtr*,
               int),
              (override));

  MOCK_METHOD(void,
              GetTrafficCountersAsync,
              (const TrafficCountersRequest&,
               base::OnceCallback<void(const TrafficCountersResponse&)>,
               base::OnceCallback<void(brillo::Error*)>,
               int),
              (override));

  MOCK_METHOD(bool,
              ModifyPortRule,
              (const ModifyPortRuleRequest&,
               ModifyPortRuleResponse*,
               brillo::ErrorPtr*,
               int),
              (override));

  MOCK_METHOD(void,
              ModifyPortRuleAsync,
              (const ModifyPortRuleRequest&,
               base::OnceCallback<void(const ModifyPortRuleResponse&)>,
               base::OnceCallback<void(brillo::Error*)>,
               int),
              (override));

  MOCK_METHOD(bool,
              ParallelsVmShutdown,
              (const ParallelsVmShutdownRequest&,
               ParallelsVmShutdownResponse*,
               brillo::ErrorPtr*,
               int),
              (override));

  MOCK_METHOD(void,
              ParallelsVmShutdownAsync,
              (const ParallelsVmShutdownRequest&,
               base::OnceCallback<void(const ParallelsVmShutdownResponse&)>,
               base::OnceCallback<void(brillo::Error*)>,
               int),
              (override));

  MOCK_METHOD(bool,
              ParallelsVmStartup,
              (const ParallelsVmStartupRequest&,
               ParallelsVmStartupResponse*,
               brillo::ErrorPtr*,
               int),
              (override));

  MOCK_METHOD(void,
              ParallelsVmStartupAsync,
              (const ParallelsVmStartupRequest&,
               base::OnceCallback<void(const ParallelsVmStartupResponse&)>,
               base::OnceCallback<void(brillo::Error*)>,
               int),
              (override));

  MOCK_METHOD(bool,
              SetDnsRedirectionRule,
              (const SetDnsRedirectionRuleRequest&,
               const base::ScopedFD&,
               SetDnsRedirectionRuleResponse*,
               brillo::ErrorPtr*,
               int),
              (override));

  MOCK_METHOD(void,
              SetDnsRedirectionRuleAsync,
              (const SetDnsRedirectionRuleRequest&,
               const base::ScopedFD&,
               base::OnceCallback<void(const SetDnsRedirectionRuleResponse&)>,
               base::OnceCallback<void(brillo::Error*)>,
               int),
              (override));

  MOCK_METHOD(bool,
              SetVpnIntent,
              (const SetVpnIntentRequest&,
               const base::ScopedFD& in_socket_fd,
               SetVpnIntentResponse*,
               brillo::ErrorPtr*,
               int),
              (override));

  MOCK_METHOD(void,
              SetVpnIntentAsync,
              (const SetVpnIntentRequest&,
               const base::ScopedFD& in_socket_fd,
               base::OnceCallback<void(const SetVpnIntentResponse&)>,
               base::OnceCallback<void(brillo::Error*)>,
               int),
              (override));

  MOCK_METHOD(bool,
              SetVpnLockdown,
              (const SetVpnLockdownRequest&,
               SetVpnLockdownResponse*,
               brillo::ErrorPtr*,
               int),
              (override));

  MOCK_METHOD(void,
              SetVpnLockdownAsync,
              (const SetVpnLockdownRequest&,
               base::OnceCallback<void(const SetVpnLockdownResponse&)>,
               base::OnceCallback<void(brillo::Error*)>,
               int),
              (override));

  MOCK_METHOD(bool,
              TerminaVmShutdown,
              (const TerminaVmShutdownRequest&,
               TerminaVmShutdownResponse*,
               brillo::ErrorPtr*,
               int),
              (override));

  MOCK_METHOD(void,
              TerminaVmShutdownAsync,
              (const TerminaVmShutdownRequest&,
               base::OnceCallback<void(const TerminaVmShutdownResponse&)>,
               base::OnceCallback<void(brillo::Error*)>,
               int),
              (override));

  MOCK_METHOD(bool,
              TerminaVmStartup,
              (const TerminaVmStartupRequest&,
               TerminaVmStartupResponse*,
               brillo::ErrorPtr*,
               int),
              (override));

  MOCK_METHOD(void,
              TerminaVmStartupAsync,
              (const TerminaVmStartupRequest&,
               base::OnceCallback<void(const TerminaVmStartupResponse&)>,
               base::OnceCallback<void(brillo::Error*)>,
               int),
              (override));

  MOCK_METHOD(bool,
              NotifyAndroidWifiMulticastLockChange,
              (const patchpanel::NotifyAndroidWifiMulticastLockChangeRequest&,
               patchpanel::NotifyAndroidWifiMulticastLockChangeResponse*,
               brillo::ErrorPtr*,
               int),
              (override));

  MOCK_METHOD(
      void,
      NotifyAndroidWifiMulticastLockChangeAsync,
      (const patchpanel::NotifyAndroidWifiMulticastLockChangeRequest&,
       base::OnceCallback<void(
           const patchpanel::
               NotifyAndroidWifiMulticastLockChangeResponse& /*response*/)>,
       base::OnceCallback<void(brillo::Error*)>,
       int),
      (override));

  MOCK_METHOD(bool,
              NotifyAndroidInteractiveState,
              (const patchpanel::NotifyAndroidInteractiveStateRequest&,
               patchpanel::NotifyAndroidInteractiveStateResponse*,
               brillo::ErrorPtr*,
               int),
              (override));

  MOCK_METHOD(void,
              NotifyAndroidInteractiveStateAsync,
              (const patchpanel::NotifyAndroidInteractiveStateRequest&,
               base::OnceCallback<void(
                   const patchpanel::
                       NotifyAndroidInteractiveStateResponse& /*response*/)>,
               base::OnceCallback<void(brillo::Error*)>,
               int),
              (override));

  MOCK_METHOD(void,
              RegisterNetworkDeviceChangedSignalHandler,
              (const base::RepeatingCallback<
                   void(const NetworkDeviceChangedSignal&)>& signal_callback,
               dbus::ObjectProxy::OnConnectedCallback on_connected_callback),
              (override));

  MOCK_METHOD(void,
              RegisterNetworkConfigurationChangedSignalHandler,
              (const base::RepeatingCallback<void(
                   const NetworkConfigurationChangedSignal&)>& signal_callback,
               dbus::ObjectProxy::OnConnectedCallback on_connected_callback),
              (override));

  MOCK_METHOD(void,
              RegisterNeighborReachabilityEventSignalHandler,
              (const base::RepeatingCallback<void(
                   const NeighborReachabilityEventSignal&)>& signal_callback,
               dbus::ObjectProxy::OnConnectedCallback on_connected_callback),
              (override));

  MOCK_METHOD(const dbus::ObjectPath&, GetObjectPath, (), (const override));
  MOCK_METHOD(dbus::ObjectProxy*, GetObjectProxy, (), (const override));
};

}  // namespace patchpanel
#endif  // PATCHPANEL_DBUS_MOCK_PATCHPANEL_PROXY_H_
