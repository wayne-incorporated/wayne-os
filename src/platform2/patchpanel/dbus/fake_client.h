// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef PATCHPANEL_DBUS_FAKE_CLIENT_H_
#define PATCHPANEL_DBUS_FAKE_CLIENT_H_

#include <memory>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "patchpanel/dbus/client.h"

namespace patchpanel {

// Fake implementation of patchpanel::ClientInterface which can be used in
// tests.
class BRILLO_EXPORT FakeClient : public Client {
 public:
  FakeClient() = default;
  ~FakeClient() = default;

  // Client overrides.
  void RegisterOnAvailableCallback(
      base::RepeatingCallback<void(bool)> callback) override;
  void RegisterProcessChangedCallback(
      base::RepeatingCallback<void(bool)> callback) override;

  bool NotifyArcStartup(pid_t pid) override;
  bool NotifyArcShutdown() override;

  std::vector<Client::VirtualDevice> NotifyArcVmStartup(uint32_t cid) override;
  bool NotifyArcVmShutdown(uint32_t cid) override;

  bool NotifyTerminaVmStartup(uint32_t cid,
                              Client::VirtualDevice* device,
                              Client::IPv4Subnet* container_subnet) override;
  bool NotifyTerminaVmShutdown(uint32_t cid) override;

  bool NotifyParallelsVmStartup(uint64_t vm_id,
                                int subnet_index,
                                Client::VirtualDevice* device) override;
  bool NotifyParallelsVmShutdown(uint64_t vm_id) override;

  bool DefaultVpnRouting(const base::ScopedFD& socket) override;

  bool RouteOnVpn(const base::ScopedFD& socket) override;

  bool BypassVpn(const base::ScopedFD& socket) override;

  std::pair<base::ScopedFD, Client::ConnectedNamespace> ConnectNamespace(
      pid_t pid,
      const std::string& outbound_ifname,
      bool forward_user_traffic,
      bool route_on_vpn,
      Client::TrafficSource traffic_source) override;

  void GetTrafficCounters(const std::set<std::string>& devices,
                          Client::GetTrafficCountersCallback callback) override;

  bool ModifyPortRule(Client::FirewallRequestOperation op,
                      Client::FirewallRequestType type,
                      Client::FirewallRequestProtocol proto,
                      const std::string& input_ifname,
                      const std::string& input_dst_ip,
                      uint32_t input_dst_port,
                      const std::string& dst_ip,
                      uint32_t dst_port) override;

  bool SetVpnLockdown(bool enable) override;

  base::ScopedFD RedirectDns(Client::DnsRedirectionRequestType type,
                             const std::string& input_ifname,
                             const std::string& proxy_address,
                             const std::vector<std::string>& nameservers,
                             const std::string& host_ifname) override;

  std::vector<Client::VirtualDevice> GetDevices() override;

  void RegisterVirtualDeviceEventHandler(
      VirtualDeviceEventHandler handler) override;

  void RegisterNeighborReachabilityEventHandler(
      Client::NeighborReachabilityEventHandler handler) override;

  bool CreateTetheredNetwork(
      const std::string& downstream_ifname,
      const std::string& upstream_ifname,
      const std::optional<DHCPOptions>& dhcp_options,
      const std::optional<int>& mtu,
      Client::CreateTetheredNetworkCallback callback) override;

  bool CreateLocalOnlyNetwork(
      const std::string& ifname,
      Client::CreateLocalOnlyNetworkCallback callback) override;

  bool GetDownstreamNetworkInfo(
      const std::string& ifname,
      Client::GetDownstreamNetworkInfoCallback callback) override;

  // Triggers registered handlers for NeighborReachabilityEvent.
  void TriggerNeighborReachabilityEvent(
      const Client::NeighborReachabilityEvent& signal);

  void set_stored_traffic_counters(
      const std::vector<Client::TrafficCounter>& counters) {
    stored_traffic_counters_ = counters;
  }

 private:
  std::vector<Client::TrafficCounter> stored_traffic_counters_;
  std::vector<Client::NeighborReachabilityEventHandler>
      neighbor_event_handlers_;
  VirtualDeviceEventHandler virtual_device_event_handlers_;
};

}  // namespace patchpanel

#endif  // PATCHPANEL_DBUS_FAKE_CLIENT_H_
