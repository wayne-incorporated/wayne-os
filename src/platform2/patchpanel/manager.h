// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef PATCHPANEL_MANAGER_H_
#define PATCHPANEL_MANAGER_H_

#include <map>
#include <memory>
#include <set>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include <base/files/scoped_file.h>
#include <base/memory/weak_ptr.h>
#include <patchpanel/proto_bindings/patchpanel_service.pb.h>

#include "patchpanel/address_manager.h"
#include "patchpanel/arc_service.h"
#include "patchpanel/counters_service.h"
#include "patchpanel/crostini_service.h"
#include "patchpanel/datapath.h"
#include "patchpanel/dhcp_server_controller.h"
#include "patchpanel/file_descriptor_watcher_posix.h"
#include "patchpanel/guest_ipv6_service.h"
#include "patchpanel/network_monitor_service.h"
#include "patchpanel/routing_service.h"
#include "patchpanel/rtnl_client.h"
#include "patchpanel/shill_client.h"
#include "patchpanel/subprocess_controller.h"
#include "patchpanel/system.h"

namespace patchpanel {

// The core implementation of the patchpanel daemon.
class Manager {
 public:
  // The notification callbacks to the client side.
  class ClientNotifier {
   public:
    virtual void OnNetworkDeviceChanged(const Device& virtual_device,
                                        Device::ChangeEvent event) = 0;
    virtual void OnNetworkConfigurationChanged() = 0;
    virtual void OnNeighborReachabilityEvent(
        int ifindex,
        const shill::IPAddress& ip_addr,
        NeighborLinkMonitor::NeighborRole role,
        NeighborReachabilityEventSignal::EventType event_type) = 0;
  };

  // The caller should guarantee |system|, |process_manager|, |metrics| and
  // |client| variables outlive the created Manager instance.
  Manager(const base::FilePath& cmd_path,
          System* system,
          shill::ProcessManager* process_manager,
          MetricsLibraryInterface* metrics,
          ClientNotifier* client_notifier,
          std::unique_ptr<ShillClient> shill_client,
          std::unique_ptr<RTNLClient> rtnl_client);
  Manager(const Manager&) = delete;
  Manager& operator=(const Manager&) = delete;
  virtual ~Manager();

  // Queries the list of virtual devices managed by patchpanel.
  GetDevicesResponse GetDevices() const;

  // Handles notification indicating ARC++ is booting up.
  bool ArcStartup(pid_t pid);

  // Handles notification indicating ARC++ is spinning down.
  void ArcShutdown();

  // Handles notification indicating ARCVM is booting up.
  std::optional<std::vector<const Device::Config*>> ArcVmStartup(uint32_t cid);

  // Handles notification indicating ARCVM is spinning down.
  void ArcVmShutdown(uint32_t cid);

  // Handles notification indicating a Termina VM is booting up.
  const Device* const TerminaVmStartup(uint64_t vm_id);

  // Handles notification indicating a Termina VM is spinning down.
  void TerminaVmShutdown(uint64_t vm_id);

  // Handles notification indicating a Parallels VM is booting up.
  const Device* const ParallelsVmStartup(uint64_t vm_id, uint32_t subnet_index);

  // Handles notification indicating a Parallels VM is spinning down.
  void ParallelsVmShutdown(uint64_t vm_id);

  // Sets a VPN intent fwmark on a socket.
  bool SetVpnIntent(SetVpnIntentRequest::VpnRoutingPolicy policy,
                    const base::ScopedFD& sockfd);

  // Connects and routes an existing network namespace created via minijail or
  // through rtnetlink RTM_NEWNSID.
  ConnectNamespaceResponse ConnectNamespace(
      const patchpanel::ConnectNamespaceRequest& request,
      const base::ScopedFD& client_fd);

  // Queries traffic counters.
  std::map<CountersService::CounterKey, CountersService::Counter>
  GetTrafficCounters(const std::set<std::string>& shill_devices) const;

  // Creates iptables rules requests from permission_broker.
  bool ModifyPortRule(const patchpanel::ModifyPortRuleRequest& request);

  // Starts or stops VPN lockdown.
  void SetVpnLockdown(bool enable_vpn_lockdown);

  // Creates iptables rules requests from dns-proxy.
  bool SetDnsRedirectionRule(
      const patchpanel::SetDnsRedirectionRuleRequest& request,
      const base::ScopedFD& client_fd);

  // Creates an L3 network on a network interface and tethered to an upstream
  // network.
  DownstreamNetworkResult CreateTetheredNetwork(
      const TetheredNetworkRequest& request, const base::ScopedFD& client_fd);

  // Creates a local-only L3 network on a network interface.
  DownstreamNetworkResult CreateLocalOnlyNetwork(
      const LocalOnlyNetworkRequest& request, const base::ScopedFD& client_fd);

  // Provides L3 and DHCP client information about clients connected to a
  // network created with CreateTetheredNetwork or CreateLocalOnlyNetwork.
  std::optional<
      std::pair<DownstreamNetworkInfo, std::vector<DownstreamClientInfo>>>
  GetDownstreamNetworkInfo(const std::string& downstream_ifname) const;

  // Start/Stop forwarding multicast traffic to ARC when ARC power state
  // changes.
  // When power state changes into interactive, start forwarding IPv4 and IPv6
  // multicast mDNS and SSDP traffic for all non-WiFi interfaces, and for WiFi
  // interface only when Android WiFi multicast lock is held by any app in ARC.
  // When power state changes into non-interactive, stop forwarding multicast
  // traffic for all interfaces if enabled.
  void NotifyAndroidInteractiveState(bool is_interactive);

  // Start/Stop forwarding WiFi multicast traffic to and from ARC when Android
  // WiFi multicast lock held status changes. Start forwarding IPv4 and IPv6
  // multicast mDNS and SSDP traffic for WiFi interfaces only when
  // device power state is interactive and Android WiFi multicast lock is held
  // by any app in ARC, otherwise stop multicast forwarder for ARC WiFi
  // interface.
  void NotifyAndroidWifiMulticastLockChange(bool is_held);

 private:
  friend class ManagerTest;

  // Struct to specify which forwarders to start and stop.
  struct ForwardingSet {
    bool ipv6;
    bool multicast;
  };

  // Callbacks from |shill_client_|.
  void OnShillDefaultLogicalDeviceChanged(
      const ShillClient::Device& new_device,
      const ShillClient::Device& prev_device);
  void OnShillDefaultPhysicalDeviceChanged(
      const ShillClient::Device& new_device,
      const ShillClient::Device& prev_device);
  void OnShillDevicesChanged(const std::vector<ShillClient::Device>& added,
                             const std::vector<ShillClient::Device>& removed);
  void OnIPConfigsChanged(const ShillClient::Device& shill_device);
  void OnIPv6NetworkChanged(const ShillClient::Device& shill_device);

  // Callbacks from |arc_svc_| and |cros_svc_| to notify Manager about new
  // or removed virtual Devices.
  void OnArcDeviceChanged(const ShillClient::Device& shill_device,
                          const Device& virtual_device,
                          Device::ChangeEvent event);
  void OnCrostiniDeviceChanged(const Device& virtual_device,
                               Device::ChangeEvent event);

  // Callback from |network_monitor_svc_|.
  void OnNeighborReachabilityEvent(
      int ifindex,
      const shill::IPAddress& ip_addr,
      NeighborLinkMonitor::NeighborRole role,
      NeighborReachabilityEventSignal::EventType event_type);

  // Helper functions for tracking DBus request lifetime with file descriptors
  // provided by DBus clients. Returns a duplicate wrapped in base::ScopedFD of
  // |dbus_fd|. The duplicate is added to the list of file descriptors watched
  // for invalidation. Returns an invalid ScopedFD object if it fails.
  base::ScopedFD AddLifelineFd(const base::ScopedFD& dbus_fd);
  bool DeleteLifelineFd(int dbus_fd);

  // Detects if any file descriptor committed in patchpanel's DBus API has been
  // invalidated by the caller. Calls OnLifelineFdClosed for any invalid fd
  // found.
  void OnLifelineFdClosed(int client_fd);

  void StartForwarding(const ShillClient::Device& shill_device,
                       const std::string& ifname_virtual,
                       const ForwardingSet& fs = {.ipv6 = true,
                                                  .multicast = true},
                       const std::optional<int>& mtu = std::nullopt);
  void StopForwarding(const ShillClient::Device& shill_device,
                      const std::string& ifname_virtual,
                      const ForwardingSet& fs = {.ipv6 = true,
                                                 .multicast = true});

  const Device* StartCrosVm(uint64_t vm_id,
                            CrostiniService::VMType vm_type,
                            uint32_t subnet_index = kAnySubnetIndex);
  void StopCrosVm(uint64_t vm_id, GuestMessage::GuestType vm_type);

  // Checks the validaty of a CreateTetheredNetwork or CreatedLocalOnlyNetwork
  // DBus request.
  bool ValidateDownstreamNetworkRequest(const DownstreamNetworkInfo& info);
  // Creates a downstream L3 network on the network interface specified by the
  // |info|. If successful, |client_fd| is monitored and triggers the teardown
  // of the network setup when closed.
  DownstreamNetworkResult HandleDownstreamNetworkInfo(
      const base::ScopedFD& client_fd, const DownstreamNetworkInfo& info);

  std::vector<DownstreamClientInfo> GetDownstreamClientInfo(
      const std::string& downstream_ifname) const;

  // Disable and re-enable IPv6 inside a namespace.
  void RestartIPv6(const std::string& netns_name);

  // Dispatch |msg| to child processes.
  void SendGuestMessage(const GuestMessage& msg);

  // patchpanel::System shared for all subsystems.
  System* system_;

  // The client of the Manager.
  ClientNotifier* client_notifier_;

  // Shill Dbus client.
  std::unique_ptr<ShillClient> shill_client_;

  // rtnetlink client.
  std::unique_ptr<RTNLClient> rtnl_client_;

  // High level routing and iptables controller service.
  std::unique_ptr<Datapath> datapath_;
  // Routing service.
  std::unique_ptr<RoutingService> routing_svc_;
  // ARC++/ARCVM service.
  std::unique_ptr<ArcService> arc_svc_;
  // Crostini and other VM service.
  std::unique_ptr<CrostiniService> cros_svc_;

  // adb connection forwarder service.
  std::unique_ptr<SubprocessController> adb_proxy_;
  // IPv4 and IPv6 Multicast forwarder service.
  std::unique_ptr<SubprocessController> mcast_proxy_;
  // IPv6 neighbor discovery forwarder process handler.
  std::unique_ptr<SubprocessController> nd_proxy_;

  // IPv6 address provisioning / ndp forwarding service.
  std::unique_ptr<GuestIPv6Service> ipv6_svc_;
  // Traffic counter service.
  std::unique_ptr<CountersService> counters_svc_;
  // L2 neighbor monitor service.
  std::unique_ptr<NetworkMonitorService> network_monitor_svc_;

  // The DHCP server controllers, keyed by its downstream interface.
  std::map<std::string, std::unique_ptr<DHCPServerController>>
      dhcp_server_controllers_;

  // IPv4 prefix and address manager.
  AddressManager addr_mgr_;

  // All namespaces currently connected through patchpanel ConnectNamespace
  // API, keyed by file descriptors committed by clients when calling
  // ConnectNamespace.
  std::map<int, ConnectedNamespace> connected_namespaces_;
  int connected_namespaces_next_id_{0};

  // DNS proxy's IPv4 and IPv6 addresses keyed by its guest interface.
  std::map<std::string, std::string> dns_proxy_ipv4_addrs_;
  std::map<std::string, std::string> dns_proxy_ipv6_addrs_;

  // All external network interfaces currently managed by patchpanel through
  // the CreateTetheredNetwork or CreateLocalOnlyNetwork DBus APIs, keyed by the
  // file descriptors committed by the DBus clients.
  std::map<int, DownstreamNetworkInfo> downstream_networks_;

  // All rules currently created through patchpanel RedirectDns
  // API, keyed by file descriptors committed by clients when calling the
  // API.
  std::map<int, DnsRedirectionRule> dns_redirection_rules_;

  // For each fd (process) committed through a patchpanel's DBus API, keep
  // track of the FileDescriptorWatcher::Controller object associated with it.
  std::map<int, std::unique_ptr<base::FileDescriptorWatcher::Controller>>
      lifeline_fd_controllers_;

  // Whether multicast lock is held by any app in ARC, used to decide whether
  // to start/stop forwarding multicast traffic to ARC on WiFi.
  bool android_wifi_multicast_lock_held_ = true;

  // Whether device is interactive, used to decide whether to start/stop
  // forwarding multicast traffic to ARC on all multicast enabled networks.
  bool is_arc_interactive_ = true;

  base::WeakPtrFactory<Manager> weak_factory_{this};
};

}  // namespace patchpanel
#endif  // PATCHPANEL_MANAGER_H_
