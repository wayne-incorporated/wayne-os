// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "patchpanel/manager.h"

#include <algorithm>
#include <utility>

#include <base/check.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/posix/eintr_wrapper.h>
#include <base/task/single_thread_task_runner.h>

#include "patchpanel/address_manager.h"
#include "patchpanel/proto_utils.h"
#include "patchpanel/scoped_ns.h"

namespace patchpanel {
namespace {
// Delay to restart IPv6 in a namespace to trigger SLAAC in the kernel.
constexpr int kIPv6RestartDelayMs = 300;
}  // namespace

Manager::Manager(const base::FilePath& cmd_path,
                 System* system,
                 shill::ProcessManager* process_manager,
                 MetricsLibraryInterface* metrics,
                 ClientNotifier* client_notifier,
                 std::unique_ptr<ShillClient> shill_client,
                 std::unique_ptr<RTNLClient> rtnl_client)
    : system_(system),
      client_notifier_(client_notifier),
      shill_client_(std::move(shill_client)),
      rtnl_client_(std::move(rtnl_client)) {
  DCHECK(rtnl_client_);

  datapath_ = std::make_unique<Datapath>(system);
  adb_proxy_ = std::make_unique<patchpanel::SubprocessController>(
      system, process_manager, cmd_path, "--adb_proxy_fd");
  mcast_proxy_ = std::make_unique<patchpanel::SubprocessController>(
      system, process_manager, cmd_path, "--mcast_proxy_fd");
  nd_proxy_ = std::make_unique<patchpanel::SubprocessController>(
      system, process_manager, cmd_path, "--nd_proxy_fd");

  adb_proxy_->Start();
  mcast_proxy_->Start();
  nd_proxy_->Start();

  routing_svc_ = std::make_unique<RoutingService>();
  counters_svc_ = std::make_unique<CountersService>(datapath_.get());

  datapath_->Start();

  shill_client_->RegisterDevicesChangedHandler(base::BindRepeating(
      &Manager::OnShillDevicesChanged, weak_factory_.GetWeakPtr()));
  shill_client_->RegisterIPConfigsChangedHandler(base::BindRepeating(
      &Manager::OnIPConfigsChanged, weak_factory_.GetWeakPtr()));
  shill_client_->RegisterIPv6NetworkChangedHandler(base::BindRepeating(
      &Manager::OnIPv6NetworkChanged, weak_factory_.GetWeakPtr()));

  auto arc_type =
      USE_ARCVM ? ArcService::ArcType::kVM : ArcService::ArcType::kContainer;
  arc_svc_ = std::make_unique<ArcService>(
      datapath_.get(), &addr_mgr_, arc_type, metrics,
      base::BindRepeating(&Manager::OnArcDeviceChanged,
                          weak_factory_.GetWeakPtr()));
  cros_svc_ = std::make_unique<CrostiniService>(
      &addr_mgr_, datapath_.get(),
      base::BindRepeating(&Manager::OnCrostiniDeviceChanged,
                          weak_factory_.GetWeakPtr()));

  network_monitor_svc_ = std::make_unique<NetworkMonitorService>(
      shill_client_.get(),
      base::BindRepeating(&Manager::OnNeighborReachabilityEvent,
                          weak_factory_.GetWeakPtr()));
  ipv6_svc_ = std::make_unique<GuestIPv6Service>(nd_proxy_.get(),
                                                 datapath_.get(), system);

  network_monitor_svc_->Start();
  ipv6_svc_->Start();

  // Shill client's default devices methods trigger the Manager's callbacks on
  // registration. Call them after everything is set up.
  shill_client_->RegisterDefaultLogicalDeviceChangedHandler(
      base::BindRepeating(&Manager::OnShillDefaultLogicalDeviceChanged,
                          weak_factory_.GetWeakPtr()));
  shill_client_->RegisterDefaultPhysicalDeviceChangedHandler(
      base::BindRepeating(&Manager::OnShillDefaultPhysicalDeviceChanged,
                          weak_factory_.GetWeakPtr()));
}

Manager::~Manager() {
  network_monitor_svc_.reset();
  cros_svc_.reset();
  arc_svc_.reset();

  // Tear down any remaining active lifeline file descriptors.
  std::vector<int> lifeline_fds;
  for (const auto& kv : connected_namespaces_) {
    lifeline_fds.push_back(kv.first);
  }
  for (const auto& kv : dns_redirection_rules_) {
    lifeline_fds.push_back(kv.first);
  }
  for (const int fdkey : lifeline_fds) {
    OnLifelineFdClosed(fdkey);
  }

  datapath_->Stop();
}

void Manager::OnShillDefaultLogicalDeviceChanged(
    const ShillClient::Device& new_device,
    const ShillClient::Device& prev_device) {
  // Only take into account interface switches and ignore layer 3 property
  // changes.
  if (prev_device.ifname == new_device.ifname)
    return;

  if (prev_device.type == ShillClient::Device::Type::kVPN) {
    datapath_->StopVpnRouting(prev_device);
    counters_svc_->OnVpnDeviceRemoved(prev_device.ifname);
  }

  if (new_device.type == ShillClient::Device::Type::kVPN) {
    counters_svc_->OnVpnDeviceAdded(new_device.ifname);
    datapath_->StartVpnRouting(new_device);
  }

  // When the default logical network changes, Crostini's tap devices must leave
  // their current forwarding group for multicast and IPv6 ndproxy and join the
  // forwarding group of the new logical default network.
  // TODO(b/197930417): Introduce a separate forwarding service and migrate the
  // update of the forwarding setup inside the default logical device change
  // handler CrostiniService::OnShillDefaultLogicalDeviceChanged.
  for (const auto* tap_device : cros_svc_->GetDevices()) {
    StopForwarding(prev_device, tap_device->host_ifname());
    StartForwarding(new_device, tap_device->host_ifname());
  }
  cros_svc_->OnShillDefaultLogicalDeviceChanged(new_device, prev_device);

  // When the default logical network changes, ConnectedNamespaces' devices
  // which follow the logical network must leave their current forwarding group
  // for IPv6 ndproxy and join the forwarding group of the new logical default
  // network. This is marked by empty |outbound_ifname| and |route_on_vpn|
  // with the value of true.
  for (auto& [_, nsinfo] : connected_namespaces_) {
    if (!nsinfo.outbound_ifname.empty() || !nsinfo.route_on_vpn) {
      continue;
    }
    StopForwarding(prev_device, nsinfo.host_ifname,
                   ForwardingSet{.ipv6 = true});
    nsinfo.current_outbound_device = new_device;
    StartForwarding(new_device, nsinfo.host_ifname,
                    ForwardingSet{.ipv6 = true});

    // Disable and re-enable IPv6. This is necessary to trigger SLAAC in the
    // kernel to send RS. Add a delay for the forwarding to be set up.
    base::SingleThreadTaskRunner::GetCurrentDefault()->PostDelayedTask(
        FROM_HERE,
        base::BindOnce(&Manager::RestartIPv6, weak_factory_.GetWeakPtr(),
                       nsinfo.netns_name),
        base::Milliseconds(kIPv6RestartDelayMs));
  }
}

void Manager::OnShillDefaultPhysicalDeviceChanged(
    const ShillClient::Device& new_device,
    const ShillClient::Device& prev_device) {
  // Only take into account interface switches and ignore layer 3 property
  // changes.
  if (prev_device.ifname == new_device.ifname)
    return;

  // When the default physical network changes, ConnectedNamespaces' devices
  // which follow the physical network must leave their current forwarding group
  // for IPv6 ndproxy and join the forwarding group of the new physical default
  // network. This is marked by empty |outbound_ifname| and |route_on_vpn|
  // with the value of false.
  for (auto& [_, nsinfo] : connected_namespaces_) {
    if (!nsinfo.outbound_ifname.empty() || nsinfo.route_on_vpn) {
      continue;
    }
    StopForwarding(prev_device, nsinfo.host_ifname,
                   ForwardingSet{.ipv6 = true});
    nsinfo.current_outbound_device = new_device;
    StartForwarding(new_device, nsinfo.host_ifname,
                    ForwardingSet{.ipv6 = true});

    // Disable and re-enable IPv6. This is necessary to trigger SLAAC in the
    // kernel to send RS. Add a delay for the forwarding to be set up.
    base::SingleThreadTaskRunner::GetCurrentDefault()->PostDelayedTask(
        FROM_HERE,
        base::BindOnce(&Manager::RestartIPv6, weak_factory_.GetWeakPtr(),
                       nsinfo.netns_name),
        base::Milliseconds(kIPv6RestartDelayMs));
  }
}

void Manager::RestartIPv6(const std::string& netns_name) {
  auto ns = ScopedNS::EnterNetworkNS(netns_name);
  if (!ns) {
    LOG(ERROR) << "Invalid namespace name " << netns_name;
    return;
  }

  if (datapath_) {
    datapath_->RestartIPv6();
  }
}

void Manager::OnShillDevicesChanged(
    const std::vector<ShillClient::Device>& added,
    const std::vector<ShillClient::Device>& removed) {
  // Rules for traffic counters should be installed at the first and removed at
  // the last to make sure every packet is counted.
  for (const auto& device : removed) {
    for (auto& [_, nsinfo] : connected_namespaces_) {
      if (nsinfo.outbound_ifname == device.ifname) {
        StopForwarding(device, nsinfo.host_ifname, ForwardingSet{.ipv6 = true});
      }
    }
    StopForwarding(device, /*ifname_virtual=*/"");
    datapath_->StopConnectionPinning(device);
    datapath_->RemoveRedirectDnsRule(device);
    arc_svc_->RemoveDevice(device);
    counters_svc_->OnPhysicalDeviceRemoved(device.ifname);

    // We have no good way to tell whether the removed Device was cellular now,
    // so we always call this. StopSourcePrefixEnforcement will find out by
    // matching |ifname| with existing rules.
    // TODO(hugobenichi): fix the above problem now that the full Device
    // information is  available.
    datapath_->StopSourceIPv6PrefixEnforcement(device);
  }

  for (const auto& device : added) {
    counters_svc_->OnPhysicalDeviceAdded(device.ifname);
    for (auto& [_, nsinfo] : connected_namespaces_) {
      if (nsinfo.outbound_ifname != device.ifname) {
        continue;
      }
      StartForwarding(device, nsinfo.host_ifname, ForwardingSet{.ipv6 = true});
      base::SingleThreadTaskRunner::GetCurrentDefault()->PostDelayedTask(
          FROM_HERE,
          base::BindOnce(&Manager::RestartIPv6, weak_factory_.GetWeakPtr(),
                         nsinfo.netns_name),
          base::Milliseconds(kIPv6RestartDelayMs));
    }
    datapath_->StartConnectionPinning(device);

    if (!device.ipconfig.ipv4_dns_addresses.empty()) {
      datapath_->AddRedirectDnsRule(device,
                                    device.ipconfig.ipv4_dns_addresses.front());
    }

    arc_svc_->AddDevice(device);

    if (device.type == ShillClient::Device::Type::kCellular) {
      datapath_->StartSourceIPv6PrefixEnforcement(device);
    }
  }
}

void Manager::OnIPConfigsChanged(const ShillClient::Device& shill_device) {
  if (shill_device.ipconfig.ipv4_dns_addresses.empty()) {
    datapath_->RemoveRedirectDnsRule(shill_device);
  } else {
    datapath_->AddRedirectDnsRule(
        shill_device, shill_device.ipconfig.ipv4_dns_addresses.front());
  }
  ipv6_svc_->UpdateUplinkIPv6DNS(shill_device);

  // Update local copies of the ShillClient::Device to keep IP configuration
  // properties in sync.
  for (auto& [_, info] : downstream_networks_) {
    if (info.upstream_device &&
        info.upstream_device->ifname == shill_device.ifname) {
      info.upstream_device = shill_device;
    }
  }
  for (auto& [_, nsinfo] : connected_namespaces_) {
    if (nsinfo.current_outbound_device.ifname == shill_device.ifname) {
      nsinfo.current_outbound_device = shill_device;
    }
  }

  arc_svc_->UpdateDeviceIPConfig(shill_device);
}

void Manager::OnIPv6NetworkChanged(const ShillClient::Device& shill_device) {
  const auto ipv6_address = net_base::IPv6Address::CreateFromString(
      shill_device.ipconfig.ipv6_address);
  if (!ipv6_address) {
    if (shill_device.type == ShillClient::Device::Type::kCellular) {
      datapath_->UpdateSourceEnforcementIPv6Prefix(shill_device, std::nullopt);
    }
    return;
  }

  ipv6_svc_->OnUplinkIPv6Changed(shill_device);

  for (auto& [_, nsinfo] : connected_namespaces_) {
    if (nsinfo.outbound_ifname != shill_device.ifname) {
      continue;
    }

    // Disable and re-enable IPv6 inside the namespace. This is necessary to
    // trigger SLAAC in the kernel to send RS.
    RestartIPv6(nsinfo.netns_name);
  }

  if (shill_device.type == ShillClient::Device::Type::kCellular) {
    // TODO(b/279871350): Support prefix shorter than /64.
    const auto prefix = GuestIPv6Service::IPAddressTo64BitPrefix(*ipv6_address);
    datapath_->UpdateSourceEnforcementIPv6Prefix(shill_device, prefix);
  }
}

void Manager::OnArcDeviceChanged(const ShillClient::Device& shill_device,
                                 const Device& virtual_device,
                                 Device::ChangeEvent event) {
  // The legacy "arc0" Device is ignored for "NetworkDeviceChanged" signals
  // and is never included in multicast forwarding or GuestIPv6Service.
  if (virtual_device.type() == Device::Type::kARC0) {
    return;
  }
  if (event == Device::ChangeEvent::kAdded) {
    // Only start forwarding multicast traffic if ARC is in an interactive
    // state.
    bool forward_multicast = is_arc_interactive_;
    // In addition, only start forwarding multicast traffic on WiFi if the
    // Android WiFi multicast lock is held.
    if (shill_device.type == ShillClient::Device::Type::kWifi &&
        !android_wifi_multicast_lock_held_) {
      forward_multicast = false;
    }
    StartForwarding(shill_device, virtual_device.host_ifname(),
                    {.ipv6 = true, .multicast = forward_multicast});
  } else if (event == Device::ChangeEvent::kRemoved) {
    StopForwarding(shill_device, virtual_device.host_ifname());
  }

  client_notifier_->OnNetworkDeviceChanged(virtual_device, event);
}

void Manager::OnCrostiniDeviceChanged(const Device& virtual_device,
                                      Device::ChangeEvent event) {
  if (event == Device::ChangeEvent::kAdded) {
    StartForwarding(shill_client_->default_logical_device(),
                    virtual_device.host_ifname(),
                    {.ipv6 = true, .multicast = true});
  } else if (event == Device::ChangeEvent::kRemoved) {
    StopForwarding(shill_client_->default_logical_device(),
                   virtual_device.host_ifname());
  }

  client_notifier_->OnNetworkDeviceChanged(virtual_device, event);
}

bool Manager::ArcStartup(pid_t pid) {
  if (pid < 0) {
    LOG(ERROR) << "Invalid ARC pid: " << pid;
    return false;
  }

  if (!arc_svc_->Start(static_cast<uint32_t>(pid)))
    return false;

  GuestMessage msg;
  msg.set_event(GuestMessage::START);
  msg.set_type(GuestMessage::ARC);
  msg.set_arc_pid(pid);
  SendGuestMessage(msg);

  return true;
}

void Manager::ArcShutdown() {
  GuestMessage msg;
  msg.set_event(GuestMessage::STOP);
  msg.set_type(GuestMessage::ARC);
  SendGuestMessage(msg);

  // After the ARC container has stopped, the pid is not known anymore.
  // The pid argument is ignored by ArcService.
  arc_svc_->Stop(0);
}

std::optional<std::vector<const Device::Config*>> Manager::ArcVmStartup(
    uint32_t cid) {
  if (!arc_svc_->Start(cid))
    return std::nullopt;

  GuestMessage msg;
  msg.set_event(GuestMessage::START);
  msg.set_type(GuestMessage::ARC_VM);
  msg.set_arcvm_vsock_cid(cid);
  SendGuestMessage(msg);

  return arc_svc_->GetDeviceConfigs();
}

void Manager::ArcVmShutdown(uint32_t cid) {
  GuestMessage msg;
  msg.set_event(GuestMessage::STOP);
  msg.set_type(GuestMessage::ARC_VM);
  msg.set_arcvm_vsock_cid(cid);
  SendGuestMessage(msg);

  arc_svc_->Stop(cid);
}

const Device* Manager::StartCrosVm(uint64_t vm_id,
                                   CrostiniService::VMType vm_type,
                                   uint32_t subnet_index) {
  const auto* guest_device = cros_svc_->Start(vm_id, vm_type, subnet_index);
  if (!guest_device) {
    return nullptr;
  }
  GuestMessage msg;
  msg.set_event(GuestMessage::START);
  msg.set_type(CrostiniService::GuestMessageTypeFromVMType(vm_type));
  SendGuestMessage(msg);
  return guest_device;
}

void Manager::StopCrosVm(uint64_t vm_id, GuestMessage::GuestType vm_type) {
  GuestMessage msg;
  msg.set_event(GuestMessage::STOP);
  msg.set_type(vm_type);
  SendGuestMessage(msg);
  cros_svc_->Stop(vm_id);
}

GetDevicesResponse Manager::GetDevices() const {
  GetDevicesResponse response;

  for (const auto* arc_device : arc_svc_->GetDevices()) {
    // The legacy "arc0" Device is never exposed in "GetDevices".
    if (arc_device->type() == Device::Type::kARC0) {
      continue;
    }
    auto* dev = response.add_devices();
    FillDeviceProto(*arc_device, dev);
    FillDeviceDnsProxyProto(*arc_device, dev, dns_proxy_ipv4_addrs_,
                            dns_proxy_ipv6_addrs_);
  }

  for (const auto* crosvm_device : cros_svc_->GetDevices()) {
    auto* dev = response.add_devices();
    FillDeviceProto(*crosvm_device, dev);
  }

  return response;
}

const Device* const Manager::TerminaVmStartup(uint64_t cid) {
  const auto* guest_device =
      StartCrosVm(cid, CrostiniService::VMType::kTermina);
  if (!guest_device) {
    LOG(ERROR) << "Failed to start Termina VM network service";
    return nullptr;
  }
  return guest_device;
}

void Manager::TerminaVmShutdown(uint64_t vm_id) {
  StopCrosVm(vm_id, GuestMessage::TERMINA_VM);
}

const Device* const Manager::ParallelsVmStartup(uint64_t vm_id,
                                                uint32_t subnet_index) {
  const auto* guest_device =
      StartCrosVm(vm_id, CrostiniService::VMType::kParallels, subnet_index);
  if (!guest_device) {
    LOG(ERROR) << "Failed to start Parallels VM network service";
    return nullptr;
  }
  return guest_device;
}

void Manager::ParallelsVmShutdown(uint64_t vm_id) {
  StopCrosVm(vm_id, GuestMessage::PARALLELS_VM);
}

bool Manager::SetVpnIntent(SetVpnIntentRequest::VpnRoutingPolicy policy,
                           const base::ScopedFD& sockfd) {
  return routing_svc_->SetVpnFwmark(sockfd.get(), policy);
}

std::map<CountersService::CounterKey, CountersService::Counter>
Manager::GetTrafficCounters(const std::set<std::string>& shill_devices) const {
  return counters_svc_->GetCounters(shill_devices);
}

bool Manager::ModifyPortRule(const ModifyPortRuleRequest& request) {
  return datapath_->ModifyPortRule(request);
}

void Manager::SetVpnLockdown(bool enable_vpn_lockdown) {
  datapath_->SetVpnLockdown(enable_vpn_lockdown);
}

patchpanel::DownstreamNetworkResult Manager::CreateTetheredNetwork(
    const TetheredNetworkRequest& request, const base::ScopedFD& client_fd) {
  using shill::IPAddress;

  const auto* shill_device =
      shill_client_->GetDevice(request.upstream_ifname());
  if (!shill_device) {
    LOG(ERROR) << "Unknown shill Device " << request.upstream_ifname();
    return patchpanel::DownstreamNetworkResult::INVALID_ARGUMENT;
  }
  const auto info = DownstreamNetworkInfo::Create(request, *shill_device);
  if (!info) {
    LOG(ERROR) << __func__ << ": Unable to parse request";
    return patchpanel::DownstreamNetworkResult::INVALID_ARGUMENT;
  }

  return HandleDownstreamNetworkInfo(client_fd, *info);
}

patchpanel::DownstreamNetworkResult Manager::CreateLocalOnlyNetwork(
    const LocalOnlyNetworkRequest& request, const base::ScopedFD& client_fd) {
  std::optional<DownstreamNetworkInfo> info =
      DownstreamNetworkInfo::Create(request);
  if (!info) {
    LOG(ERROR) << __func__ << ": Unable to parse request";
    return patchpanel::DownstreamNetworkResult::INVALID_ARGUMENT;
  }

  return HandleDownstreamNetworkInfo(client_fd, *info);
}

std::optional<
    std::pair<DownstreamNetworkInfo, std::vector<DownstreamClientInfo>>>
Manager::GetDownstreamNetworkInfo(const std::string& downstream_ifname) const {
  auto match_by_downstream_ifname = [&downstream_ifname](const auto& kv) {
    return kv.second.downstream_ifname == downstream_ifname;
  };

  const auto it =
      std::find_if(downstream_networks_.begin(), downstream_networks_.end(),
                   match_by_downstream_ifname);
  if (it == downstream_networks_.end()) {
    return std::nullopt;
  }

  return std::make_pair(it->second, GetDownstreamClientInfo(downstream_ifname));
}

std::vector<DownstreamClientInfo> Manager::GetDownstreamClientInfo(
    const std::string& downstream_ifname) const {
  const auto ifindex = system_->IfNametoindex(downstream_ifname);
  if (!ifindex) {
    LOG(WARNING) << "Failed to get index of the interface:" << downstream_ifname
                 << ", skip querying the client info";
    return {};
  }

  std::map<MacAddress,
           std::pair<net_base::IPv4Address, std::vector<net_base::IPv6Address>>>
      mac_to_ip;
  for (const auto& [ipv4_addr, mac_addr] :
       rtnl_client_->GetIPv4NeighborMacTable(ifindex)) {
    mac_to_ip[mac_addr].first = ipv4_addr;
  }
  for (const auto& [ipv6_addr, mac_addr] :
       rtnl_client_->GetIPv6NeighborMacTable(ifindex)) {
    mac_to_ip[mac_addr].second.push_back(ipv6_addr);
  }

  std::vector<DownstreamClientInfo> client_infos;
  for (const auto& [mac_addr, ip] : mac_to_ip) {
    client_infos.push_back({mac_addr, ip.first, ip.second,
                            /*hostname=*/"", /*vendor_class=*/""});
  }
  return client_infos;
}

void Manager::OnNeighborReachabilityEvent(
    int ifindex,
    const shill::IPAddress& ip_addr,
    NeighborLinkMonitor::NeighborRole role,
    NeighborReachabilityEventSignal::EventType event_type) {
  client_notifier_->OnNeighborReachabilityEvent(ifindex, ip_addr, role,
                                                event_type);
}

ConnectNamespaceResponse Manager::ConnectNamespace(
    const ConnectNamespaceRequest& request, const base::ScopedFD& client_fd) {
  ConnectNamespaceResponse response;

  const pid_t pid = request.pid();
  if (pid == 1 || pid == getpid()) {
    LOG(ERROR) << "Privileged namespace pid " << pid;
    return response;
  }
  if (pid != ConnectedNamespace::kNewNetnsPid) {
    auto ns = ScopedNS::EnterNetworkNS(pid);
    if (!ns) {
      LOG(ERROR) << "Invalid namespace pid " << pid;
      return response;
    }
  }

  // Get the ConnectedNamespace outbound shill Device.
  const std::string& outbound_ifname = request.outbound_physical_device();
  ShillClient::Device current_outbound_device;
  if (!outbound_ifname.empty()) {
    auto* shill_device = shill_client_->GetDevice(outbound_ifname);
    if (!shill_device) {
      LOG(ERROR) << __func__ << ": no shill Device for upstream ifname "
                 << outbound_ifname;
      return response;
    }
    current_outbound_device = *shill_device;
  } else if (request.route_on_vpn()) {
    current_outbound_device = shill_client_->default_logical_device();
  } else {
    current_outbound_device = shill_client_->default_physical_device();
  }

  std::unique_ptr<Subnet> subnet =
      addr_mgr_.AllocateIPv4Subnet(AddressManager::GuestType::kNetns);
  if (!subnet) {
    LOG(ERROR) << "Exhausted IPv4 subnet space";
    return response;
  }

  base::ScopedFD local_client_fd = AddLifelineFd(client_fd);
  if (!local_client_fd.is_valid()) {
    LOG(ERROR) << "Failed to create lifeline fd";
    return response;
  }

  const std::string ifname_id = std::to_string(connected_namespaces_next_id_);
  ConnectedNamespace nsinfo = {};
  nsinfo.pid = request.pid();
  nsinfo.netns_name = "connected_netns_" + ifname_id;
  nsinfo.source = ProtoToTrafficSource(request.traffic_source());
  if (nsinfo.source == TrafficSource::kUnknown)
    nsinfo.source = TrafficSource::kSystem;
  nsinfo.outbound_ifname = outbound_ifname;
  nsinfo.route_on_vpn = request.route_on_vpn();
  nsinfo.host_ifname = "arc_ns" + ifname_id;
  nsinfo.peer_ifname = "veth" + ifname_id;
  nsinfo.peer_subnet = std::move(subnet);
  nsinfo.host_mac_addr = addr_mgr_.GenerateMacAddress();
  nsinfo.peer_mac_addr = addr_mgr_.GenerateMacAddress();
  if (nsinfo.host_mac_addr == nsinfo.peer_mac_addr) {
    LOG(ERROR) << "Failed to generate unique MAC address for connected "
                  "namespace host and peer interface";
  }
  nsinfo.current_outbound_device = current_outbound_device;

  if (!datapath_->StartRoutingNamespace(nsinfo)) {
    LOG(ERROR) << "Failed to setup datapath";
    if (!DeleteLifelineFd(local_client_fd.release())) {
      LOG(ERROR) << "Failed to delete lifeline fd";
    }
    return response;
  }

  // Prepare the response before storing ConnectedNamespace.
  const auto host_cidr = nsinfo.peer_subnet->CIDRAtOffset(1);
  const auto peer_cidr = nsinfo.peer_subnet->CIDRAtOffset(2);
  if (!host_cidr || !peer_cidr) {
    LOG(ERROR) << "Failed to create CIDR from subnet: "
               << nsinfo.peer_subnet->base_cidr();
    return response;
  }
  response.set_peer_ifname(nsinfo.peer_ifname);
  response.set_peer_ipv4_address(peer_cidr->address().ToInAddr().s_addr);
  response.set_host_ifname(nsinfo.host_ifname);
  response.set_host_ipv4_address(host_cidr->address().ToInAddr().s_addr);
  response.set_netns_name(nsinfo.netns_name);
  auto* response_subnet = response.mutable_ipv4_subnet();
  FillSubnetProto(*nsinfo.peer_subnet, response_subnet);

  LOG(INFO) << "Connected network namespace " << nsinfo;

  // Start forwarding for IPv6.
  StartForwarding(nsinfo.current_outbound_device, nsinfo.host_ifname,
                  ForwardingSet{.ipv6 = true});
  base::SingleThreadTaskRunner::GetCurrentDefault()->PostDelayedTask(
      FROM_HERE,
      base::BindOnce(&Manager::RestartIPv6, weak_factory_.GetWeakPtr(),
                     nsinfo.netns_name),
      base::Milliseconds(kIPv6RestartDelayMs));

  // Store ConnectedNamespace
  connected_namespaces_next_id_++;
  int fdkey = local_client_fd.release();
  connected_namespaces_.emplace(fdkey, std::move(nsinfo));

  return response;
}

base::ScopedFD Manager::AddLifelineFd(const base::ScopedFD& dbus_fd) {
  if (!dbus_fd.is_valid()) {
    LOG(ERROR) << "Invalid client file descriptor";
    return base::ScopedFD();
  }

  // Dup the client fd into our own: this guarantees that the fd number will
  // be stable and tied to the actual kernel resources used by the client.
  // The duped fd will be watched for read events.
  int fd = dup(dbus_fd.get());
  if (fd < 0) {
    PLOG(ERROR) << "dup() failed";
    return base::ScopedFD();
  }

  lifeline_fd_controllers_[fd] = base::FileDescriptorWatcher::WatchReadable(
      fd, base::BindRepeating(&Manager::OnLifelineFdClosed,
                              // The callback will not outlive the object.
                              base::Unretained(this), fd));
  return base::ScopedFD(fd);
}

bool Manager::DeleteLifelineFd(int dbus_fd) {
  auto iter = lifeline_fd_controllers_.find(dbus_fd);
  if (iter == lifeline_fd_controllers_.end()) {
    return false;
  }

  iter->second.reset();  // Destruct the controller, which removes the callback.
  lifeline_fd_controllers_.erase(iter);

  // AddLifelineFd() calls dup(), so this function should close the fd.
  // We still return true since at this point the FileDescriptorWatcher object
  // has been destructed.
  if (IGNORE_EINTR(close(dbus_fd)) < 0) {
    PLOG(ERROR) << "close";
  }

  return true;
}

void Manager::OnLifelineFdClosed(int client_fd) {
  // The process that requested this port has died/exited.
  DeleteLifelineFd(client_fd);

  auto downstream_network_it = downstream_networks_.find(client_fd);
  if (downstream_network_it != downstream_networks_.end()) {
    const auto& info = downstream_network_it->second;
    // Stop IPv6 guest service on the downstream interface if IPv6 is enabled.
    if (info.enable_ipv6 && info.upstream_device) {
      StopForwarding(*info.upstream_device, info.downstream_ifname,
                     ForwardingSet{.ipv6 = true});
    }

    // Stop the DHCP server if exists.
    // TODO(b/274998094): Currently the DHCPServerController stop the process
    // asynchronously. It might cause the new DHCPServerController creation
    // failure if the new one is created before the process terminated. We
    // should polish the termination procedure to prevent this situation.
    dhcp_server_controllers_.erase(info.downstream_ifname);

    datapath_->StopDownstreamNetwork(info);
    LOG(INFO) << "Disconnected Downstream Network " << info;
    downstream_networks_.erase(downstream_network_it);
    return;
  }

  // Remove the rules tied to the lifeline fd.
  auto connected_namespace_it = connected_namespaces_.find(client_fd);
  if (connected_namespace_it != connected_namespaces_.end()) {
    StopForwarding(connected_namespace_it->second.current_outbound_device,
                   connected_namespace_it->second.host_ifname,
                   ForwardingSet{.ipv6 = true});
    datapath_->StopRoutingNamespace(connected_namespace_it->second);
    LOG(INFO) << "Disconnected network namespace "
              << connected_namespace_it->second;
    // This release the allocated IPv4 subnet.
    connected_namespaces_.erase(connected_namespace_it);
    return;
  }

  auto dns_redirection_it = dns_redirection_rules_.find(client_fd);
  if (dns_redirection_it == dns_redirection_rules_.end()) {
    LOG(ERROR) << "No client_fd found for " << client_fd;
    return;
  }
  auto rule = dns_redirection_it->second;
  datapath_->StopDnsRedirection(rule);
  LOG(INFO) << "Stopped DNS redirection " << rule;
  dns_redirection_rules_.erase(dns_redirection_it);
  // Propagate DNS proxy addresses change.
  if (rule.type == patchpanel::SetDnsRedirectionRuleRequest::ARC) {
    switch (GetIpFamily(rule.proxy_address)) {
      case AF_INET:
        dns_proxy_ipv4_addrs_.erase(rule.input_ifname);
        break;
      case AF_INET6:
        dns_proxy_ipv6_addrs_.erase(rule.input_ifname);
        break;
      default:
        LOG(ERROR) << "Invalid proxy address " << rule.proxy_address;
        return;
    }
    client_notifier_->OnNetworkConfigurationChanged();
  }
}

bool Manager::SetDnsRedirectionRule(const SetDnsRedirectionRuleRequest& request,
                                    const base::ScopedFD& client_fd) {
  base::ScopedFD local_client_fd = AddLifelineFd(client_fd);
  if (!local_client_fd.is_valid()) {
    LOG(ERROR) << "Failed to create lifeline fd";
    return false;
  }

  DnsRedirectionRule rule{.type = request.type(),
                          .input_ifname = request.input_ifname(),
                          .proxy_address = request.proxy_address(),
                          .host_ifname = request.host_ifname()};

  for (const auto& nameserver : request.nameservers()) {
    rule.nameservers.emplace_back(nameserver);
  }

  if (!datapath_->StartDnsRedirection(rule)) {
    LOG(ERROR) << "Failed to setup datapath";
    if (!DeleteLifelineFd(local_client_fd.release()))
      LOG(ERROR) << "Failed to delete lifeline fd";
    return false;
  }
  // Notify GuestIPv6Service to add a route for the IPv6 proxy address to the
  // namespace if it did not exist yet, so that the address is reachable.
  const auto ipv6_proxy_addr =
      net_base::IPv6Address::CreateFromString(rule.proxy_address);
  if (ipv6_proxy_addr) {
    ipv6_svc_->RegisterDownstreamNeighborIP(rule.host_ifname, *ipv6_proxy_addr);
  }

  // Propagate DNS proxy addresses change.
  if (rule.type == patchpanel::SetDnsRedirectionRuleRequest::ARC) {
    switch (GetIpFamily(rule.proxy_address)) {
      case AF_INET:
        dns_proxy_ipv4_addrs_.emplace(rule.input_ifname, rule.proxy_address);
        break;
      case AF_INET6:
        dns_proxy_ipv6_addrs_.emplace(rule.input_ifname, rule.proxy_address);
        break;
      default:
        LOG(ERROR) << "Invalid proxy address " << rule.proxy_address;
        if (!DeleteLifelineFd(local_client_fd.release()))
          LOG(ERROR) << "Failed to delete lifeline fd";
        return false;
    }
    client_notifier_->OnNetworkConfigurationChanged();
  }

  // Store DNS proxy's redirection request.
  int fdkey = local_client_fd.release();
  dns_redirection_rules_.emplace(fdkey, std::move(rule));

  return true;
}

bool Manager::ValidateDownstreamNetworkRequest(
    const DownstreamNetworkInfo& info) {
  // TODO(b/239559602) Validate the request and log any invalid argument:
  //    - |upstream_ifname| should be an active shill Device/Network,
  //    - |downstream_ifname| should not be a shill Device/Network already in
  //    use,
  //    - |downstream_ifname| should not be already in use in another
  //    DownstreamNetworkInfo,
  //    - if there are IPv4 and/or IPv6 configurations, check the prefixes are
  //      correct and available.
  //    - check the downstream subnet doesn't conflict with any IPv4
  //      configuration of the currently connected networks.
  return true;
}

patchpanel::DownstreamNetworkResult Manager::HandleDownstreamNetworkInfo(
    const base::ScopedFD& client_fd, const DownstreamNetworkInfo& info) {
  if (!ValidateDownstreamNetworkRequest(info)) {
    LOG(ERROR) << __func__ << " " << info << ": Invalid request";
    return patchpanel::DownstreamNetworkResult::INVALID_ARGUMENT;
  }

  base::ScopedFD local_client_fd = AddLifelineFd(client_fd);
  if (!local_client_fd.is_valid()) {
    LOG(ERROR) << __func__ << " " << info << ": Failed to create lifeline fd";
    return patchpanel::DownstreamNetworkResult::ERROR;
  }

  if (!datapath_->StartDownstreamNetwork(info)) {
    LOG(ERROR) << __func__ << " " << info
               << ": Failed to configure forwarding to downstream network";
    return patchpanel::DownstreamNetworkResult::ERROR;
  }

  // Start the DHCP server at downstream.
  if (info.enable_ipv4_dhcp) {
    if (dhcp_server_controllers_.find(info.downstream_ifname) !=
        dhcp_server_controllers_.end()) {
      LOG(ERROR) << __func__ << " " << info
                 << ": DHCP server is already running at "
                 << info.downstream_ifname;
      return patchpanel::DownstreamNetworkResult::INTERFACE_USED;
    }
    const auto config = info.ToDHCPServerConfig();
    if (!config) {
      LOG(ERROR) << __func__ << " " << info
                 << ": Failed to get DHCP server config";
      return patchpanel::DownstreamNetworkResult::INVALID_ARGUMENT;
    }
    auto dhcp_server_controller =
        std::make_unique<DHCPServerController>(info.downstream_ifname);
    // TODO(b/274722417) Handle the DHCP server exits unexpectedly.
    if (!dhcp_server_controller->Start(*config, base::DoNothing())) {
      LOG(ERROR) << __func__ << " " << info << ": Failed to start DHCP server";
      return patchpanel::DownstreamNetworkResult::DHCP_SERVER_FAILURE;
    }
    dhcp_server_controllers_[info.downstream_ifname] =
        std::move(dhcp_server_controller);
  }

  // Start IPv6 guest service on the downstream interface if IPv6 is enabled.
  // TODO(b/278966909) Prevents neighbor discovery between the downstream
  // network and other virtual guests and interfaces in the same upstream
  // group.
  if (info.enable_ipv6 && info.upstream_device) {
    StartForwarding(*info.upstream_device, info.downstream_ifname,
                    ForwardingSet{.ipv6 = true}, info.mtu);
  }

  int fdkey = local_client_fd.release();
  downstream_networks_[fdkey] = info;
  return patchpanel::DownstreamNetworkResult::SUCCESS;
}

void Manager::SendGuestMessage(const GuestMessage& msg) {
  ControlMessage cm;
  *cm.mutable_guest_message() = msg;
  adb_proxy_->SendControlMessage(cm);
  mcast_proxy_->SendControlMessage(cm);
}

void Manager::StartForwarding(const ShillClient::Device& shill_device,
                              const std::string& ifname_virtual,
                              const ForwardingSet& fs,
                              const std::optional<int>& mtu) {
  if (shill_device.ifname.empty() || ifname_virtual.empty())
    return;

  if (fs.ipv6) {
    ipv6_svc_->StartForwarding(shill_device, ifname_virtual, mtu);
  }

  if (fs.multicast && IsMulticastInterface(shill_device.ifname)) {
    ControlMessage cm;
    DeviceMessage* msg = cm.mutable_device_message();
    msg->set_dev_ifname(shill_device.ifname);
    msg->set_br_ifname(ifname_virtual);

    LOG(INFO) << "Starting multicast forwarding from " << shill_device << " to "
              << ifname_virtual;
    mcast_proxy_->SendControlMessage(cm);
  }
}

void Manager::StopForwarding(const ShillClient::Device& shill_device,
                             const std::string& ifname_virtual,
                             const ForwardingSet& fs) {
  if (shill_device.ifname.empty())
    return;

  if (fs.ipv6) {
    if (ifname_virtual.empty()) {
      ipv6_svc_->StopUplink(shill_device);
    } else {
      ipv6_svc_->StopForwarding(shill_device, ifname_virtual);
    }
  }

  if (fs.multicast) {
    ControlMessage cm;
    DeviceMessage* msg = cm.mutable_device_message();
    msg->set_dev_ifname(shill_device.ifname);
    msg->set_teardown(true);
    if (!ifname_virtual.empty()) {
      msg->set_br_ifname(ifname_virtual);
    }
    if (ifname_virtual.empty()) {
      LOG(INFO) << "Stopping multicast forwarding on " << shill_device;
    } else {
      LOG(INFO) << "Stopping multicast forwarding from " << shill_device
                << " to " << ifname_virtual;
    }
    mcast_proxy_->SendControlMessage(cm);
  }
}

void Manager::NotifyAndroidWifiMulticastLockChange(bool is_held) {
  // When multicast lock status changes from not held to held or the other
  // way, decide whether to enable or disable multicast forwarder for ARC.
  if (android_wifi_multicast_lock_held_ == is_held) {
    return;
  }

  // If arc is not interactive, multicast lock held status does not
  // affect multicast traffic.
  android_wifi_multicast_lock_held_ = is_held;
  if (!is_arc_interactive_) {
    return;
  }

  // Only start/stop forwarding when multicast allowed status changes to avoid
  // start/stop forwarding multiple times, also wifi multicast lock should
  // only affect multicast traffic on wireless device.
  for (const auto* device : arc_svc_->GetDevices()) {
    const auto& upstream_device = device->shill_device();
    if (upstream_device.has_value()) {
      LOG(ERROR) << __func__ << ": no upstream defined for ARC Device "
                 << device;
      continue;
    }
    if (upstream_device->type != ShillClient::Device::Type::kWifi) {
      continue;
    }
    if (android_wifi_multicast_lock_held_) {
      StartForwarding(*upstream_device, device->host_ifname(),
                      ForwardingSet{.multicast = true});
    } else {
      StopForwarding(*upstream_device, device->host_ifname(),
                     ForwardingSet{.multicast = true});
    }
  }
}

void Manager::NotifyAndroidInteractiveState(bool is_interactive) {
  // When power state of device changes, decide whether to disable
  // multicast forwarder for ARC.
  if (is_arc_interactive_ == is_interactive) {
    return;
  }

  // If ARC power state has changed to interactive, enable all
  // interfaces that are not wifi interface, and only enable wifi interfaces
  // when wifi multicast lock is held.
  // If ARC power state has changed to non-interactive, disable all
  // interfaces that are not wifi interface, and only disable wifi
  // interfaces when they were in enabled state (multicast lock held).
  is_arc_interactive_ = is_interactive;
  for (const auto* device : arc_svc_->GetDevices()) {
    const auto& upstream_device = device->shill_device();
    if (upstream_device.has_value()) {
      LOG(ERROR) << __func__ << ": no upstream defined for ARC Device "
                 << device;
      continue;
    }
    if (upstream_device->type == ShillClient::Device::Type::kWifi &&
        !android_wifi_multicast_lock_held_) {
      continue;
    }
    if (is_arc_interactive_) {
      StartForwarding(*upstream_device, device->host_ifname(),
                      ForwardingSet{.multicast = true});
    } else {
      StopForwarding(*upstream_device, device->host_ifname(),
                     ForwardingSet{.multicast = true});
    }
  }
}
}  // namespace patchpanel
