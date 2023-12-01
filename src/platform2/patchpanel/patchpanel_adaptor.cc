// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "patchpanel/patchpanel_adaptor.h"

#include <chromeos/dbus/patchpanel/dbus-constants.h>
#include <shill/net/process_manager.h>

#include "patchpanel/proto_utils.h"

namespace patchpanel {

PatchpanelAdaptor::PatchpanelAdaptor(const base::FilePath& cmd_path,
                                     scoped_refptr<::dbus::Bus> bus,
                                     System* system,
                                     shill::ProcessManager* process_manager,
                                     MetricsLibraryInterface* metrics,
                                     std::unique_ptr<RTNLClient> rtnl_client)
    : org::chromium::PatchPanelAdaptor(this),
      dbus_object_(nullptr, bus, dbus::ObjectPath(kPatchPanelServicePath)),
      metrics_(metrics),
      manager_(
          std::make_unique<Manager>(cmd_path,
                                    system,
                                    process_manager,
                                    metrics_,
                                    this,
                                    std::make_unique<ShillClient>(bus, system),
                                    std::move(rtnl_client))) {}

void PatchpanelAdaptor::RegisterAsync(
    brillo::dbus_utils::AsyncEventSequencer::CompletionAction cb) {
  RegisterWithDBusObject(&dbus_object_);
  dbus_object_.RegisterAsync(std::move(cb));
}

ArcShutdownResponse PatchpanelAdaptor::ArcShutdown(
    const ArcShutdownRequest& request) {
  LOG(INFO) << "ARC++ shutting down";
  RecordDbusEvent(DbusUmaEvent::kArcShutdown);

  manager_->ArcShutdown();
  RecordDbusEvent(DbusUmaEvent::kArcShutdownSuccess);
  return {};
}

ArcStartupResponse PatchpanelAdaptor::ArcStartup(
    const ArcStartupRequest& request) {
  LOG(INFO) << "ARC++ starting up";
  RecordDbusEvent(DbusUmaEvent::kArcStartup);

  if (!manager_->ArcStartup(request.pid())) {
    LOG(ERROR) << "Failed to start ARC++ network service";
  } else {
    RecordDbusEvent(DbusUmaEvent::kArcStartupSuccess);
  }
  return {};
}

ArcVmShutdownResponse PatchpanelAdaptor::ArcVmShutdown(
    const ArcVmShutdownRequest& request) {
  LOG(INFO) << "ARCVM shutting down";
  RecordDbusEvent(DbusUmaEvent::kArcVmShutdown);

  manager_->ArcVmShutdown(request.cid());
  RecordDbusEvent(DbusUmaEvent::kArcVmShutdownSuccess);
  return {};
}

ArcVmStartupResponse PatchpanelAdaptor::ArcVmStartup(
    const ArcVmStartupRequest& request) {
  LOG(INFO) << "ARCVM starting up";
  RecordDbusEvent(DbusUmaEvent::kArcVmStartup);

  const auto device_configs = manager_->ArcVmStartup(request.cid());
  if (!device_configs) {
    LOG(ERROR) << "Failed to start ARCVM network service";
    return {};
  }

  // Populate the response with the interface configurations of the known ARC
  // Devices
  patchpanel::ArcVmStartupResponse response;
  for (const auto* config : *device_configs) {
    if (config->tap_ifname().empty())
      continue;

    // TODO(hugobenichi) Use FillDeviceProto.
    auto* dev = response.add_devices();
    dev->set_ifname(config->tap_ifname());
    dev->set_ipv4_addr(config->guest_ipv4_addr().ToInAddr().s_addr);
    dev->set_guest_type(NetworkDevice::ARCVM);
  }

  RecordDbusEvent(DbusUmaEvent::kArcVmStartupSuccess);
  return response;
}

ConnectNamespaceResponse PatchpanelAdaptor::ConnectNamespace(
    const ConnectNamespaceRequest& request, const base::ScopedFD& client_fd) {
  RecordDbusEvent(DbusUmaEvent::kConnectNamespace);

  const auto response = manager_->ConnectNamespace(request, client_fd);
  if (!response.netns_name().empty()) {
    RecordDbusEvent(DbusUmaEvent::kConnectNamespaceSuccess);
  }
  return response;
}

LocalOnlyNetworkResponse PatchpanelAdaptor::CreateLocalOnlyNetwork(
    const LocalOnlyNetworkRequest& request, const base::ScopedFD& client_fd) {
  RecordDbusEvent(DbusUmaEvent::kCreateLocalOnlyNetwork);

  const auto response_code =
      manager_->CreateLocalOnlyNetwork(request, client_fd);
  if (response_code == patchpanel::DownstreamNetworkResult::SUCCESS) {
    RecordDbusEvent(DbusUmaEvent::kCreateLocalOnlyNetworkSuccess);
  }

  LocalOnlyNetworkResponse response;
  response.set_response_code(response_code);
  return response;
}

TetheredNetworkResponse PatchpanelAdaptor::CreateTetheredNetwork(
    const TetheredNetworkRequest& request, const base::ScopedFD& client_fd) {
  RecordDbusEvent(DbusUmaEvent::kCreateTetheredNetwork);

  const auto response_code =
      manager_->CreateTetheredNetwork(request, client_fd);
  if (response_code == patchpanel::DownstreamNetworkResult::SUCCESS) {
    RecordDbusEvent(DbusUmaEvent::kCreateTetheredNetworkSuccess);
  }

  TetheredNetworkResponse response;
  response.set_response_code(response_code);
  return response;
}

GetDevicesResponse PatchpanelAdaptor::GetDevices(
    const GetDevicesRequest& request) const {
  return manager_->GetDevices();
}

GetDownstreamNetworkInfoResponse PatchpanelAdaptor::GetDownstreamNetworkInfo(
    const GetDownstreamNetworkInfoRequest& request) const {
  RecordDbusEvent(DbusUmaEvent::kGetDownstreamNetworkInfo);

  const auto& downstream_ifname = request.downstream_ifname();
  const auto downstream_info =
      manager_->GetDownstreamNetworkInfo(downstream_ifname);
  if (!downstream_info) {
    LOG(ERROR) << __func__ << ": no DownstreamNetwork for interface "
               << downstream_ifname;
    return {};
  }

  RecordDbusEvent(DbusUmaEvent::kGetDownstreamNetworkInfoSuccess);
  GetDownstreamNetworkInfoResponse response;
  response.set_success(true);
  FillDownstreamNetworkProto(downstream_info->first,
                             response.mutable_downstream_network());
  for (const auto& info : downstream_info->second) {
    FillNetworkClientInfoProto(info, response.add_clients_info());
  }
  return response;
}

TrafficCountersResponse PatchpanelAdaptor::GetTrafficCounters(
    const TrafficCountersRequest& request) const {
  RecordDbusEvent(DbusUmaEvent::kGetTrafficCounters);

  const std::set<std::string> shill_devices{request.devices().begin(),
                                            request.devices().end()};
  const auto counters = manager_->GetTrafficCounters(shill_devices);

  TrafficCountersResponse response;
  for (const auto& kv : counters) {
    auto* traffic_counter = response.add_counters();
    const auto& key = kv.first;
    const auto& counter = kv.second;
    traffic_counter->set_source(key.source);
    traffic_counter->set_device(key.ifname);
    traffic_counter->set_ip_family(key.ip_family);
    traffic_counter->set_rx_bytes(counter.rx_bytes);
    traffic_counter->set_rx_packets(counter.rx_packets);
    traffic_counter->set_tx_bytes(counter.tx_bytes);
    traffic_counter->set_tx_packets(counter.tx_packets);
  }

  RecordDbusEvent(DbusUmaEvent::kGetTrafficCountersSuccess);
  return response;
}

ModifyPortRuleResponse PatchpanelAdaptor::ModifyPortRule(
    const ModifyPortRuleRequest& request) {
  RecordDbusEvent(DbusUmaEvent::kModifyPortRule);

  const bool success = manager_->ModifyPortRule(request);
  if (success) {
    RecordDbusEvent(DbusUmaEvent::kModifyPortRuleSuccess);
  }

  ModifyPortRuleResponse response;
  response.set_success(success);
  return response;
}

ParallelsVmShutdownResponse PatchpanelAdaptor::ParallelsVmShutdown(
    const ParallelsVmShutdownRequest& request) {
  LOG(INFO) << "Parallels VM shutting down";
  RecordDbusEvent(DbusUmaEvent::kParallelsVmShutdown);

  manager_->ParallelsVmShutdown(request.id());

  RecordDbusEvent(DbusUmaEvent::kParallelsVmShutdownSuccess);
  return {};
}

ParallelsVmStartupResponse PatchpanelAdaptor::ParallelsVmStartup(
    const ParallelsVmStartupRequest& request) {
  LOG(INFO) << "Parallels VM starting up";
  RecordDbusEvent(DbusUmaEvent::kParallelsVmStartup);

  if (request.subnet_index() < 0) {
    LOG(ERROR) << "Invalid subnet index: " << request.subnet_index();
    return {};
  }
  const uint32_t subnet_index = static_cast<uint32_t>(request.subnet_index());
  const uint64_t vm_id = request.id();
  const auto* const guest_device =
      manager_->ParallelsVmStartup(vm_id, subnet_index);
  if (!guest_device) {
    LOG(DFATAL) << "Parallels VM TAP Device missing";
    return {};
  }
  if (!guest_device->config().ipv4_subnet()) {
    LOG(DFATAL) << "Missing required subnet for {cid: " << vm_id << "}";
    return {};
  }

  ParallelsVmStartupResponse response;
  auto* dev = response.mutable_device();
  dev->set_guest_type(NetworkDevice::PARALLELS_VM);
  FillDeviceProto(*guest_device, dev);

  RecordDbusEvent(DbusUmaEvent::kParallelsVmStartupSuccess);
  return response;
}

SetDnsRedirectionRuleResponse PatchpanelAdaptor::SetDnsRedirectionRule(
    const SetDnsRedirectionRuleRequest& request,
    const base::ScopedFD& client_fd) {
  RecordDbusEvent(DbusUmaEvent::kSetDnsRedirectionRule);

  const bool success = manager_->SetDnsRedirectionRule(request, client_fd);
  if (success) {
    RecordDbusEvent(DbusUmaEvent::kSetDnsRedirectionRuleSuccess);
  }

  SetDnsRedirectionRuleResponse response;
  response.set_success(success);
  return response;
}

SetVpnIntentResponse PatchpanelAdaptor::SetVpnIntent(
    const SetVpnIntentRequest& request, const base::ScopedFD& socket_fd) {
  RecordDbusEvent(DbusUmaEvent::kSetVpnIntent);

  const bool success = manager_->SetVpnIntent(request.policy(), socket_fd);
  if (!success) {
    LOG(ERROR) << "Failed to set VpnIntent: " << request.policy();
    return {};
  }

  RecordDbusEvent(DbusUmaEvent::kSetVpnIntentSuccess);
  SetVpnIntentResponse response;
  response.set_success(true);
  return response;
}

SetVpnLockdownResponse PatchpanelAdaptor::SetVpnLockdown(
    const SetVpnLockdownRequest& request) {
  RecordDbusEvent(DbusUmaEvent::kSetVpnLockdown);

  manager_->SetVpnLockdown(request.enable_vpn_lockdown());

  RecordDbusEvent(DbusUmaEvent::kSetVpnLockdownSuccess);
  return {};
}

TerminaVmShutdownResponse PatchpanelAdaptor::TerminaVmShutdown(
    const TerminaVmShutdownRequest& request) {
  LOG(INFO) << "Termina VM shutting down";
  RecordDbusEvent(DbusUmaEvent::kTerminaVmShutdown);

  manager_->TerminaVmShutdown(request.cid());

  RecordDbusEvent(DbusUmaEvent::kTerminaVmShutdownSuccess);
  return {};
}

TerminaVmStartupResponse PatchpanelAdaptor::TerminaVmStartup(
    const TerminaVmStartupRequest& request) {
  LOG(INFO) << "Termina VM starting up";
  RecordDbusEvent(DbusUmaEvent::kTerminaVmStartup);

  const uint32_t cid = request.cid();
  const auto* const guest_device = manager_->TerminaVmStartup(cid);

  if (!guest_device) {
    return {};
  }
  if (!guest_device->config().ipv4_subnet()) {
    LOG(DFATAL) << "Missing required Termina IPv4 subnet for {cid: " << cid
                << "}";
    return {};
  }
  const auto* lxd_subnet = guest_device->config().lxd_ipv4_subnet();
  if (!lxd_subnet) {
    LOG(DFATAL) << "Missing required lxd container IPv4 subnet for {cid: "
                << cid << "}";
    return {};
  }

  TerminaVmStartupResponse response;
  auto* dev = response.mutable_device();
  FillDeviceProto(*guest_device, dev);
  FillSubnetProto(*lxd_subnet, response.mutable_container_subnet());

  RecordDbusEvent(DbusUmaEvent::kTerminaVmStartupSuccess);
  return response;
}

NotifyAndroidWifiMulticastLockChangeResponse
PatchpanelAdaptor::NotifyAndroidWifiMulticastLockChange(
    const NotifyAndroidWifiMulticastLockChangeRequest& request) {
  manager_->NotifyAndroidWifiMulticastLockChange(request.held());
  return {};
}

NotifyAndroidInteractiveStateResponse
PatchpanelAdaptor::NotifyAndroidInteractiveState(
    const NotifyAndroidInteractiveStateRequest& request) {
  manager_->NotifyAndroidInteractiveState(request.interactive());
  return {};
}

void PatchpanelAdaptor::OnNetworkDeviceChanged(const Device& virtual_device,
                                               Device::ChangeEvent event) {
  NetworkDeviceChangedSignal signal;
  signal.set_event(event == Device::ChangeEvent::kAdded
                       ? NetworkDeviceChangedSignal::DEVICE_ADDED
                       : NetworkDeviceChangedSignal::DEVICE_REMOVED);
  auto* dev = signal.mutable_device();
  FillDeviceProto(virtual_device, dev);
  SendNetworkDeviceChangedSignal(signal);
}

void PatchpanelAdaptor::OnNetworkConfigurationChanged() {
  NetworkConfigurationChangedSignal signal;
  SendNetworkConfigurationChangedSignal(signal);
}

void PatchpanelAdaptor::OnNeighborReachabilityEvent(
    int ifindex,
    const shill::IPAddress& ip_addr,
    NeighborLinkMonitor::NeighborRole role,
    NeighborReachabilityEventSignal::EventType event_type) {
  NeighborReachabilityEventSignal signal;
  signal.set_ifindex(ifindex);
  signal.set_ip_addr(ip_addr.ToString());
  signal.set_type(event_type);
  switch (role) {
    case NeighborLinkMonitor::NeighborRole::kGateway:
      signal.set_role(NeighborReachabilityEventSignal::GATEWAY);
      break;
    case NeighborLinkMonitor::NeighborRole::kDNSServer:
      signal.set_role(NeighborReachabilityEventSignal::DNS_SERVER);
      break;
    case NeighborLinkMonitor::NeighborRole::kGatewayAndDNSServer:
      signal.set_role(NeighborReachabilityEventSignal::GATEWAY_AND_DNS_SERVER);
      break;
    default:
      NOTREACHED();
  }
  SendNeighborReachabilityEventSignal(signal);
}

void PatchpanelAdaptor::RecordDbusEvent(DbusUmaEvent event) const {
  metrics_->SendEnumToUMA(kDbusUmaEventMetrics, event);
}

}  // namespace patchpanel
