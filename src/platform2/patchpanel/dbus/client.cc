// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "patchpanel/dbus/client.h"

#include <fcntl.h>
#include <string.h>

#include <algorithm>
#include <optional>

#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/memory/weak_ptr.h>
#include <base/synchronization/waitable_event.h>
#include <base/strings/string_util.h>
#include <base/task/bind_post_task.h>
#include <base/time/time.h>
#include <brillo/dbus/dbus_proxy_util.h>
#include <chromeos/dbus/service_constants.h>
#include <dbus/message.h>
#include <dbus/object_path.h>
#include <patchpanel/proto_bindings/patchpanel_service.pb.h>

#include "patchpanel/dbus-proxies.h"
#include "patchpanel/net_util.h"

namespace patchpanel {

namespace {

using org::chromium::PatchPanelProxyInterface;

void CopyBytes(const std::string& from, std::vector<uint8_t>* to) {
  to->assign(from.begin(), from.end());
}

patchpanel::TrafficCounter::Source ConvertTrafficSource(
    Client::TrafficSource source) {
  switch (source) {
    case Client::TrafficSource::kUnknown:
      return patchpanel::TrafficCounter::UNKNOWN;
    case Client::TrafficSource::kChrome:
      return patchpanel::TrafficCounter::CHROME;
    case Client::TrafficSource::kUser:
      return patchpanel::TrafficCounter::USER;
    case Client::TrafficSource::kArc:
      return patchpanel::TrafficCounter::ARC;
    case Client::TrafficSource::kCrosVm:
      return patchpanel::TrafficCounter::CROSVM;
    case Client::TrafficSource::kParallelsVm:
      return patchpanel::TrafficCounter::PARALLELS_VM;
    case Client::TrafficSource::kUpdateEngine:
      return patchpanel::TrafficCounter::UPDATE_ENGINE;
    case Client::TrafficSource::kVpn:
      return patchpanel::TrafficCounter::VPN;
    case Client::TrafficSource::kSystem:
      return patchpanel::TrafficCounter::SYSTEM;
  }
}

Client::TrafficSource ConvertTrafficSource(
    patchpanel::TrafficCounter::Source source) {
  switch (source) {
    case patchpanel::TrafficCounter::CHROME:
      return Client::TrafficSource::kChrome;
    case patchpanel::TrafficCounter::USER:
      return Client::TrafficSource::kUser;
    case patchpanel::TrafficCounter::ARC:
      return Client::TrafficSource::kArc;
    case patchpanel::TrafficCounter::CROSVM:
      return Client::TrafficSource::kCrosVm;
    case patchpanel::TrafficCounter::PARALLELS_VM:
      return Client::TrafficSource::kParallelsVm;
    case patchpanel::TrafficCounter::UPDATE_ENGINE:
      return Client::TrafficSource::kUpdateEngine;
    case patchpanel::TrafficCounter::VPN:
      return Client::TrafficSource::kVpn;
    case patchpanel::TrafficCounter::SYSTEM:
      return Client::TrafficSource::kSystem;
    default:
      return Client::TrafficSource::kUnknown;
  }
}

patchpanel::NeighborReachabilityEventSignal::Role ConvertNeighborRole(
    Client::NeighborRole role) {
  switch (role) {
    case Client::NeighborRole::kGateway:
      return patchpanel::NeighborReachabilityEventSignal::GATEWAY;
    case Client::NeighborRole::kDnsServer:
      return patchpanel::NeighborReachabilityEventSignal::DNS_SERVER;
    case Client::NeighborRole::kGatewayAndDnsServer:
      return patchpanel::NeighborReachabilityEventSignal::
          GATEWAY_AND_DNS_SERVER;
  }
}

patchpanel::NeighborReachabilityEventSignal::EventType ConvertNeighborStatus(
    Client::NeighborStatus status) {
  switch (status) {
    case Client::NeighborStatus::kFailed:
      return patchpanel::NeighborReachabilityEventSignal::FAILED;
    case Client::NeighborStatus::kReachable:
      return patchpanel::NeighborReachabilityEventSignal::REACHABLE;
  }
}

patchpanel::ModifyPortRuleRequest::Operation ConvertFirewallRequestOperation(
    Client::FirewallRequestOperation op) {
  switch (op) {
    case Client::FirewallRequestOperation::kCreate:
      return ModifyPortRuleRequest::CREATE;
    case Client::FirewallRequestOperation::kDelete:
      return ModifyPortRuleRequest::DELETE;
  }
}

patchpanel::ModifyPortRuleRequest::RuleType ConvertFirewallRequestType(
    Client::FirewallRequestType type) {
  switch (type) {
    case Client::FirewallRequestType::kAccess:
      return ModifyPortRuleRequest::ACCESS;
    case Client::FirewallRequestType::kLockdown:
      return ModifyPortRuleRequest::LOCKDOWN;
    case Client::FirewallRequestType::kForwarding:
      return ModifyPortRuleRequest::FORWARDING;
  }
}

patchpanel::ModifyPortRuleRequest::Protocol ConvertFirewallRequestProtocol(
    Client::FirewallRequestProtocol protocol) {
  switch (protocol) {
    case Client::FirewallRequestProtocol::kTcp:
      return ModifyPortRuleRequest::TCP;
    case Client::FirewallRequestProtocol::kUdp:
      return ModifyPortRuleRequest::UDP;
  }
}

patchpanel::SetDnsRedirectionRuleRequest::RuleType
ConvertDnsRedirectionRequestType(Client::DnsRedirectionRequestType type) {
  switch (type) {
    case Client::DnsRedirectionRequestType::kDefault:
      return patchpanel::SetDnsRedirectionRuleRequest::DEFAULT;
    case Client::DnsRedirectionRequestType::kArc:
      return patchpanel::SetDnsRedirectionRuleRequest::ARC;
    case Client::DnsRedirectionRequestType::kUser:
      return patchpanel::SetDnsRedirectionRuleRequest::USER;
    case Client::DnsRedirectionRequestType::kExcludeDestination:
      return patchpanel::SetDnsRedirectionRuleRequest::EXCLUDE_DESTINATION;
  }
}

Client::IPv4Subnet ConvertIPv4Subnet(const IPv4Subnet& in) {
  Client::IPv4Subnet out = {};
  out.base_addr.assign(in.addr().begin(), in.addr().begin());
  CopyBytes(in.addr(), &out.base_addr);
  out.prefix_len = static_cast<int>(in.prefix_len());
  return out;
}

std::optional<Client::TrafficCounter> ConvertTrafficCounter(
    const TrafficCounter& in) {
  auto out = std::make_optional<Client::TrafficCounter>();
  out->rx_bytes = in.rx_bytes();
  out->tx_bytes = in.tx_bytes();
  out->rx_packets = in.rx_packets();
  out->tx_packets = in.tx_packets();
  out->ifname = in.device();
  out->source = ConvertTrafficSource(in.source());
  switch (in.ip_family()) {
    case patchpanel::TrafficCounter::IPV4:
      out->ip_family = Client::IPFamily::kIPv4;
      break;
    case patchpanel::TrafficCounter::IPV6:
      out->ip_family = Client::IPFamily::kIPv6;
      break;
    default:
      LOG(ERROR) << __func__ << ": Unknown IpFamily "
                 << patchpanel::TrafficCounter::IpFamily_Name(in.ip_family());
      return std::nullopt;
  }
  return out;
}

std::optional<Client::VirtualDevice> ConvertVirtualDevice(
    const NetworkDevice& in) {
  auto out = std::make_optional<Client::VirtualDevice>();
  out->ifname = in.ifname();
  out->phys_ifname = in.phys_ifname();
  out->guest_ifname = in.guest_ifname();
  out->ipv4_addr = ConvertUint32ToIPv4Address(in.ipv4_addr());
  out->host_ipv4_addr = ConvertUint32ToIPv4Address(in.host_ipv4_addr());
  out->ipv4_subnet = ConvertIPv4Subnet(in.ipv4_subnet());

  out->dns_proxy_ipv4_addr = net_base::IPv4Address::CreateFromBytes(
      in.dns_proxy_ipv4_addr().data(), in.dns_proxy_ipv4_addr().size());
  out->dns_proxy_ipv6_addr = net_base::IPv6Address::CreateFromBytes(
      in.dns_proxy_ipv6_addr().data(), in.dns_proxy_ipv6_addr().size());

  switch (in.guest_type()) {
    case patchpanel::NetworkDevice::ARC:
      out->guest_type = Client::GuestType::kArcContainer;
      break;
    case patchpanel::NetworkDevice::ARCVM:
      out->guest_type = Client::GuestType::kArcVm;
      break;
    case patchpanel::NetworkDevice::TERMINA_VM:
      out->guest_type = Client::GuestType::kTerminaVm;
      break;
    case patchpanel::NetworkDevice::PARALLELS_VM:
      out->guest_type = Client::GuestType::kParallelsVm;
      break;
    default:
      LOG(ERROR) << __func__ << ": Unknown GuestType "
                 << patchpanel::NetworkDevice::GuestType_Name(in.guest_type());
      return std::nullopt;
  }
  return out;
}

std::optional<Client::NetworkClientInfo> ConvertNetworkClientInfo(
    const NetworkClientInfo& in) {
  auto out = std::make_optional<Client::NetworkClientInfo>();
  std::copy(in.mac_addr().begin(), in.mac_addr().end(),
            std::back_inserter(out->mac_addr));
  const auto ipv4_addr = net_base::IPv4Address::CreateFromBytes(
      in.ipv4_addr().data(), in.ipv4_addr().size());
  if (!ipv4_addr) {
    LOG(ERROR) << "Failed to convert protobuf bytes to IPv4Address. size="
               << in.ipv4_addr().size();
    return std::nullopt;
  }
  out->ipv4_addr = *ipv4_addr;
  for (const auto& in_ipv6_addr : in.ipv6_addresses()) {
    const auto ipv6_addr = net_base::IPv6Address::CreateFromBytes(
        in_ipv6_addr.data(), in_ipv6_addr.size());
    if (!ipv6_addr) {
      LOG(ERROR) << "Failed to convert protobuf bytes to IPv6Address. size="
                 << in_ipv6_addr.size();
      return std::nullopt;
    }
    out->ipv6_addresses.push_back(*ipv6_addr);
  }
  out->hostname = in.hostname();
  out->vendor_class = in.vendor_class();
  return out;
}

std::optional<Client::DownstreamNetwork> ConvertDownstreamNetwork(
    const DownstreamNetwork& in) {
  auto out = std::make_optional<Client::DownstreamNetwork>();
  out->ifname = in.downstream_ifname();
  out->ipv4_subnet = ConvertIPv4Subnet(in.ipv4_subnet());
  const auto ipv4_gateway_addr = net_base::IPv4Address::CreateFromBytes(
      in.ipv4_gateway_addr().data(), in.ipv4_gateway_addr().size());
  if (!ipv4_gateway_addr) {
    LOG(ERROR) << "Failed to create IPv4Address for gateway address: size="
               << in.ipv4_gateway_addr().size();
    return std::nullopt;
  }
  out->ipv4_gateway_addr = *ipv4_gateway_addr;
  return out;
}

std::optional<Client::NeighborReachabilityEvent>
ConvertNeighborReachabilityEvent(const NeighborReachabilityEventSignal& in) {
  auto out = std::make_optional<Client::NeighborReachabilityEvent>();
  out->ifindex = in.ifindex();
  out->ip_addr = in.ip_addr();
  switch (in.role()) {
    case patchpanel::NeighborReachabilityEventSignal::GATEWAY:
      out->role = Client::NeighborRole::kGateway;
      break;
    case patchpanel::NeighborReachabilityEventSignal::DNS_SERVER:
      out->role = Client::NeighborRole::kDnsServer;
      break;
    case patchpanel::NeighborReachabilityEventSignal::GATEWAY_AND_DNS_SERVER:
      out->role = Client::NeighborRole::kGatewayAndDnsServer;
      break;
    default:
      LOG(ERROR) << __func__ << ": Unknown NeighborReachability role "
                 << patchpanel::NeighborReachabilityEventSignal::Role_Name(
                        in.role());
      return std::nullopt;
  }
  switch (in.type()) {
    case patchpanel::NeighborReachabilityEventSignal::FAILED:
      out->status = Client::NeighborStatus::kFailed;
      break;
    case patchpanel::NeighborReachabilityEventSignal::REACHABLE:
      out->status = Client::NeighborStatus::kReachable;
      break;
    default:
      LOG(ERROR) << __func__ << ": Unknown NeighborReachability event type "
                 << patchpanel::NeighborReachabilityEventSignal::EventType_Name(
                        in.type());
      return std::nullopt;
  }
  return out;
}

std::optional<Client::VirtualDeviceEvent> ConvertVirtualDeviceEvent(
    const NetworkDeviceChangedSignal& in) {
  switch (in.event()) {
    case patchpanel::NetworkDeviceChangedSignal::DEVICE_ADDED:
      return Client::VirtualDeviceEvent::kAdded;
    case patchpanel::NetworkDeviceChangedSignal::DEVICE_REMOVED:
      return Client::VirtualDeviceEvent::kRemoved;
    default:
      LOG(ERROR) << __func__ << ": Unknown NetworkDeviceChangedSignal event "
                 << patchpanel::NetworkDeviceChangedSignal::Event_Name(
                        in.event());
      return std::nullopt;
  }
}

Client::ConnectedNamespace ConvertConnectedNamespace(
    const ConnectNamespaceResponse& in) {
  Client::ConnectedNamespace out;
  out.ipv4_subnet = ConvertIPv4Subnet(in.ipv4_subnet());
  out.peer_ifname = in.peer_ifname();
  out.peer_ipv4_address = ConvertUint32ToIPv4Address(in.peer_ipv4_address());
  out.host_ifname = in.host_ifname();
  out.host_ipv4_address = ConvertUint32ToIPv4Address(in.host_ipv4_address());
  out.netns_name = in.netns_name();
  return out;
}

std::ostream& operator<<(std::ostream& stream,
                         const ModifyPortRuleRequest& request) {
  stream << "{ operation: "
         << ModifyPortRuleRequest::Operation_Name(request.op())
         << ", rule type: "
         << ModifyPortRuleRequest::RuleType_Name(request.type())
         << ", protocol: "
         << ModifyPortRuleRequest::Protocol_Name(request.proto());
  if (!request.input_ifname().empty()) {
    stream << ", input interface name: " << request.input_ifname();
  }
  if (!request.input_dst_ip().empty()) {
    stream << ", input destination IP: " << request.input_dst_ip();
  }
  stream << ", input destination port: " << request.input_dst_port();
  if (!request.dst_ip().empty()) {
    stream << ", destination IP: " << request.dst_ip();
  }
  if (request.dst_port() != 0) {
    stream << ", destination port: " << request.dst_port();
  }
  stream << " }";
  return stream;
}

std::ostream& operator<<(std::ostream& stream,
                         const SetDnsRedirectionRuleRequest& request) {
  stream << "{ proxy type: "
         << SetDnsRedirectionRuleRequest::RuleType_Name(request.type());
  if (!request.input_ifname().empty()) {
    stream << ", input interface name: " << request.input_ifname();
  }
  if (!request.proxy_address().empty()) {
    stream << ", proxy IPv4 address: " << request.proxy_address();
  }
  if (!request.nameservers().empty()) {
    std::vector<std::string> nameservers;
    for (const auto& ns : request.nameservers()) {
      nameservers.emplace_back(ns);
    }
    stream << ", nameserver(s): " << base::JoinString(nameservers, ",");
  }
  stream << " }";
  return stream;
}

// Prepares a pair of ScopedFDs corresponding to the write end (pair first
// element) and read end (pair second element) of a Linux pipe. The client must
// keep the write end alive until the setup requested from patchpanel is not
// necessary anymore.
std::pair<base::ScopedFD, base::ScopedFD> CreateLifelineFd() {
  int pipe_fds[2] = {-1, -1};
  if (pipe2(pipe_fds, O_CLOEXEC) < 0) {
    PLOG(ERROR) << "Failed to create a pair of fds with pipe2()";
    return {};
  }
  return {base::ScopedFD(pipe_fds[0]), base::ScopedFD(pipe_fds[1])};
}

void OnGetTrafficCountersDBusResponse(
    Client::GetTrafficCountersCallback callback,
    const TrafficCountersResponse& response) {
  std::vector<Client::TrafficCounter> counters;
  for (const auto& proto_counter : response.counters()) {
    auto client_counter = ConvertTrafficCounter(proto_counter);
    if (client_counter) {
      counters.push_back(*client_counter);
    }
  }
  std::move(callback).Run(counters);
}

void OnGetTrafficCountersError(Client::GetTrafficCountersCallback callback,
                               brillo::Error* error) {
  LOG(ERROR) << __func__ << "(): " << error->GetMessage();
  std::move(callback).Run({});
}

void OnNetworkDeviceChanged(
    Client::VirtualDeviceEventHandler handler,
    const patchpanel::NetworkDeviceChangedSignal& signal) {
  const auto event = ConvertVirtualDeviceEvent(signal);
  if (!event) {
    return;
  }

  const auto device = ConvertVirtualDevice(signal.device());
  if (!device) {
    return;
  }

  handler.Run(*event, *device);
}

void OnNeighborReachabilityEvent(
    const Client::NeighborReachabilityEventHandler& handler,
    const NeighborReachabilityEventSignal& signal) {
  const auto event = ConvertNeighborReachabilityEvent(signal);
  if (event) {
    handler.Run(*event);
  }
}

void OnSignalConnectedCallback(const std::string& interface_name,
                               const std::string& signal_name,
                               bool success) {
  if (!success)
    LOG(ERROR) << "Failed to connect to " << signal_name;
}

// Helper static function to process answers to CreateTetheredNetwork calls.
void OnTetheredNetworkResponse(Client::CreateTetheredNetworkCallback callback,
                               base::ScopedFD fd_local,
                               const TetheredNetworkResponse& response) {
  if (response.response_code() != DownstreamNetworkResult::SUCCESS) {
    LOG(ERROR) << kCreateTetheredNetworkMethod << " failed: "
               << patchpanel::DownstreamNetworkResult_Name(
                      response.response_code());
    std::move(callback).Run({});
    return;
  }

  std::move(callback).Run(std::move(fd_local));
}

void OnTetheredNetworkError(Client::CreateTetheredNetworkCallback callback,
                            brillo::Error* error) {
  LOG(ERROR) << __func__ << "(): " << error->GetMessage();
  std::move(callback).Run({});
}

// Helper static function to process answers to CreateLocalOnlyNetwork calls.
void OnLocalOnlyNetworkResponse(Client::CreateLocalOnlyNetworkCallback callback,
                                base::ScopedFD fd_local,
                                const LocalOnlyNetworkResponse& response) {
  if (response.response_code() != DownstreamNetworkResult::SUCCESS) {
    LOG(ERROR) << kCreateLocalOnlyNetworkMethod << " failed: "
               << patchpanel::DownstreamNetworkResult_Name(
                      response.response_code());
    std::move(callback).Run({});
    return;
  }

  std::move(callback).Run(std::move(fd_local));
}

void OnLocalOnlyNetworkError(Client::CreateLocalOnlyNetworkCallback callback,
                             brillo::Error* error) {
  LOG(ERROR) << __func__ << "(): " << error->GetMessage();
  std::move(callback).Run({});
}

// Helper static function to process answers to GetDownstreamNetworkInfo calls.
void OnGetDownstreamNetworkInfoResponse(
    Client::GetDownstreamNetworkInfoCallback callback,
    const GetDownstreamNetworkInfoResponse& response) {
  auto downstream_network =
      ConvertDownstreamNetwork(response.downstream_network());
  if (!downstream_network) {
    std::move(callback).Run(false, {}, {});
    return;
  }

  std::vector<Client::NetworkClientInfo> clients_info;
  for (const auto& ci : response.clients_info()) {
    const auto info = ConvertNetworkClientInfo(ci);
    if (info) {
      clients_info.push_back(*info);
    }
  }

  std::move(callback).Run(true, *downstream_network, clients_info);
}

void OnGetDownstreamNetworkInfoError(
    Client::GetDownstreamNetworkInfoCallback callback, brillo::Error* error) {
  LOG(ERROR) << __func__ << "(): " << error->GetMessage();
  std::move(callback).Run(false, {}, {});
}

class ClientImpl : public Client {
 public:
  ClientImpl(scoped_refptr<dbus::Bus> bus,
             std::unique_ptr<org::chromium::PatchPanelProxyInterface> proxy,
             bool owns_bus)
      : bus_(std::move(bus)), proxy_(std::move(proxy)), owns_bus_(owns_bus) {}

  ClientImpl(const ClientImpl&) = delete;
  ClientImpl& operator=(const ClientImpl&) = delete;

  ~ClientImpl();

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
                          GetTrafficCountersCallback callback) override;

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
      NeighborReachabilityEventHandler handler) override;

  bool CreateTetheredNetwork(const std::string& downstream_ifname,
                             const std::string& upstream_ifname,
                             const std::optional<DHCPOptions>& dhcp_options,
                             const std::optional<int>& mtu,
                             CreateTetheredNetworkCallback callback) override;

  bool CreateLocalOnlyNetwork(const std::string& ifname,
                              CreateLocalOnlyNetworkCallback callback) override;

  bool GetDownstreamNetworkInfo(
      const std::string& ifname,
      GetDownstreamNetworkInfoCallback callback) override;

 private:
  // Runs the |task| on the DBus thread synchronously.
  // The generated proxy uses brillo::dbus_utils::CallMethod*(), which asserts
  // to be executed on the DBus thread, instead of hopping on the DBus thread.
  // Therefore we need to do it by ourselves.
  bool RunOnDBusThreadSync(base::OnceCallback<bool()> task) {
    if (!bus_->HasDBusThread() ||
        bus_->GetDBusTaskRunner()->RunsTasksInCurrentSequence()) {
      return std::move(task).Run();
    }

    base::WaitableEvent event;
    bool result = false;
    bus_->GetDBusTaskRunner()->PostTask(
        FROM_HERE, base::BindOnce(
                       [](base::OnceCallback<bool()> task, bool* result,
                          base::WaitableEvent* event) {
                         *result = std::move(task).Run();
                         event->Signal();
                       },
                       std::move(task), base::Unretained(&result),
                       base::Unretained(&event)));
    event.Wait();
    return result;
  }

  // Runs the |task| on the DBus thread asynchronously.
  // The generated proxy uses brillo::dbus_utils::CallMethod*(), which asserts
  // to be executed on the DBus thread, instead of hopping on the DBus thread.
  // Therefore we need to do it by ourselves.
  void RunOnDBusThreadAsync(base::OnceClosure task) {
    if (!bus_->HasDBusThread() ||
        bus_->GetDBusTaskRunner()->RunsTasksInCurrentSequence()) {
      std::move(task).Run();
      return;
    }

    bus_->GetDBusTaskRunner()->PostTask(FROM_HERE, std::move(task));
  }

  scoped_refptr<dbus::Bus> bus_;
  std::unique_ptr<org::chromium::PatchPanelProxyInterface> proxy_;
  bool owns_bus_;  // Yes if |bus_| is created by Client::New

  base::RepeatingCallback<void(bool)> owner_callback_;

  void OnOwnerChanged(const std::string& old_owner,
                      const std::string& new_owner);

  bool SendSetVpnIntentRequest(const base::ScopedFD& socket,
                               SetVpnIntentRequest::VpnRoutingPolicy policy);

  base::WeakPtrFactory<ClientImpl> weak_factory_{this};
};

ClientImpl::~ClientImpl() {
  if (bus_ && owns_bus_)
    bus_->ShutdownAndBlock();
}

void ClientImpl::RegisterOnAvailableCallback(
    base::RepeatingCallback<void(bool)> callback) {
  auto* object_proxy = proxy_->GetObjectProxy();
  if (!object_proxy) {
    LOG(ERROR) << "Cannot register callback - no proxy";
    return;
  }
  object_proxy->WaitForServiceToBeAvailable(callback);
}

void ClientImpl::RegisterProcessChangedCallback(
    base::RepeatingCallback<void(bool)> callback) {
  owner_callback_ = callback;
  bus_->GetObjectProxy(kPatchPanelServiceName, dbus::ObjectPath{"/"})
      ->SetNameOwnerChangedCallback(base::BindRepeating(
          &ClientImpl::OnOwnerChanged, weak_factory_.GetWeakPtr()));
}

void ClientImpl::OnOwnerChanged(const std::string& old_owner,
                                const std::string& new_owner) {
  if (new_owner.empty()) {
    LOG(INFO) << "Patchpanel lost";
    if (!owner_callback_.is_null())
      owner_callback_.Run(false);
    return;
  }

  LOG(INFO) << "Patchpanel reset";
  if (!owner_callback_.is_null())
    owner_callback_.Run(true);
}

bool ClientImpl::NotifyArcStartup(pid_t pid) {
  ArcStartupRequest request;
  request.set_pid(pid);

  // TODO(b/284076578): Check if we can call the DBus method asynchronously.
  ArcStartupResponse response;
  brillo::ErrorPtr error;
  const bool result = RunOnDBusThreadSync(base::BindOnce(
      [](PatchPanelProxyInterface* proxy, const ArcStartupRequest& request,
         ArcStartupResponse* response, brillo::ErrorPtr* error) {
        return proxy->ArcStartup(request, response, error);
      },
      proxy_.get(), request, &response, &error));
  if (!result) {
    LOG(ERROR) << "ARC network startup failed: " << error->GetMessage();
    return false;
  }

  return true;
}

bool ClientImpl::NotifyArcShutdown() {
  // TODO(b/284076578): Check if we can call the DBus method asynchronously.
  brillo::ErrorPtr error;
  const bool result = RunOnDBusThreadSync(base::BindOnce(
      [](PatchPanelProxyInterface* proxy, brillo::ErrorPtr* error) {
        ArcShutdownResponse response;
        return proxy->ArcShutdown({}, &response, error);
      },
      proxy_.get(), &error));
  if (!result) {
    LOG(ERROR) << "ARC network shutdown failed: " << error->GetMessage();
    return false;
  }

  return true;
}

std::vector<Client::VirtualDevice> ClientImpl::NotifyArcVmStartup(
    uint32_t cid) {
  ArcVmStartupRequest request;
  request.set_cid(cid);

  // TODO(b/284076578): Check if concierge can handle the result asynchronously.
  ArcVmStartupResponse response;
  brillo::ErrorPtr error;
  const bool result = RunOnDBusThreadSync(base::BindOnce(
      [](PatchPanelProxyInterface* proxy, const ArcVmStartupRequest& request,
         ArcVmStartupResponse* response, brillo::ErrorPtr* error) {
        return proxy->ArcVmStartup(request, response, error);
      },
      proxy_.get(), request, &response, &error));
  if (!result) {
    LOG(ERROR) << "ARCVM network startup failed: " << error->GetMessage();
    return {};
  }

  std::vector<Client::VirtualDevice> devices;
  for (const auto& d : response.devices()) {
    const auto device = ConvertVirtualDevice(d);
    if (device) {
      devices.push_back(*device);
    }
  }
  return devices;
}

bool ClientImpl::NotifyArcVmShutdown(uint32_t cid) {
  ArcVmShutdownRequest request;
  request.set_cid(cid);

  // TODO(b/284076578): Check if concierge can handle the result asynchronously.
  ArcVmShutdownResponse response;
  brillo::ErrorPtr error;
  const bool result = RunOnDBusThreadSync(base::BindOnce(
      [](PatchPanelProxyInterface* proxy, const ArcVmShutdownRequest& request,
         ArcVmShutdownResponse* response, brillo::ErrorPtr* error) {
        return proxy->ArcVmShutdown(request, response, error);
      },
      proxy_.get(), request, &response, &error));
  if (!result) {
    LOG(ERROR) << "ARCVM network shutdown failed: " << error->GetMessage();
  }

  return result;
}

bool ClientImpl::NotifyTerminaVmStartup(uint32_t cid,
                                        Client::VirtualDevice* device,
                                        Client::IPv4Subnet* container_subnet) {
  TerminaVmStartupRequest request;
  request.set_cid(cid);

  TerminaVmStartupResponse response;
  brillo::ErrorPtr error;
  const bool result = RunOnDBusThreadSync(base::BindOnce(
      [](PatchPanelProxyInterface* proxy,
         const TerminaVmStartupRequest& request,
         TerminaVmStartupResponse* response, brillo::ErrorPtr* error) {
        return proxy->TerminaVmStartup(request, response, error);
      },
      proxy_.get(), request, &response, &error));
  if (!result) {
    LOG(ERROR) << "TerminaVM network startup failed: " << error->GetMessage();
    return false;
  }

  if (!response.has_device()) {
    LOG(ERROR) << "No virtual device found";
    return false;
  }

  const auto response_device = ConvertVirtualDevice(response.device());
  if (!response_device) {
    LOG(ERROR) << "Invalid virtual device response";
    return false;
  }
  *device = *response_device;

  if (response.has_container_subnet()) {
    *container_subnet = ConvertIPv4Subnet(response.container_subnet());
  } else {
    LOG(WARNING) << "No container subnet found";
  }

  return true;
}

bool ClientImpl::NotifyTerminaVmShutdown(uint32_t cid) {
  TerminaVmShutdownRequest request;
  request.set_cid(cid);

  TerminaVmShutdownResponse response;
  brillo::ErrorPtr error;
  const bool result = RunOnDBusThreadSync(base::BindOnce(
      [](PatchPanelProxyInterface* proxy,
         const TerminaVmShutdownRequest& request,
         TerminaVmShutdownResponse* response, brillo::ErrorPtr* error) {
        return proxy->TerminaVmShutdown(request, response, error);
      },
      proxy_.get(), request, &response, &error));
  if (!result) {
    LOG(ERROR) << "TerminaVM network shutdown failed: " << error->GetMessage();
    return false;
  }
  return true;
}

bool ClientImpl::NotifyParallelsVmStartup(uint64_t vm_id,
                                          int subnet_index,
                                          Client::VirtualDevice* device) {
  ParallelsVmStartupRequest request;
  request.set_id(vm_id);
  request.set_subnet_index(subnet_index);

  ParallelsVmStartupResponse response;
  brillo::ErrorPtr error;
  const bool result = RunOnDBusThreadSync(base::BindOnce(
      [](PatchPanelProxyInterface* proxy,
         const ParallelsVmStartupRequest& request,
         ParallelsVmStartupResponse* response, brillo::ErrorPtr* error) {
        return proxy->ParallelsVmStartup(request, response, error);
      },
      proxy_.get(), request, &response, &error));
  if (!result) {
    LOG(ERROR) << "ParallelsVm network startup failed: " << error->GetMessage();
    return false;
  }

  if (!response.has_device()) {
    LOG(ERROR) << "No virtual device found";
    return false;
  }

  const auto response_device = ConvertVirtualDevice(response.device());
  if (!response_device) {
    LOG(ERROR) << "Invalid virtual device response";
    return false;
  }

  *device = *response_device;
  return true;
}

bool ClientImpl::NotifyParallelsVmShutdown(uint64_t vm_id) {
  ParallelsVmShutdownRequest request;
  request.set_id(vm_id);

  ParallelsVmShutdownResponse response;
  brillo::ErrorPtr error;
  const bool result = RunOnDBusThreadSync(base::BindOnce(
      [](PatchPanelProxyInterface* proxy,
         const ParallelsVmShutdownRequest& request,
         ParallelsVmShutdownResponse* response, brillo::ErrorPtr* error) {
        return proxy->ParallelsVmShutdown(request, response, error);
      },
      proxy_.get(), request, &response, &error));
  if (!result) {
    LOG(ERROR) << "ParallelsVM network shutdown failed: "
               << error->GetMessage();
    return false;
  }
  return true;
}

bool ClientImpl::DefaultVpnRouting(const base::ScopedFD& socket) {
  return SendSetVpnIntentRequest(socket, SetVpnIntentRequest::DEFAULT_ROUTING);
}

bool ClientImpl::RouteOnVpn(const base::ScopedFD& socket) {
  return SendSetVpnIntentRequest(socket, SetVpnIntentRequest::ROUTE_ON_VPN);
}

bool ClientImpl::BypassVpn(const base::ScopedFD& socket) {
  return SendSetVpnIntentRequest(socket, SetVpnIntentRequest::BYPASS_VPN);
}

bool ClientImpl::SendSetVpnIntentRequest(
    const base::ScopedFD& socket,
    SetVpnIntentRequest::VpnRoutingPolicy policy) {
  SetVpnIntentRequest request;
  request.set_policy(policy);

  base::ScopedFD dup_socket(dup(socket.get()));
  if (!dup_socket.is_valid()) {
    LOG(ERROR) << "Failed to duplicate the socket fd";
    return false;
  }

  SetVpnIntentResponse response;
  brillo::ErrorPtr error;
  const bool result = RunOnDBusThreadSync(base::BindOnce(
      [](PatchPanelProxyInterface* proxy, const SetVpnIntentRequest& request,
         base::ScopedFD socket, SetVpnIntentResponse* response,
         brillo::ErrorPtr* error) {
        return proxy->SetVpnIntent(request, socket, response, error);
      },
      proxy_.get(), request, std::move(dup_socket), &response, &error));
  if (!result) {
    LOG(ERROR) << "SetVpnIntent failed: " << error->GetMessage();
    return false;
  }

  if (!response.success()) {
    LOG(ERROR) << "SetVpnIntentRequest failed";
    return false;
  }
  return true;
}

std::pair<base::ScopedFD, Client::ConnectedNamespace>
ClientImpl::ConnectNamespace(pid_t pid,
                             const std::string& outbound_ifname,
                             bool forward_user_traffic,
                             bool route_on_vpn,
                             Client::TrafficSource traffic_source) {
  // Prepare and serialize the request proto.
  ConnectNamespaceRequest request;
  request.set_pid(static_cast<int32_t>(pid));
  request.set_outbound_physical_device(outbound_ifname);
  request.set_allow_user_traffic(forward_user_traffic);
  request.set_route_on_vpn(route_on_vpn);
  request.set_traffic_source(ConvertTrafficSource(traffic_source));

  auto [fd_local, fd_remote] = CreateLifelineFd();
  if (!fd_local.is_valid()) {
    LOG(ERROR)
        << "Cannot send ConnectNamespace message to patchpanel: no lifeline fd";
    return {};
  }

  ConnectNamespaceResponse response;
  brillo::ErrorPtr error;
  const bool result = RunOnDBusThreadSync(base::BindOnce(
      [](PatchPanelProxyInterface* proxy,
         const ConnectNamespaceRequest& request, base::ScopedFD fd_remote,
         ConnectNamespaceResponse* response, brillo::ErrorPtr* error) {
        return proxy->ConnectNamespace(request, fd_remote, response, error);
      },
      proxy_.get(), request, std::move(fd_remote), &response, &error));
  if (!result) {
    LOG(ERROR) << "ConnectNamespace failed: " << error->GetMessage();
    return {};
  }

  if (response.peer_ifname().empty() || response.host_ifname().empty()) {
    LOG(ERROR) << "ConnectNamespace for netns pid " << pid << " failed";
    return {};
  }

  const auto connected_ns = ConvertConnectedNamespace(response);
  std::string subnet_info = IPv4AddressToCidrString(
      connected_ns.ipv4_subnet.base_addr, connected_ns.ipv4_subnet.prefix_len);
  LOG(INFO) << "ConnectNamespace for netns pid " << pid
            << " succeeded: peer_ifname=" << connected_ns.peer_ifname
            << " peer_ipv4_address=" << connected_ns.peer_ipv4_address
            << " host_ifname=" << connected_ns.host_ifname
            << " host_ipv4_address=" << connected_ns.host_ipv4_address
            << " subnet=" << subnet_info;

  return std::make_pair(std::move(fd_local), std::move(connected_ns));
}

void ClientImpl::GetTrafficCounters(const std::set<std::string>& devices,
                                    GetTrafficCountersCallback callback) {
  TrafficCountersRequest request;
  for (const auto& device : devices) {
    request.add_devices(device);
  }

  RunOnDBusThreadAsync(base::BindOnce(
      [](PatchPanelProxyInterface* proxy, const TrafficCountersRequest& request,
         GetTrafficCountersCallback callback) {
        auto split_callback = SplitOnceCallback(std::move(callback));
        proxy->GetTrafficCountersAsync(
            request,
            base::BindOnce(&OnGetTrafficCountersDBusResponse,
                           std::move(split_callback.first)),
            base::BindOnce(&OnGetTrafficCountersError,
                           std::move(split_callback.second)));
      },
      proxy_.get(), request,
      base::BindPostTaskToCurrentDefault(std::move(callback))));
}

bool ClientImpl::ModifyPortRule(Client::FirewallRequestOperation op,
                                Client::FirewallRequestType type,
                                Client::FirewallRequestProtocol proto,
                                const std::string& input_ifname,
                                const std::string& input_dst_ip,
                                uint32_t input_dst_port,
                                const std::string& dst_ip,
                                uint32_t dst_port) {
  ModifyPortRuleRequest request;
  request.set_op(ConvertFirewallRequestOperation(op));
  request.set_type(ConvertFirewallRequestType(type));
  request.set_proto(ConvertFirewallRequestProtocol(proto));
  request.set_input_ifname(input_ifname);
  request.set_input_dst_ip(input_dst_ip);
  request.set_input_dst_port(input_dst_port);
  request.set_dst_ip(dst_ip);
  request.set_dst_port(dst_port);

  // TODO(b/284797476): Switch permission_brokker to use the async DBus call.
  ModifyPortRuleResponse response;
  brillo::ErrorPtr error;
  const bool result = RunOnDBusThreadSync(base::BindOnce(
      [](PatchPanelProxyInterface* proxy, const ModifyPortRuleRequest& request,
         ModifyPortRuleResponse* response, brillo::ErrorPtr* error) {
        return proxy->ModifyPortRule(request, response, error);
      },
      proxy_.get(), request, &response, &error));
  if (!result) {
    LOG(ERROR) << "ModifyPortRule failed: " << error->GetMessage();
    return false;
  }

  if (!response.success()) {
    LOG(ERROR) << "ModifyPortRuleRequest failed " << request;
    return false;
  }
  return true;
}

bool ClientImpl::SetVpnLockdown(bool enable) {
  SetVpnLockdownRequest request;
  request.set_enable_vpn_lockdown(enable);

  // TODO(b/284797476): Switch shill to use the async DBus call.
  SetVpnLockdownResponse response;
  brillo::ErrorPtr error;
  const bool result = RunOnDBusThreadSync(base::BindOnce(
      [](PatchPanelProxyInterface* proxy, const SetVpnLockdownRequest& request,
         SetVpnLockdownResponse* response, brillo::ErrorPtr* error) {
        return proxy->SetVpnLockdown(request, response, error);
      },
      proxy_.get(), request, &response, &error));
  if (!result) {
    LOG(ERROR) << "SetVpnLockdown(" << enable
               << ") failed: " << error->GetMessage();
    return false;
  }

  return true;
}

base::ScopedFD ClientImpl::RedirectDns(
    Client::DnsRedirectionRequestType type,
    const std::string& input_ifname,
    const std::string& proxy_address,
    const std::vector<std::string>& nameservers,
    const std::string& host_ifname) {
  SetDnsRedirectionRuleRequest request;
  request.set_type(ConvertDnsRedirectionRequestType(type));
  request.set_input_ifname(input_ifname);
  request.set_proxy_address(proxy_address);
  request.set_host_ifname(host_ifname);
  for (const auto& nameserver : nameservers) {
    request.add_nameservers(nameserver);
  }

  // Prepare an fd pair and append one fd directly after the serialized request.
  auto [fd_local, fd_remote] = CreateLifelineFd();
  if (!fd_local.is_valid()) {
    LOG(ERROR) << "Cannot send SetDnsRedirectionRuleRequest message to "
                  "patchpanel: no lifeline fd";
    return {};
  }

  SetDnsRedirectionRuleResponse response;
  brillo::ErrorPtr error;
  const bool result = RunOnDBusThreadSync(base::BindOnce(
      [](PatchPanelProxyInterface* proxy,
         const SetDnsRedirectionRuleRequest& request, base::ScopedFD fd_remote,
         SetDnsRedirectionRuleResponse* response, brillo::ErrorPtr* error) {
        return proxy->SetDnsRedirectionRule(request, fd_remote, response,
                                            error);
      },
      proxy_.get(), request, std::move(fd_remote), &response, &error));
  if (!result) {
    LOG(ERROR) << "SetDnsRedirectionRule failed: " << error->GetMessage();
    return {};
  }

  if (!response.success()) {
    LOG(ERROR) << "SetDnsRedirectionRuleRequest failed " << request;
    return {};
  }
  return std::move(fd_local);
}

std::vector<Client::VirtualDevice> ClientImpl::GetDevices() {
  // TODO(b/284797476): Add a DBus service in dns-proxy to let patchpanel push
  // information to dns-proxy.
  GetDevicesResponse response;
  brillo::ErrorPtr error;
  const bool result = RunOnDBusThreadSync(base::BindOnce(
      [](PatchPanelProxyInterface* proxy, GetDevicesResponse* response,
         brillo::ErrorPtr* error) {
        return proxy->GetDevices({}, response, error);
      },
      proxy_.get(), &response, &error));
  if (!result) {
    LOG(ERROR) << "GetDevices failed: " << error->GetMessage();
    return {};
  }

  std::vector<Client::VirtualDevice> devices;
  for (const auto& d : response.devices()) {
    const auto device = ConvertVirtualDevice(d);
    if (device) {
      devices.push_back(*device);
    }
  }
  return devices;
}

void ClientImpl::RegisterVirtualDeviceEventHandler(
    VirtualDeviceEventHandler handler) {
  proxy_->RegisterNetworkDeviceChangedSignalHandler(
      base::BindRepeating(OnNetworkDeviceChanged, std::move(handler)),
      base::BindOnce(OnSignalConnectedCallback));
}

void ClientImpl::RegisterNeighborReachabilityEventHandler(
    NeighborReachabilityEventHandler handler) {
  proxy_->RegisterNeighborReachabilityEventSignalHandler(
      base::BindRepeating(OnNeighborReachabilityEvent, std::move(handler)),
      base::BindOnce(OnSignalConnectedCallback));
}

bool ClientImpl::CreateTetheredNetwork(
    const std::string& downstream_ifname,
    const std::string& upstream_ifname,
    const std::optional<DHCPOptions>& dhcp_options,
    const std::optional<int>& mtu,
    CreateTetheredNetworkCallback callback) {
  TetheredNetworkRequest request;
  request.set_ifname(downstream_ifname);
  request.set_upstream_ifname(upstream_ifname);
  if (mtu) {
    request.set_mtu(*mtu);
  }
  if (dhcp_options.has_value()) {
    auto* ipv4_config = request.mutable_ipv4_config();
    ipv4_config->set_use_dhcp(true);
    for (const auto& dns_server : dhcp_options->dns_server_addresses) {
      ipv4_config->add_dns_servers(dns_server.ToByteString());
    }
    for (const auto& domain_search : dhcp_options->domain_search_list) {
      ipv4_config->add_domain_searches(domain_search);
    }
    if (dhcp_options->is_android_metered) {
      auto options = ipv4_config->add_options();
      // RFC 3925 defines the DHCP option 43 is Vendor Specific.
      options->set_code(43);
      options->set_content("ANDROID_METERED");
    }
  }
  request.set_enable_ipv6(true);

  // Prepare an fd pair and append one fd directly after the serialized request.
  auto [fd_local, fd_remote] = CreateLifelineFd();
  if (!fd_local.is_valid()) {
    LOG(ERROR) << kCreateTetheredNetworkMethod << "(" << downstream_ifname
               << "," << upstream_ifname << "): Cannot create lifeline fds";
    return false;
  }

  RunOnDBusThreadAsync(base::BindOnce(
      [](PatchPanelProxyInterface* proxy, const TetheredNetworkRequest& request,
         base::ScopedFD fd_local, base::ScopedFD fd_remote,
         CreateTetheredNetworkCallback callback) {
        auto split_callback = SplitOnceCallback(std::move(callback));
        proxy->CreateTetheredNetworkAsync(
            request, fd_remote,
            base::BindOnce(&OnTetheredNetworkResponse,
                           std::move(split_callback.first),
                           std::move(fd_local)),
            base::BindOnce(&OnTetheredNetworkError,
                           std::move(split_callback.second)));
      },
      proxy_.get(), request, std::move(fd_local), std::move(fd_remote),
      base::BindPostTaskToCurrentDefault(std::move(callback))));

  return true;
}

bool ClientImpl::CreateLocalOnlyNetwork(
    const std::string& ifname, CreateLocalOnlyNetworkCallback callback) {
  LocalOnlyNetworkRequest request;
  request.set_ifname(ifname);
  auto* ipv4_config = request.mutable_ipv4_config();
  ipv4_config->set_use_dhcp(true);

  // Prepare an fd pair and append one fd directly after the serialized request.
  auto [fd_local, fd_remote] = CreateLifelineFd();
  if (!fd_local.is_valid()) {
    LOG(ERROR) << kCreateLocalOnlyNetworkMethod
               << ": Cannot create lifeline fds";
    return false;
  }

  RunOnDBusThreadAsync(base::BindOnce(
      [](PatchPanelProxyInterface* proxy,
         const LocalOnlyNetworkRequest& request, base::ScopedFD fd_local,
         base::ScopedFD fd_remote, CreateLocalOnlyNetworkCallback callback) {
        auto split_callback = SplitOnceCallback(std::move(callback));
        proxy->CreateLocalOnlyNetworkAsync(
            request, fd_remote,
            base::BindOnce(&OnLocalOnlyNetworkResponse,
                           std::move(split_callback.first),
                           std::move(fd_local)),
            base::BindOnce(&OnLocalOnlyNetworkError,
                           std::move(split_callback.second)));
      },
      proxy_.get(), request, std::move(fd_local), std::move(fd_remote),
      base::BindPostTaskToCurrentDefault(std::move(callback))));

  return true;
}

bool ClientImpl::GetDownstreamNetworkInfo(
    const std::string& ifname, GetDownstreamNetworkInfoCallback callback) {
  GetDownstreamNetworkInfoRequest request;
  request.set_downstream_ifname(ifname);

  RunOnDBusThreadAsync(base::BindOnce(
      [](PatchPanelProxyInterface* proxy,
         const GetDownstreamNetworkInfoRequest& request,
         GetDownstreamNetworkInfoCallback callback) {
        auto split_callback = SplitOnceCallback(std::move(callback));
        proxy->GetDownstreamNetworkInfoAsync(
            request,
            base::BindOnce(&OnGetDownstreamNetworkInfoResponse,
                           std::move(split_callback.first)),
            base::BindOnce(&OnGetDownstreamNetworkInfoError,
                           std::move(split_callback.second)));
      },
      proxy_.get(), request,
      base::BindPostTaskToCurrentDefault(std::move(callback))));

  return true;
}

}  // namespace

// static
std::unique_ptr<Client> Client::New() {
  dbus::Bus::Options opts;
  opts.bus_type = dbus::Bus::SYSTEM;
  scoped_refptr<dbus::Bus> bus(new dbus::Bus(std::move(opts)));

  if (!bus->Connect()) {
    LOG(ERROR) << "Failed to connect to system bus";
    return nullptr;
  }

  auto proxy = std::make_unique<org::chromium::PatchPanelProxy>(bus);
  if (!proxy) {
    LOG(ERROR) << "Failed to create proxy";
    return nullptr;
  }

  return std::make_unique<ClientImpl>(std::move(bus), std::move(proxy),
                                      /*owns_bus=*/true);
}

// static
std::unique_ptr<Client> Client::New(const scoped_refptr<dbus::Bus>& bus) {
  auto proxy = std::make_unique<org::chromium::PatchPanelProxy>(bus);
  if (!proxy) {
    LOG(ERROR) << "Failed to create proxy";
    return nullptr;
  }
  return std::make_unique<ClientImpl>(bus, std::move(proxy),
                                      /*owns_bus=*/false);
}

// static
std::unique_ptr<Client> Client::NewForTesting(
    scoped_refptr<dbus::Bus> bus,
    std::unique_ptr<org::chromium::PatchPanelProxyInterface> proxy) {
  return std::make_unique<ClientImpl>(std::move(bus), std::move(proxy),
                                      /*owns_bus=*/false);
}

// static
bool Client::IsArcGuest(Client::GuestType guest_type) {
  switch (guest_type) {
    case Client::GuestType::kArcContainer:
    case Client::GuestType::kArcVm:
      return true;
    default:
      return false;
  }
}

// static
std::string Client::TrafficSourceName(
    patchpanel::Client::TrafficSource source) {
  return patchpanel::TrafficCounter::Source_Name(ConvertTrafficSource(source));
}

// static
std::string Client::ProtocolName(
    patchpanel::Client::FirewallRequestProtocol protocol) {
  return patchpanel::ModifyPortRuleRequest::Protocol_Name(
      ConvertFirewallRequestProtocol(protocol));
}

// static
std::string Client::NeighborRoleName(patchpanel::Client::NeighborRole role) {
  return NeighborReachabilityEventSignal::Role_Name(ConvertNeighborRole(role));
}

// static
std::string Client::NeighborStatusName(
    patchpanel::Client::NeighborStatus status) {
  return NeighborReachabilityEventSignal::EventType_Name(
      ConvertNeighborStatus(status));
}

BRILLO_EXPORT std::ostream& operator<<(
    std::ostream& stream, const Client::NeighborReachabilityEvent& event) {
  return stream << "{ifindex: " << event.ifindex
                << ", ip_address: " << event.ip_addr
                << ", role: " << Client::NeighborRoleName(event.role)
                << ", status: " << Client::NeighborStatusName(event.status)
                << "}";
}

}  // namespace patchpanel
