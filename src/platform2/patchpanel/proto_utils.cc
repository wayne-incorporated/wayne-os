// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "patchpanel/proto_utils.h"

#include <net-base/ipv4_address.h>
#include <net-base/ipv6_address.h>

#include "patchpanel/arc_service.h"

namespace patchpanel {

void FillDeviceProto(const Device& virtual_device,
                     patchpanel::NetworkDevice* output) {
  output->set_ifname(virtual_device.host_ifname());
  if (virtual_device.shill_device()) {
    output->set_phys_ifname(virtual_device.shill_device()->ifname);
  }
  output->set_guest_ifname(virtual_device.guest_ifname());
  output->set_ipv4_addr(
      virtual_device.config().guest_ipv4_addr().ToInAddr().s_addr);
  output->set_host_ipv4_addr(
      virtual_device.config().host_ipv4_addr().ToInAddr().s_addr);
  switch (virtual_device.type()) {
    case Device::Type::kARC0:
      // The "arc0" legacy management device is not exposed in DBus
      // patchpanel "GetDevices" method or in "NetworkDeviceChanged" signal.
      // However the "arc0" legacy device is exposed in the ArcVmStartupResponse
      // proto sent back to a "ArcVmStartup" method call. In this latter case
      // the |guest_type| field is left empty.
      output->set_phys_ifname(kArc0Ifname);
      break;
    case Device::Type::kARCContainer:
      output->set_guest_type(NetworkDevice::ARC);
      break;
    case Device::Type::kARCVM:
      output->set_guest_type(NetworkDevice::ARCVM);
      break;
    case Device::Type::kTerminaVM:
      output->set_phys_ifname(virtual_device.host_ifname());
      output->set_guest_type(NetworkDevice::TERMINA_VM);
      break;
    case Device::Type::kParallelsVM:
      output->set_phys_ifname(virtual_device.host_ifname());
      output->set_guest_type(NetworkDevice::PARALLELS_VM);
      break;
  }
  if (const auto* subnet = virtual_device.config().ipv4_subnet()) {
    FillSubnetProto(*subnet, output->mutable_ipv4_subnet());
  }
}

void FillSubnetProto(const net_base::IPv4CIDR& cidr,
                     patchpanel::IPv4Subnet* output) {
  output->set_addr(cidr.address().ToByteString());
  output->set_base_addr(cidr.address().ToInAddr().s_addr);
  output->set_prefix_len(static_cast<uint32_t>(cidr.prefix_length()));
}

void FillSubnetProto(const Subnet& virtual_subnet,
                     patchpanel::IPv4Subnet* output) {
  FillSubnetProto(virtual_subnet.base_cidr(), output);
}

void FillDeviceDnsProxyProto(
    const Device& virtual_device,
    patchpanel::NetworkDevice* output,
    const std::map<std::string, std::string>& ipv4_addrs,
    const std::map<std::string, std::string>& ipv6_addrs) {
  const auto& ipv4_it = ipv4_addrs.find(virtual_device.host_ifname());
  if (ipv4_it != ipv4_addrs.end()) {
    const auto ipv4_addr =
        net_base::IPv4Address::CreateFromString(ipv4_it->second);
    if (ipv4_addr) {
      output->set_dns_proxy_ipv4_addr(ipv4_addr->ToByteString());
    }
  }
  const auto& ipv6_it = ipv6_addrs.find(virtual_device.host_ifname());
  if (ipv6_it != ipv6_addrs.end()) {
    const auto ipv6_addr =
        net_base::IPv6Address::CreateFromString(ipv6_it->second);
    if (ipv6_addr) {
      output->set_dns_proxy_ipv6_addr(ipv6_addr->ToByteString());
    }
  }
}

void FillDownstreamNetworkProto(
    const DownstreamNetworkInfo& downstream_network_info,
    patchpanel::DownstreamNetwork* output) {
  output->set_downstream_ifname(downstream_network_info.downstream_ifname);
  output->set_ipv4_gateway_addr(
      downstream_network_info.ipv4_cidr.address().ToByteString());
  FillSubnetProto(downstream_network_info.ipv4_cidr,
                  output->mutable_ipv4_subnet());
}

void FillNetworkClientInfoProto(const DownstreamClientInfo& network_client_info,
                                NetworkClientInfo* output) {
  output->set_mac_addr(network_client_info.mac_addr.data(),
                       network_client_info.mac_addr.size());
  output->set_ipv4_addr(network_client_info.ipv4_addr.ToByteString());
  for (const auto& ipv6_addr : network_client_info.ipv6_addresses) {
    output->add_ipv6_addresses(ipv6_addr.ToByteString());
  }
  output->set_hostname(network_client_info.hostname);
  output->set_vendor_class(network_client_info.vendor_class);
}

}  // namespace patchpanel
