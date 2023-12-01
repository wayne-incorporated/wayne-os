// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <net/if.h>
#include <string.h>
#include <sys/ioctl.h>

#include <memory>
#include <string>
#include <vector>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wconversion"
#include <base/at_exit.h>
#pragma GCC diagnostic pop
#include <base/functional/bind.h>
#include <base/functional/callback_helpers.h>
#include <base/logging.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <net-base/ipv4_address.h>

#include "patchpanel/datapath.h"
#include "patchpanel/firewall.h"
#include "patchpanel/minijailed_process_runner.h"
#include "patchpanel/multicast_forwarder.h"
#include "patchpanel/net_util.h"
#include "patchpanel/shill_client.h"
#include "patchpanel/subnet.h"
#include "patchpanel/system.h"

namespace patchpanel {
namespace {

// Always succeeds
class FakeProcessRunner : public MinijailedProcessRunner {
 public:
  FakeProcessRunner() = default;
  FakeProcessRunner(const FakeProcessRunner&) = delete;
  FakeProcessRunner& operator=(const FakeProcessRunner&) = delete;
  ~FakeProcessRunner() = default;

  int Run(const std::vector<std::string>& argv, bool log_failures) override {
    return 0;
  }

  int RunSync(const std::vector<std::string>& argv,
              bool log_failures,
              std::string* output) override {
    return 0;
  }
};

// Always succeeds
class NoopSystem : public System {
 public:
  NoopSystem() = default;
  NoopSystem(const NoopSystem&) = delete;
  NoopSystem& operator=(const NoopSystem&) = delete;
  virtual ~NoopSystem() = default;

  int Ioctl(int fd, ioctl_req_t request, const char* argp) override {
    return 0;
  }
};

class Environment {
 public:
  Environment() {
    logging::SetMinLogLevel(logging::LOGGING_FATAL);  // <- DISABLE LOGGING.
  }
  base::AtExitManager at_exit;
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  static Environment env;
  FuzzedDataProvider provider(data, size);

  int32_t pid = provider.ConsumeIntegral<int32_t>();
  std::string netns_name = provider.ConsumeRandomLengthString(10);
  std::string ifname = provider.ConsumeRandomLengthString(IFNAMSIZ - 1);
  std::string ifname2 = provider.ConsumeRandomLengthString(IFNAMSIZ - 1);
  std::string ifname3 = provider.ConsumeRandomLengthString(IFNAMSIZ - 1);
  std::string bridge = provider.ConsumeRandomLengthString(IFNAMSIZ - 1);
  uint32_t addr = provider.ConsumeIntegral<uint32_t>();
  int prefix_len = provider.ConsumeIntegralInRange<int>(0, 31);
  const auto ipv4_addr = ConvertUint32ToIPv4Address(addr);
  const auto cidr =
      *net_base::IPv4CIDR::CreateFromAddressAndPrefix(ipv4_addr, prefix_len);
  SubnetAddress subnet_addr(cidr, base::DoNothing());
  MacAddress mac;
  std::vector<uint8_t> mac_addr_bytes =
      provider.ConsumeBytes<uint8_t>(mac.size());
  std::copy(mac_addr_bytes.begin(), mac_addr_bytes.end(), mac.begin());

  const std::vector<uint8_t> ipv6_addr_bytes =
      provider.ConsumeBytes<uint8_t>(net_base::IPv6Address::kAddressLength);
  const int ipv6_prefix_len = provider.ConsumeIntegralInRange<int>(0, 128);
  const auto ipv6_addr = net_base::IPv6Address::CreateFromBytes(
                             ipv6_addr_bytes.data(), ipv6_addr_bytes.size())
                             .value_or(net_base::IPv6Address());
  const auto ipv6_cidr = *net_base::IPv6CIDR::CreateFromAddressAndPrefix(
      ipv6_addr, ipv6_prefix_len);
  const std::string ipv6_addr_str = ipv6_addr.ToString();
  bool route_on_vpn = provider.ConsumeBool();

  ConnectedNamespace nsinfo = {};
  nsinfo.pid = pid;
  nsinfo.netns_name = netns_name;
  nsinfo.source = TrafficSource::kUser;
  nsinfo.outbound_ifname = ifname;
  nsinfo.route_on_vpn = route_on_vpn;
  nsinfo.host_ifname = ifname2;
  nsinfo.peer_ifname = ifname3;
  nsinfo.peer_subnet = std::make_unique<Subnet>(cidr, base::DoNothing());
  nsinfo.peer_mac_addr = mac;

  ShillClient::Device shill_device;
  shill_device.ifname = ifname;
  shill_device.type = ShillClient::Device::Type::kWifi;
  shill_device.service_path = provider.ConsumeRandomLengthString(10);
  shill_device.ifindex = provider.ConsumeIntegral<int32_t>();

  auto runner = new FakeProcessRunner();
  auto firewall = new Firewall();
  NoopSystem system;
  Datapath datapath(runner, firewall, &system);
  datapath.Start();
  datapath.Stop();
  datapath.NetnsAttachName(netns_name, pid);
  datapath.NetnsDeleteName(netns_name);
  datapath.AddBridge(ifname, cidr);
  datapath.RemoveBridge(ifname);
  datapath.AddToBridge(ifname, ifname2);
  datapath.StartRoutingDevice(shill_device, ifname2, TrafficSource::kUnknown);
  datapath.StartRoutingDeviceAsSystem(ifname2, TrafficSource::kUnknown);
  datapath.StartRoutingDeviceAsUser(ifname2, ipv4_addr,
                                    TrafficSource::kUnknown);
  datapath.StopRoutingDevice(ifname2);
  datapath.StartRoutingNamespace(nsinfo);
  datapath.StopRoutingNamespace(nsinfo);
  datapath.ConnectVethPair(pid, netns_name, ifname, ifname2, mac, cidr,
                           provider.ConsumeBool());
  datapath.RemoveInterface(ifname);
  datapath.AddTAP(ifname, &mac, &cidr, "");
  datapath.RemoveTAP(ifname);
  datapath.AddIPv4Route(
      ConvertUint32ToIPv4Address(provider.ConsumeIntegral<uint32_t>()), cidr);
  datapath.DeleteIPv4Route(
      ConvertUint32ToIPv4Address(provider.ConsumeIntegral<uint32_t>()), cidr);
  datapath.StartConnectionPinning(shill_device);
  datapath.StopConnectionPinning(shill_device);
  datapath.StartVpnRouting(shill_device);
  datapath.StopVpnRouting(shill_device);
  datapath.MaskInterfaceFlags(ifname, provider.ConsumeIntegral<uint16_t>(),
                              provider.ConsumeIntegral<uint16_t>());
  datapath.AddIPv6HostRoute(ifname, ipv6_cidr);
  datapath.RemoveIPv6HostRoute(ipv6_cidr);
  datapath.AddIPv6Address(ifname, ipv6_addr_str);
  datapath.RemoveIPv6Address(ifname, ipv6_addr_str);
  datapath.StartSourceIPv6PrefixEnforcement(shill_device);
  datapath.StopSourceIPv6PrefixEnforcement(shill_device);
  datapath.UpdateSourceEnforcementIPv6Prefix(shill_device, ipv6_cidr);
  datapath.AddInboundIPv4DNAT(AutoDNATTarget::kArc, shill_device, ipv4_addr);
  datapath.RemoveInboundIPv4DNAT(AutoDNATTarget::kArc, shill_device, ipv4_addr);
  datapath.AddRedirectDnsRule(shill_device, ipv4_addr.ToString());
  datapath.RemoveRedirectDnsRule(shill_device);

  return 0;
}

}  // namespace
}  // namespace patchpanel
