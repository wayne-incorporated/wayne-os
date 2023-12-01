// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "patchpanel/dbus/client.h"

#include <memory>
#include <sstream>
#include <string>
#include <vector>

#include <dbus/mock_bus.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <patchpanel/proto_bindings/patchpanel_service.pb.h>

#include "patchpanel/dbus/mock_patchpanel_proxy.h"
#include "patchpanel/net_util.h"

namespace patchpanel {
namespace {

using ::testing::_;
using ::testing::AllOf;
using ::testing::DoAll;
using ::testing::Property;
using ::testing::Return;
using ::testing::SaveArg;
using ::testing::SetArgPointee;

class ClientTest : public testing::Test {
 protected:
  void SetUp() override {
    dbus_ = new dbus::MockBus{dbus::Bus::Options{}};
    proxy_ = new MockPatchPanelProxy();
    client_ = Client::NewForTesting(
        dbus_,
        std::unique_ptr<org::chromium::PatchPanelProxyInterface>(proxy_));
  }

  scoped_refptr<dbus::MockBus> dbus_;
  std::unique_ptr<Client> client_;
  MockPatchPanelProxy* proxy_;  // It's owned by |client_|.
};

TEST_F(ClientTest, NotifyArcStartup) {
  const pid_t pid = 3456;
  EXPECT_CALL(*proxy_,
              ArcStartup(Property(&ArcStartupRequest::pid, pid), _, _, _))
      .WillOnce(Return(true));

  const bool result = client_->NotifyArcStartup(pid);
  EXPECT_TRUE(result);
}

TEST_F(ClientTest, NotifyArcShutdown) {
  EXPECT_CALL(*proxy_, ArcShutdown(_, _, _, _)).WillOnce(Return(true));

  const bool result = client_->NotifyArcShutdown();
  EXPECT_TRUE(result);
}

TEST_F(ClientTest, NotifyArcVmStartup) {
  const uint32_t cid = 5;
  // FIXME: add virtual devices to the response_proto.
  ArcVmStartupResponse response_proto;

  EXPECT_CALL(*proxy_,
              ArcVmStartup(Property(&ArcVmStartupRequest::cid, cid), _, _, _))
      .WillOnce(DoAll(SetArgPointee<1>(response_proto), Return(true)));

  const auto virtual_devices = client_->NotifyArcVmStartup(cid);
  EXPECT_TRUE(virtual_devices.empty());
}

TEST_F(ClientTest, NotifyArcVmShutdown) {
  const uint32_t cid = 5;

  EXPECT_CALL(*proxy_,
              ArcVmShutdown(Property(&ArcVmShutdownRequest::cid, cid), _, _, _))
      .WillOnce(Return(true));

  const bool result = client_->NotifyArcVmShutdown(cid);
  EXPECT_TRUE(result);
}

TEST_F(ClientTest, NotifyTerminaVmStartup) {
  const uint32_t cid = 5;

  TerminaVmStartupResponse response_proto;
  auto* response_device = response_proto.mutable_device();
  response_device->set_ifname("vmtap1");
  response_device->set_phys_ifname("wlan0");
  response_device->set_guest_ifname("not_defined");
  response_device->set_ipv4_addr(Ipv4Addr(100, 115, 92, 18));
  response_device->set_host_ipv4_addr(Ipv4Addr(100, 115, 92, 17));
  auto* response_device_subnet = response_device->mutable_ipv4_subnet();
  response_device_subnet->set_addr(
      std::vector<uint8_t>{100, 115, 92, 16}.data(), 4);
  response_device_subnet->set_prefix_len(30);
  response_device->set_guest_type(NetworkDevice::TERMINA_VM);
  response_device->set_dns_proxy_ipv4_addr(
      std::vector<uint8_t>{100, 115, 93, 1}.data(), 4);
  response_device->set_dns_proxy_ipv6_addr(
      std::vector<uint8_t>{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0x12,
                           0x34, 0xab, 0xcd}
          .data(),
      16);
  auto* response_subnet = response_proto.mutable_container_subnet();
  response_subnet->set_addr(std::vector<uint8_t>{100, 115, 92, 128}.data(), 4);
  response_subnet->set_prefix_len(24);

  EXPECT_CALL(
      *proxy_,
      TerminaVmStartup(Property(&TerminaVmStartupRequest::cid, cid), _, _, _))
      .WillOnce(DoAll(SetArgPointee<1>(response_proto), Return(true)));

  Client::VirtualDevice device;
  Client::IPv4Subnet container_subnet;
  const bool result =
      client_->NotifyTerminaVmStartup(cid, &device, &container_subnet);

  EXPECT_TRUE(result);
  EXPECT_EQ("vmtap1", device.ifname);
  EXPECT_EQ("wlan0", device.phys_ifname);
  EXPECT_EQ("not_defined", device.guest_ifname);
  EXPECT_EQ("100.115.92.18", device.ipv4_addr.ToString());
  EXPECT_EQ("100.115.92.17", device.host_ipv4_addr.ToString());
  EXPECT_EQ("100.115.92.16", IPv4AddressToString(device.ipv4_subnet.base_addr));
  EXPECT_EQ(30, device.ipv4_subnet.prefix_len);
  EXPECT_EQ(Client::GuestType::kTerminaVm, device.guest_type);
  EXPECT_EQ("100.115.93.1", device.dns_proxy_ipv4_addr->ToString());
  EXPECT_EQ("2001:db8::1234:abcd", device.dns_proxy_ipv6_addr->ToString());
  EXPECT_EQ("100.115.92.128", IPv4AddressToString(container_subnet.base_addr));
  EXPECT_EQ(24, container_subnet.prefix_len);
}

TEST_F(ClientTest, NotifyTerminaVmShutdown) {
  const uint32_t cid = 5;

  EXPECT_CALL(
      *proxy_,
      TerminaVmShutdown(Property(&TerminaVmShutdownRequest::cid, cid), _, _, _))
      .WillOnce(Return(true));

  bool result = client_->NotifyTerminaVmShutdown(cid);
  EXPECT_TRUE(result);
}

TEST_F(ClientTest, NotifyParallelsVmStartup) {
  const uint64_t id = 5;
  const int subnet_index = 4;

  ParallelsVmStartupResponse response_proto;
  auto* response_device = response_proto.mutable_device();
  response_device->set_ifname("vmtap2");
  response_device->set_phys_ifname("eth0");
  response_device->set_guest_ifname("not_defined");
  response_device->set_ipv4_addr(Ipv4Addr(100, 115, 93, 34));
  response_device->set_host_ipv4_addr(Ipv4Addr(100, 115, 93, 33));
  auto* response_device_subnet = response_device->mutable_ipv4_subnet();
  response_device_subnet->set_addr(
      std::vector<uint8_t>{100, 115, 93, 32}.data(), 4);
  response_device_subnet->set_prefix_len(28);
  response_device->set_guest_type(NetworkDevice::PARALLELS_VM);
  response_device->set_dns_proxy_ipv4_addr(
      std::vector<uint8_t>{100, 115, 93, 5}.data(), 4);
  response_device->set_dns_proxy_ipv6_addr(
      std::vector<uint8_t>{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0xbf,
                           0xc7, 0x4a, 0xd2}
          .data(),
      16);

  EXPECT_CALL(*proxy_,
              ParallelsVmStartup(
                  AllOf(Property(&ParallelsVmStartupRequest::id, id),
                        Property(&ParallelsVmStartupRequest::subnet_index,
                                 subnet_index)),
                  _, _, _))
      .WillOnce(DoAll(SetArgPointee<1>(response_proto), Return(true)));

  Client::VirtualDevice device;
  bool result = client_->NotifyParallelsVmStartup(id, subnet_index, &device);
  EXPECT_TRUE(result);
  EXPECT_EQ("vmtap2", device.ifname);
  EXPECT_EQ("eth0", device.phys_ifname);
  EXPECT_EQ("not_defined", device.guest_ifname);
  EXPECT_EQ("100.115.93.34", device.ipv4_addr.ToString());
  EXPECT_EQ("100.115.93.33", device.host_ipv4_addr.ToString());
  EXPECT_EQ("100.115.93.32", IPv4AddressToString(device.ipv4_subnet.base_addr));
  EXPECT_EQ(28, device.ipv4_subnet.prefix_len);
  EXPECT_EQ(Client::GuestType::kParallelsVm, device.guest_type);
  EXPECT_EQ("100.115.93.5", device.dns_proxy_ipv4_addr->ToString());
  EXPECT_EQ("2001:db8::bfc7:4ad2", device.dns_proxy_ipv6_addr->ToString());
}

TEST_F(ClientTest, NotifyParallelsVmShutdown) {
  const uint64_t id = 5;

  EXPECT_CALL(*proxy_,
              ParallelsVmShutdown(Property(&ParallelsVmShutdownRequest::id, id),
                                  _, _, _))
      .WillOnce(Return(true));

  const bool result = client_->NotifyParallelsVmShutdown(id);
  EXPECT_TRUE(result);
}

TEST_F(ClientTest, ConnectNamespace_Fail) {
  const pid_t invalid_pid = 3456;
  const std::string outbound_ifname = "";

  auto action = [](const patchpanel::ConnectNamespaceRequest&,
                   const base::ScopedFD&, patchpanel::ConnectNamespaceResponse*,
                   brillo::ErrorPtr* error, int) {
    *error = brillo::Error::Create(FROM_HERE, "", "", "");
    return false;
  };
  EXPECT_CALL(*proxy_, ConnectNamespace(
                           Property(&ConnectNamespaceRequest::pid, invalid_pid),
                           _, _, _, _))
      .WillOnce(action);

  const auto result =
      client_->ConnectNamespace(invalid_pid, outbound_ifname, false, true,
                                Client::TrafficSource::kSystem);
  EXPECT_FALSE(result.first.is_valid());
  EXPECT_TRUE(result.second.peer_ifname.empty());
  EXPECT_TRUE(result.second.host_ifname.empty());
  EXPECT_TRUE(result.second.peer_ipv4_address.IsZero());
  EXPECT_TRUE(result.second.host_ipv4_address.IsZero());
  EXPECT_EQ("", IPv4AddressToString(result.second.ipv4_subnet.base_addr));
  EXPECT_EQ(0, result.second.ipv4_subnet.prefix_len);
}

TEST_F(ClientTest, ConnectNamespace) {
  const pid_t pid = 3456;
  const std::string outbound_ifname = "test_ifname";
  const net_base::IPv4Address host_ipv4_addr(100, 115, 92, 129);
  const net_base::IPv4Address peer_ipv4_addr(100, 115, 92, 130);

  ConnectNamespaceResponse response_proto;
  response_proto.set_peer_ifname("veth0");
  response_proto.set_host_ifname("arc_ns0");
  response_proto.set_host_ipv4_address(host_ipv4_addr.ToInAddr().s_addr);
  response_proto.set_peer_ipv4_address(peer_ipv4_addr.ToInAddr().s_addr);
  auto* response_subnet = response_proto.mutable_ipv4_subnet();
  response_subnet->set_prefix_len(30);
  response_subnet->set_addr(std::vector<uint8_t>{100, 115, 92, 128}.data(), 4);

  EXPECT_CALL(
      *proxy_,
      ConnectNamespace(
          AllOf(Property(&ConnectNamespaceRequest::pid, pid),
                Property(&ConnectNamespaceRequest::outbound_physical_device,
                         outbound_ifname)),
          _, _, _, _))
      .WillOnce(DoAll(SetArgPointee<2>(response_proto), Return(true)));

  const auto result = client_->ConnectNamespace(
      pid, outbound_ifname, false, true, Client::TrafficSource::kSystem);
  EXPECT_TRUE(result.first.is_valid());
  EXPECT_EQ("arc_ns0", result.second.host_ifname);
  EXPECT_EQ("veth0", result.second.peer_ifname);
  EXPECT_EQ(30, result.second.ipv4_subnet.prefix_len);
  EXPECT_EQ("100.115.92.128",
            IPv4AddressToString(result.second.ipv4_subnet.base_addr));
  EXPECT_EQ(host_ipv4_addr, result.second.host_ipv4_address);
  EXPECT_EQ(peer_ipv4_addr, result.second.peer_ipv4_address);
}

TEST_F(ClientTest, RegisterNeighborEventHandler) {
  static Client::NeighborReachabilityEvent actual_event;
  static int call_num = 0;
  auto callback =
      base::BindRepeating([](const Client::NeighborReachabilityEvent& event) {
        call_num++;
        actual_event = event;
      });

  // Store the DBus callback.
  base::RepeatingCallback<void(
      const patchpanel::NeighborReachabilityEventSignal&)>
      registered_dbus_callback;
  EXPECT_CALL(*proxy_, RegisterNeighborReachabilityEventSignalHandler(_, _))
      .WillOnce(SaveArg<0>(&registered_dbus_callback));

  client_->RegisterNeighborReachabilityEventHandler(callback);

  // Trigger the DBus callback to simulate the signal arrival.
  NeighborReachabilityEventSignal signal_proto;
  signal_proto.set_ifindex(7);
  signal_proto.set_ip_addr("1.2.3.4");
  signal_proto.set_role(NeighborReachabilityEventSignal::GATEWAY);
  signal_proto.set_type(NeighborReachabilityEventSignal::FAILED);
  registered_dbus_callback.Run(signal_proto);

  EXPECT_EQ(call_num, 1);
  EXPECT_EQ(actual_event.ifindex, 7);
  EXPECT_EQ(actual_event.ip_addr, "1.2.3.4");
  EXPECT_EQ(actual_event.role, Client::NeighborRole::kGateway);
  EXPECT_EQ(actual_event.status, Client::NeighborStatus::kFailed);
}

TEST_F(ClientTest, RegisterNeighborEventSignal) {
  Client::NeighborReachabilityEvent event;
  event.ifindex = 1;
  event.ip_addr = "192.168.1.32";
  event.role = Client::NeighborRole::kGateway;
  event.status = Client::NeighborStatus::kFailed;

  std::stringstream stream;
  stream << event;
  EXPECT_EQ(
      "{ifindex: 1, ip_address: 192.168.1.32, role: GATEWAY, status: FAILED}",
      stream.str());
}

TEST_F(ClientTest, TrafficSourceName) {
  EXPECT_EQ("UNKNOWN",
            Client::TrafficSourceName(Client::TrafficSource::kUnknown));
  EXPECT_EQ("CHROME",
            Client::TrafficSourceName(Client::TrafficSource::kChrome));
  EXPECT_EQ("USER", Client::TrafficSourceName(Client::TrafficSource::kUser));
  EXPECT_EQ("CROSVM",
            Client::TrafficSourceName(Client::TrafficSource::kCrosVm));
  EXPECT_EQ("PARALLELS_VM",
            Client::TrafficSourceName(Client::TrafficSource::kParallelsVm));
  EXPECT_EQ("UPDATE_ENGINE",
            Client::TrafficSourceName(Client::TrafficSource::kUpdateEngine));
  EXPECT_EQ("VPN", Client::TrafficSourceName(Client::TrafficSource::kVpn));
  EXPECT_EQ("SYSTEM",
            Client::TrafficSourceName(Client::TrafficSource::kSystem));
}

TEST_F(ClientTest, ProtocolName) {
  EXPECT_EQ("UDP", Client::ProtocolName(Client::FirewallRequestProtocol::kUdp));
  EXPECT_EQ("TCP", Client::ProtocolName(Client::FirewallRequestProtocol::kTcp));
}

TEST_F(ClientTest, NeighborRoleName) {
  EXPECT_EQ("GATEWAY",
            Client::NeighborRoleName(Client::NeighborRole::kGateway));
  EXPECT_EQ("DNS_SERVER",
            Client::NeighborRoleName(Client::NeighborRole::kDnsServer));
  EXPECT_EQ(
      "GATEWAY_AND_DNS_SERVER",
      Client::NeighborRoleName(Client::NeighborRole::kGatewayAndDnsServer));
}

TEST_F(ClientTest, NeighborStatusName) {
  EXPECT_EQ("REACHABLE",
            Client::NeighborStatusName(Client::NeighborStatus::kReachable));
  EXPECT_EQ("FAILED",
            Client::NeighborStatusName(Client::NeighborStatus::kFailed));
}

}  // namespace
}  // namespace patchpanel
