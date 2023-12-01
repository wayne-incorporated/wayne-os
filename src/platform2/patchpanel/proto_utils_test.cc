// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "patchpanel/proto_utils.h"

#include <memory>
#include <optional>
#include <string>
#include <utility>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <metrics/metrics_library_mock.h>
#include <patchpanel/proto_bindings/patchpanel_service.pb.h>

#include "patchpanel/address_manager.h"
#include "patchpanel/crostini_service.h"
#include "patchpanel/device.h"
#include "patchpanel/net_util.h"

namespace patchpanel {

class ProtoUtilsTest : public testing::Test {
 protected:
  void SetUp() override { addr_mgr_ = std::make_unique<AddressManager>(); }

  std::unique_ptr<AddressManager> addr_mgr_;
};

TEST_F(ProtoUtilsTest, ConvertTerminaDevice) {
  const uint32_t subnet_index = 0;
  const auto mac_addr = addr_mgr_->GenerateMacAddress(subnet_index);
  auto ipv4_subnet = addr_mgr_->AllocateIPv4Subnet(
      AddressManager::GuestType::kTerminaVM, subnet_index);
  auto host_ipv4_addr = ipv4_subnet->AllocateAtOffset(1);
  auto guest_ipv4_addr = ipv4_subnet->AllocateAtOffset(2);
  auto lxd_subnet =
      addr_mgr_->AllocateIPv4Subnet(AddressManager::GuestType::kLXDContainer);
  auto expected_host_ipv4 = host_ipv4_addr->cidr().address().ToInAddr().s_addr;
  auto expected_guest_ipv4 =
      guest_ipv4_addr->cidr().address().ToInAddr().s_addr;
  auto expected_base_cidr = ipv4_subnet->base_cidr();

  auto config = std::make_unique<Device::Config>(
      mac_addr, std::move(ipv4_subnet), std::move(host_ipv4_addr),
      std::move(guest_ipv4_addr), std::move(lxd_subnet));
  auto device = std::make_unique<Device>(Device::Type::kTerminaVM, std::nullopt,
                                         "vmtap0", "", std::move(config));

  NetworkDevice proto_device;
  FillDeviceProto(*device, &proto_device);

  ASSERT_EQ("vmtap0", proto_device.ifname());
  // Convention for Crostini Devices is to reuse the virtual interface name in
  // place of the interface name of the upstream network used by ARC Devices.
  ASSERT_EQ("vmtap0", proto_device.phys_ifname());
  ASSERT_EQ("", proto_device.guest_ifname());
  ASSERT_EQ(expected_guest_ipv4, proto_device.ipv4_addr());
  ASSERT_EQ(expected_host_ipv4, proto_device.host_ipv4_addr());
  ASSERT_EQ(expected_base_cidr.address(),
            net_base::IPv4Address::CreateFromBytes(
                proto_device.ipv4_subnet().addr().c_str(),
                proto_device.ipv4_subnet().addr().size()));
  ASSERT_EQ(expected_base_cidr.address().ToInAddr().s_addr,
            proto_device.ipv4_subnet().base_addr());
  ASSERT_EQ(expected_base_cidr.prefix_length(),
            proto_device.ipv4_subnet().prefix_len());
  ASSERT_EQ(NetworkDevice::TERMINA_VM, proto_device.guest_type());
}

TEST_F(ProtoUtilsTest, ConvertParallelsDevice) {
  const uint32_t subnet_index = 1;
  const auto mac_addr = addr_mgr_->GenerateMacAddress(subnet_index);
  auto ipv4_subnet = addr_mgr_->AllocateIPv4Subnet(
      AddressManager::GuestType::kParallelsVM, subnet_index);
  auto host_ipv4_addr = ipv4_subnet->AllocateAtOffset(1);
  auto guest_ipv4_addr = ipv4_subnet->AllocateAtOffset(2);
  auto expected_host_ipv4 = host_ipv4_addr->cidr().address().ToInAddr().s_addr;
  auto expected_guest_ipv4 =
      guest_ipv4_addr->cidr().address().ToInAddr().s_addr;
  auto expected_base_cidr = ipv4_subnet->base_cidr();

  auto config = std::make_unique<Device::Config>(
      mac_addr, std::move(ipv4_subnet), std::move(host_ipv4_addr),
      std::move(guest_ipv4_addr));
  auto device =
      std::make_unique<Device>(Device::Type::kParallelsVM, std::nullopt,
                               "vmtap1", "", std::move(config));

  NetworkDevice proto_device;
  FillDeviceProto(*device, &proto_device);

  ASSERT_EQ("vmtap1", proto_device.ifname());
  // Convention for Crostini Devices is to reuse the virtual interface name in
  // place of the interface name of the upstream network used by ARC Devices.
  ASSERT_EQ("vmtap1", proto_device.phys_ifname());
  ASSERT_EQ("", proto_device.guest_ifname());
  ASSERT_EQ(expected_guest_ipv4, proto_device.ipv4_addr());
  ASSERT_EQ(expected_host_ipv4, proto_device.host_ipv4_addr());
  ASSERT_EQ(expected_base_cidr.address(),
            net_base::IPv4Address::CreateFromBytes(
                proto_device.ipv4_subnet().addr().c_str(),
                proto_device.ipv4_subnet().addr().size()));
  ASSERT_EQ(expected_base_cidr.address().ToInAddr().s_addr,
            proto_device.ipv4_subnet().base_addr());
  ASSERT_EQ(expected_base_cidr.prefix_length(),
            proto_device.ipv4_subnet().prefix_len());
  ASSERT_EQ(NetworkDevice::PARALLELS_VM, proto_device.guest_type());
}

TEST_F(ProtoUtilsTest, ConvertARCContainerDevice) {
  const auto mac_addr = addr_mgr_->GenerateMacAddress(0);
  auto ipv4_subnet =
      addr_mgr_->AllocateIPv4Subnet(AddressManager::GuestType::kArcNet, 0);
  auto host_ipv4_addr = ipv4_subnet->AllocateAtOffset(1);
  auto guest_ipv4_addr = ipv4_subnet->AllocateAtOffset(2);
  auto expected_host_ipv4 = host_ipv4_addr->cidr().address().ToInAddr().s_addr;
  auto expected_guest_ipv4 =
      guest_ipv4_addr->cidr().address().ToInAddr().s_addr;
  auto expected_base_cidr = ipv4_subnet->base_cidr();

  ShillClient::Device shill_device;
  shill_device.ifname = "wlan0";
  auto config = std::make_unique<Device::Config>(
      mac_addr, std::move(ipv4_subnet), std::move(host_ipv4_addr),
      std::move(guest_ipv4_addr));
  auto device =
      std::make_unique<Device>(Device::Type::kARCContainer, shill_device,
                               "arc_wlan0", "wlan0", std::move(config));

  NetworkDevice proto_device;
  FillDeviceProto(*device, &proto_device);

  ASSERT_EQ("arc_wlan0", proto_device.ifname());
  ASSERT_EQ("wlan0", proto_device.phys_ifname());
  // For ARC container, the name of the veth half set inside the container is
  // renamed to match the name of the host upstream network interface managed by
  // shill.
  ASSERT_EQ("wlan0", proto_device.guest_ifname());
  ASSERT_EQ(expected_guest_ipv4, proto_device.ipv4_addr());
  ASSERT_EQ(expected_host_ipv4, proto_device.host_ipv4_addr());
  ASSERT_EQ(expected_base_cidr.address(),
            net_base::IPv4Address::CreateFromBytes(
                proto_device.ipv4_subnet().addr().c_str(),
                proto_device.ipv4_subnet().addr().size()));
  ASSERT_EQ(expected_base_cidr.address().ToInAddr().s_addr,
            proto_device.ipv4_subnet().base_addr());
  ASSERT_EQ(expected_base_cidr.prefix_length(),
            proto_device.ipv4_subnet().prefix_len());
  ASSERT_EQ(NetworkDevice::ARC, proto_device.guest_type());
}

TEST_F(ProtoUtilsTest, ConvertARCVMDevice) {
  const auto mac_addr = addr_mgr_->GenerateMacAddress(3);
  auto ipv4_subnet =
      addr_mgr_->AllocateIPv4Subnet(AddressManager::GuestType::kArcNet, 0);
  auto host_ipv4_addr = ipv4_subnet->AllocateAtOffset(1);
  auto guest_ipv4_addr = ipv4_subnet->AllocateAtOffset(2);
  auto expected_host_ipv4 = host_ipv4_addr->cidr().address().ToInAddr().s_addr;
  auto expected_guest_ipv4 =
      guest_ipv4_addr->cidr().address().ToInAddr().s_addr;
  auto expected_base_cidr = ipv4_subnet->base_cidr();

  ShillClient::Device shill_device;
  shill_device.ifname = "wlan0";
  auto config = std::make_unique<Device::Config>(
      mac_addr, std::move(ipv4_subnet), std::move(host_ipv4_addr),
      std::move(guest_ipv4_addr));
  auto device =
      std::make_unique<Device>(Device::Type::kARCVM, shill_device, "arc_wlan0",
                               "eth3", std::move(config));

  NetworkDevice proto_device;
  FillDeviceProto(*device, &proto_device);

  ASSERT_EQ("arc_wlan0", proto_device.ifname());
  ASSERT_EQ("wlan0", proto_device.phys_ifname());
  // For ARCVM, the name of the virtio interface is controlled by the virtio
  // driver and follows a ethernet-like pattern.
  ASSERT_EQ("eth3", proto_device.guest_ifname());
  ASSERT_EQ(expected_guest_ipv4, proto_device.ipv4_addr());
  ASSERT_EQ(expected_host_ipv4, proto_device.host_ipv4_addr());
  ASSERT_EQ(expected_base_cidr.address(),
            net_base::IPv4Address::CreateFromBytes(
                proto_device.ipv4_subnet().addr().c_str(),
                proto_device.ipv4_subnet().addr().size()));
  ASSERT_EQ(expected_base_cidr.address().ToInAddr().s_addr,
            proto_device.ipv4_subnet().base_addr());
  ASSERT_EQ(expected_base_cidr.prefix_length(),
            proto_device.ipv4_subnet().prefix_len());
  ASSERT_EQ(NetworkDevice::ARCVM, proto_device.guest_type());
}

TEST_F(ProtoUtilsTest, ConvertARC0ForARCContainer) {
  const auto mac_addr = addr_mgr_->GenerateMacAddress(0);
  auto ipv4_subnet =
      addr_mgr_->AllocateIPv4Subnet(AddressManager::GuestType::kArc0, 0);
  auto host_ipv4_addr = ipv4_subnet->AllocateAtOffset(1);
  auto guest_ipv4_addr = ipv4_subnet->AllocateAtOffset(2);
  auto expected_host_ipv4 = host_ipv4_addr->cidr().address().ToInAddr().s_addr;
  auto expected_guest_ipv4 =
      guest_ipv4_addr->cidr().address().ToInAddr().s_addr;
  auto expected_base_cidr = ipv4_subnet->base_cidr();

  auto config = std::make_unique<Device::Config>(
      mac_addr, std::move(ipv4_subnet), std::move(host_ipv4_addr),
      std::move(guest_ipv4_addr));
  auto device = std::make_unique<Device>(Device::Type::kARC0, std::nullopt,
                                         "arcbr0", "arc0", std::move(config));

  NetworkDevice proto_device;
  FillDeviceProto(*device, &proto_device);

  ASSERT_EQ("arcbr0", proto_device.ifname());
  // Convention for arc0 is to reuse the virtual interface name in
  // place of the interface name of the upstream network used by other ARC
  // Devices.
  ASSERT_EQ("arc0", proto_device.phys_ifname());
  // For arc0 with ARC container, the name of the veth half inside ARC is set
  // to "arc0" for legacy compatibility with old ARC N code, and ARC P code
  // prior to ARC multinetworking support.
  ASSERT_EQ("arc0", proto_device.guest_ifname());
  ASSERT_EQ(expected_guest_ipv4, proto_device.ipv4_addr());
  ASSERT_EQ(expected_host_ipv4, proto_device.host_ipv4_addr());
  ASSERT_EQ(expected_base_cidr.address(),
            net_base::IPv4Address::CreateFromBytes(
                proto_device.ipv4_subnet().addr().c_str(),
                proto_device.ipv4_subnet().addr().size()));
  ASSERT_EQ(expected_base_cidr.address().ToInAddr().s_addr,
            proto_device.ipv4_subnet().base_addr());
  ASSERT_EQ(expected_base_cidr.prefix_length(),
            proto_device.ipv4_subnet().prefix_len());
  ASSERT_EQ(NetworkDevice::UNKNOWN, proto_device.guest_type());
}

TEST_F(ProtoUtilsTest, ConvertARC0ForARCVM) {
  const auto mac_addr = addr_mgr_->GenerateMacAddress(0);
  auto ipv4_subnet =
      addr_mgr_->AllocateIPv4Subnet(AddressManager::GuestType::kArc0, 0);
  auto host_ipv4_addr = ipv4_subnet->AllocateAtOffset(1);
  auto guest_ipv4_addr = ipv4_subnet->AllocateAtOffset(2);
  auto expected_host_ipv4 = host_ipv4_addr->cidr().address().ToInAddr().s_addr;
  auto expected_guest_ipv4 =
      guest_ipv4_addr->cidr().address().ToInAddr().s_addr;
  auto expected_base_cidr = ipv4_subnet->base_cidr();

  auto config = std::make_unique<Device::Config>(
      mac_addr, std::move(ipv4_subnet), std::move(host_ipv4_addr),
      std::move(guest_ipv4_addr));
  auto device = std::make_unique<Device>(Device::Type::kARC0, std::nullopt,
                                         "arcbr0", "arc0", std::move(config));

  NetworkDevice proto_device;
  FillDeviceProto(*device, &proto_device);

  ASSERT_EQ("arcbr0", proto_device.ifname());
  // Convention for arc0 is to reuse the virtual interface name in
  // place of the interface name of the upstream network used by other ARC
  // Devices.
  ASSERT_EQ("arc0", proto_device.phys_ifname());
  // For arc0 with ARC container, the name of the veth half inside ARC is set
  // to "arc0" for legacy compatibility with old ARC N code, and ARC P code
  // prior to ARC multinetworking support.
  ASSERT_EQ("arc0", proto_device.guest_ifname());
  ASSERT_EQ(expected_guest_ipv4, proto_device.ipv4_addr());
  ASSERT_EQ(expected_host_ipv4, proto_device.host_ipv4_addr());
  ASSERT_EQ(expected_base_cidr.address(),
            net_base::IPv4Address::CreateFromBytes(
                proto_device.ipv4_subnet().addr().c_str(),
                proto_device.ipv4_subnet().addr().size()));
  ASSERT_EQ(expected_base_cidr.address().ToInAddr().s_addr,
            proto_device.ipv4_subnet().base_addr());
  ASSERT_EQ(expected_base_cidr.prefix_length(),
            proto_device.ipv4_subnet().prefix_len());
  ASSERT_EQ(NetworkDevice::UNKNOWN, proto_device.guest_type());
}

TEST_F(ProtoUtilsTest, FillNetworkClientInfoProto) {
  DownstreamClientInfo info;
  info.mac_addr = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
  info.ipv4_addr = net_base::IPv4Address(127, 0, 0, 1);
  info.ipv6_addresses.push_back(
      *net_base::IPv6Address::CreateFromString("fe80::1"));
  info.ipv6_addresses.push_back(
      *net_base::IPv6Address::CreateFromString("fe80::3"));
  info.hostname = "test_host";
  info.vendor_class = "test_vendor_class";

  NetworkClientInfo proto;
  FillNetworkClientInfoProto(info, &proto);

  EXPECT_EQ(proto.mac_addr(),
            std::string({0x11, 0x22, 0x33, 0x44, 0x55, 0x66}));
  EXPECT_EQ(proto.ipv4_addr(), std::string({127, 0, 0, 1}));
  EXPECT_EQ(proto.ipv6_addresses().size(), 2);
  EXPECT_EQ(proto.ipv6_addresses()[0],
            net_base::IPv6Address::CreateFromString("fe80::1")->ToByteString());
  EXPECT_EQ(proto.ipv6_addresses()[1],
            net_base::IPv6Address::CreateFromString("fe80::3")->ToByteString());
  EXPECT_EQ(proto.hostname(), "test_host");
  EXPECT_EQ(proto.vendor_class(), "test_vendor_class");
}

}  // namespace patchpanel
