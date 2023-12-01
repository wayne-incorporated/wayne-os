// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "patchpanel/crostini_service.h"

#include <algorithm>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <base/functional/bind.h>
#include <base/functional/callback_helpers.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <metrics/metrics_library_mock.h>
#include <net-base/ipv4_address.h>
#include <patchpanel/proto_bindings/patchpanel_service.pb.h>

#include "patchpanel/address_manager.h"
#include "patchpanel/datapath.h"
#include "patchpanel/mock_datapath.h"
#include "patchpanel/net_util.h"
#include "patchpanel/routing_service.h"

using testing::_;
using testing::AnyNumber;
using testing::Eq;
using testing::Invoke;
using testing::Mock;
using testing::Pair;
using testing::Pointee;
using testing::Return;
using testing::ReturnRef;
using testing::StrEq;
using testing::UnorderedElementsAre;

namespace patchpanel {
namespace {

MATCHER_P(ShillDeviceHasInterfaceName, expected_ifname, "") {
  return arg.ifname == expected_ifname;
}

class CrostiniServiceTest : public testing::Test {
 protected:
  void SetUp() override {
    datapath_ = std::make_unique<MockDatapath>();
    addr_mgr_ = std::make_unique<AddressManager>();
  }

  std::unique_ptr<CrostiniService> NewService() {
    return std::make_unique<CrostiniService>(
        addr_mgr_.get(), datapath_.get(),
        base::BindRepeating(&CrostiniServiceTest::DeviceHandler,
                            base::Unretained(this)));
  }

  void DeviceHandler(const Device& device, Device::ChangeEvent event) {
    guest_devices_[device.host_ifname()] = event;
  }

  std::unique_ptr<AddressManager> addr_mgr_;
  std::unique_ptr<MockDatapath> datapath_;
  std::map<std::string, Device::ChangeEvent> guest_devices_;
};

TEST_F(CrostiniServiceTest, StartStopCrostiniVM) {
  constexpr uint64_t vm_id = 101;
  auto crostini = NewService();

  ShillClient::Device wlan0_dev;
  wlan0_dev.ifname = "wlan0";
  crostini->OnShillDefaultLogicalDeviceChanged(wlan0_dev, {});

  EXPECT_CALL(*datapath_, AddTAP("", _, _, "crosvm"))
      .WillOnce(Return("vmtap0"));
  EXPECT_CALL(*datapath_, AddIPv4Route).WillOnce(Return(true));
  EXPECT_CALL(*datapath_,
              StartRoutingDeviceAsUser("vmtap0", _, TrafficSource::kCrosVM,
                                       Eq(std::nullopt)));
  EXPECT_CALL(*datapath_, AddInboundIPv4DNAT).Times(0);

  // There should be no virtual device before the VM starts.
  ASSERT_EQ(nullptr, crostini->GetDevice(vm_id));
  ASSERT_TRUE(crostini->GetDevices().empty());

  // The virtual datapath for the Crostini VM can successfully start.
  auto* device = crostini->Start(vm_id, CrostiniService::VMType::kTermina,
                                 /*subnet_index=*/0);
  Mock::VerifyAndClearExpectations(datapath_.get());
  ASSERT_NE(nullptr, device);
  ASSERT_EQ("vmtap0", device->host_ifname());
  ASSERT_EQ(std::nullopt, device->shill_device());
  auto it = guest_devices_.find("vmtap0");
  ASSERT_NE(guest_devices_.end(), it);
  ASSERT_EQ(Device::ChangeEvent::kAdded, it->second);
  guest_devices_.clear();

  // After starting, there should be a virtual device.
  ASSERT_EQ(device, crostini->GetDevice(vm_id));
  auto devices = crostini->GetDevices();
  ASSERT_FALSE(devices.empty());
  ASSERT_EQ(device, devices[0]);

  // The virtual datapath for the Crostini VM can successfully stop.
  EXPECT_CALL(*datapath_, RemoveInterface("vmtap0"));
  EXPECT_CALL(*datapath_, StopRoutingDevice("vmtap0"));
  EXPECT_CALL(*datapath_, RemoveInboundIPv4DNAT).Times(0);
  crostini->Stop(vm_id);
  it = guest_devices_.find("vmtap0");
  ASSERT_NE(guest_devices_.end(), it);
  ASSERT_EQ(Device::ChangeEvent::kRemoved, it->second);

  // After stopping the datapath setup, there should be no virtual device.
  ASSERT_EQ(nullptr, crostini->GetDevice(vm_id));
  ASSERT_TRUE(crostini->GetDevices().empty());
}

TEST_F(CrostiniServiceTest, StartStopParallelsVM) {
  constexpr uint64_t vm_id = 102;
  auto crostini = NewService();

  ShillClient::Device wlan0_dev;
  wlan0_dev.ifname = "wlan0";
  crostini->OnShillDefaultLogicalDeviceChanged(wlan0_dev, {});

  EXPECT_CALL(*datapath_, AddTAP("", _, _, "crosvm"))
      .WillOnce(Return("vmtap0"));
  EXPECT_CALL(*datapath_, AddIPv4Route).Times(0);
  EXPECT_CALL(*datapath_,
              StartRoutingDeviceAsUser("vmtap0", _, TrafficSource::kParallelsVM,
                                       Eq(std::nullopt)));
  EXPECT_CALL(*datapath_,
              AddInboundIPv4DNAT(AutoDNATTarget::kParallels,
                                 ShillDeviceHasInterfaceName("wlan0"),
                                 net_base::IPv4Address(100, 115, 93, 2)));

  // There should be no virtual device before the VM starts.
  ASSERT_EQ(nullptr, crostini->GetDevice(vm_id));
  ASSERT_TRUE(crostini->GetDevices().empty());

  // The virtual datapath for the Parallels VM can successfully start.
  auto* device = crostini->Start(vm_id, CrostiniService::VMType::kParallels,
                                 /*subnet_index=*/1);
  ASSERT_NE(nullptr, device);
  ASSERT_EQ("vmtap0", device->host_ifname());
  ASSERT_EQ(std::nullopt, device->shill_device());
  Mock::VerifyAndClearExpectations(datapath_.get());
  auto it = guest_devices_.find("vmtap0");
  ASSERT_NE(guest_devices_.end(), it);
  ASSERT_EQ(Device::ChangeEvent::kAdded, it->second);
  guest_devices_.clear();

  // After starting, there should be a virtual device.
  ASSERT_EQ(device, crostini->GetDevice(vm_id));
  auto devices = crostini->GetDevices();
  ASSERT_NE(nullptr, device);
  ASSERT_FALSE(devices.empty());
  ASSERT_EQ(device, devices[0]);

  // The virtual datapath for the Parallels VM can successfully stop.
  EXPECT_CALL(*datapath_, RemoveInterface("vmtap0"));
  EXPECT_CALL(*datapath_, StopRoutingDevice("vmtap0"));
  EXPECT_CALL(*datapath_,
              RemoveInboundIPv4DNAT(AutoDNATTarget::kParallels,
                                    ShillDeviceHasInterfaceName("wlan0"),
                                    net_base::IPv4Address(100, 115, 93, 2)));
  crostini->Stop(vm_id);
  it = guest_devices_.find("vmtap0");
  ASSERT_NE(guest_devices_.end(), it);
  ASSERT_EQ(Device::ChangeEvent::kRemoved, it->second);

  // After stopping the datapath setup, there should be no virtual device.
  ASSERT_EQ(nullptr, crostini->GetDevice(vm_id));
  ASSERT_TRUE(crostini->GetDevices().empty());
}

TEST_F(CrostiniServiceTest, MultipleVMs) {
  constexpr uint64_t vm_id1 = 101;
  constexpr uint64_t vm_id2 = 102;
  constexpr uint64_t vm_id3 = 103;
  auto crostini = NewService();

  ShillClient::Device wlan0_dev;
  wlan0_dev.ifname = "wlan0";
  crostini->OnShillDefaultLogicalDeviceChanged(wlan0_dev, {});

  // There should be no virtual device before any VM starts.
  ASSERT_EQ(nullptr, crostini->GetDevice(vm_id1));
  ASSERT_EQ(nullptr, crostini->GetDevice(vm_id2));
  ASSERT_EQ(nullptr, crostini->GetDevice(vm_id3));
  ASSERT_TRUE(crostini->GetDevices().empty());

  // Start first Crostini VM.
  EXPECT_CALL(*datapath_, AddIPv4Route).WillRepeatedly(Return(true));
  EXPECT_CALL(*datapath_, AddTAP("", _, _, "crosvm"))
      .WillOnce(Return("vmtap0"));
  EXPECT_CALL(*datapath_,
              StartRoutingDeviceAsUser("vmtap0", _, TrafficSource::kCrosVM,
                                       Eq(std::nullopt)));
  EXPECT_CALL(*datapath_, AddInboundIPv4DNAT).Times(0);
  auto* device = crostini->Start(vm_id1, CrostiniService::VMType::kTermina,
                                 /*subnet_index=*/0);
  ASSERT_NE(nullptr, device);
  ASSERT_EQ("vmtap0", device->host_ifname());
  ASSERT_EQ(std::nullopt, device->shill_device());
  auto it = guest_devices_.find("vmtap0");
  ASSERT_NE(guest_devices_.end(), it);
  ASSERT_EQ(Device::ChangeEvent::kAdded, it->second);
  guest_devices_.clear();
  Mock::VerifyAndClearExpectations(datapath_.get());

  // After starting, there should be a virtual device for that VM.
  ASSERT_EQ(device, crostini->GetDevice(vm_id1));

  // Start Parallels VM.
  EXPECT_CALL(*datapath_, AddTAP("", _, _, "crosvm"))
      .WillOnce(Return("vmtap1"));
  EXPECT_CALL(*datapath_, AddIPv4Route).WillRepeatedly(Return(true));
  EXPECT_CALL(*datapath_,
              StartRoutingDeviceAsUser("vmtap1", _, TrafficSource::kParallelsVM,
                                       Eq(std::nullopt)));
  EXPECT_CALL(*datapath_,
              AddInboundIPv4DNAT(AutoDNATTarget::kParallels,
                                 ShillDeviceHasInterfaceName("wlan0"),
                                 net_base::IPv4Address(100, 115, 93, 2)));
  device = crostini->Start(vm_id2, CrostiniService::VMType::kParallels,
                           /*subnet_index=*/0);
  ASSERT_NE(nullptr, device);
  ASSERT_EQ("vmtap1", device->host_ifname());
  ASSERT_EQ(std::nullopt, device->shill_device());
  it = guest_devices_.find("vmtap1");
  ASSERT_NE(guest_devices_.end(), it);
  ASSERT_EQ(Device::ChangeEvent::kAdded, it->second);
  guest_devices_.clear();
  Mock::VerifyAndClearExpectations(datapath_.get());

  // After starting that second VM, there should be another virtual device.
  ASSERT_EQ(device, crostini->GetDevice(vm_id2));

  // Start second Crostini VM.
  EXPECT_CALL(*datapath_, AddIPv4Route).WillRepeatedly(Return(true));
  EXPECT_CALL(*datapath_, AddTAP("", _, _, "crosvm"))
      .WillOnce(Return("vmtap2"));
  EXPECT_CALL(*datapath_,
              StartRoutingDeviceAsUser("vmtap2", _, TrafficSource::kCrosVM,
                                       Eq(std::nullopt)));
  EXPECT_CALL(*datapath_, AddInboundIPv4DNAT).Times(0);
  device = crostini->Start(vm_id3, CrostiniService::VMType::kTermina,
                           /*subnet_index=*/0);
  ASSERT_NE(nullptr, device);
  ASSERT_EQ("vmtap2", device->host_ifname());
  ASSERT_EQ(std::nullopt, device->shill_device());
  it = guest_devices_.find("vmtap2");
  ASSERT_NE(guest_devices_.end(), it);
  ASSERT_EQ(Device::ChangeEvent::kAdded, it->second);
  guest_devices_.clear();
  Mock::VerifyAndClearExpectations(datapath_.get());

  // After starting that third VM, there should be another virtual device.
  ASSERT_EQ(device, crostini->GetDevice(vm_id3));

  // There are three virtual devices owned by CrostiniService.
  auto devices = crostini->GetDevices();
  ASSERT_FALSE(devices.empty());
  for (const auto* dev : devices) {
    ASSERT_EQ(std::nullopt, dev->shill_device());
    ASSERT_EQ("", dev->guest_ifname());
    if (dev->host_ifname() == "vmtap0") {
      ASSERT_EQ(Device::Type::kTerminaVM, dev->type());
    } else if (dev->host_ifname() == "vmtap1") {
      ASSERT_EQ(Device::Type::kParallelsVM, dev->type());
    } else if (dev->host_ifname() == "vmtap2") {
      ASSERT_EQ(Device::Type::kTerminaVM, dev->type());
    } else {
      FAIL() << "Unexpected guest Device " << dev->host_ifname();
    }
  }

  // Stop first Crostini VM. Its virtual device is destroyed.
  EXPECT_CALL(*datapath_, RemoveInterface("vmtap0"));
  EXPECT_CALL(*datapath_, StopRoutingDevice("vmtap0"));
  EXPECT_CALL(*datapath_, RemoveInboundIPv4DNAT).Times(0);
  crostini->Stop(vm_id1);
  ASSERT_EQ(nullptr, crostini->GetDevice(vm_id1));
  it = guest_devices_.find("vmtap0");
  ASSERT_NE(guest_devices_.end(), it);
  ASSERT_EQ(Device::ChangeEvent::kRemoved, it->second);
  guest_devices_.clear();
  Mock::VerifyAndClearExpectations(datapath_.get());

  // Stop second Crostini VM. Its virtual device is destroyed.
  EXPECT_CALL(*datapath_, RemoveInterface("vmtap2"));
  EXPECT_CALL(*datapath_, StopRoutingDevice("vmtap2"));
  EXPECT_CALL(*datapath_, RemoveInboundIPv4DNAT).Times(0);
  crostini->Stop(vm_id3);
  ASSERT_EQ(nullptr, crostini->GetDevice(vm_id3));
  it = guest_devices_.find("vmtap2");
  ASSERT_NE(guest_devices_.end(), it);
  ASSERT_EQ(Device::ChangeEvent::kRemoved, it->second);
  guest_devices_.clear();
  Mock::VerifyAndClearExpectations(datapath_.get());

  // Stop Parallels VM. Its virtual device is destroyed.
  EXPECT_CALL(*datapath_, RemoveInterface("vmtap1"));
  EXPECT_CALL(*datapath_, StopRoutingDevice("vmtap1"));
  EXPECT_CALL(*datapath_,
              RemoveInboundIPv4DNAT(AutoDNATTarget::kParallels,
                                    ShillDeviceHasInterfaceName("wlan0"),
                                    net_base::IPv4Address(100, 115, 93, 2)));
  crostini->Stop(vm_id2);
  ASSERT_EQ(nullptr, crostini->GetDevice(vm_id2));
  it = guest_devices_.find("vmtap1");
  ASSERT_NE(guest_devices_.end(), it);
  ASSERT_EQ(Device::ChangeEvent::kRemoved, it->second);

  // There are no more virtual devices left.
  ASSERT_TRUE(crostini->GetDevices().empty());
}

TEST_F(CrostiniServiceTest, DefaultLogicalDeviceChange) {
  constexpr uint64_t vm_id1 = 101;
  constexpr uint64_t vm_id2 = 102;
  const auto parallels_addr = net_base::IPv4Address(100, 115, 93, 2);
  auto crostini = NewService();

  // Start a Crostini VM and a Parallels VM.
  EXPECT_CALL(*datapath_, AddIPv4Route).WillRepeatedly(Return(true));
  EXPECT_CALL(*datapath_, AddTAP("", _, _, "crosvm"))
      .WillOnce(Return("vmtap0"))
      .WillOnce(Return("vmtap1"));
  EXPECT_CALL(*datapath_,
              StartRoutingDeviceAsUser("vmtap0", _, TrafficSource::kCrosVM,
                                       Eq(std::nullopt)));
  EXPECT_CALL(*datapath_,
              StartRoutingDeviceAsUser("vmtap1", _, TrafficSource::kParallelsVM,
                                       Eq(std::nullopt)));
  EXPECT_CALL(*datapath_, AddInboundIPv4DNAT).Times(0);
  crostini->Start(vm_id1, CrostiniService::VMType::kTermina,
                  /*subnet_index=*/0);
  crostini->Start(vm_id2, CrostiniService::VMType::kParallels,
                  /*subnet_index=*/0);
  Mock::VerifyAndClearExpectations(datapath_.get());

  // A logical default Device is available.
  ShillClient::Device wlan0_dev;
  wlan0_dev.ifname = "wlan0";
  EXPECT_CALL(
      *datapath_,
      AddInboundIPv4DNAT(AutoDNATTarget::kParallels,
                         ShillDeviceHasInterfaceName("wlan0"), parallels_addr));
  crostini->OnShillDefaultLogicalDeviceChanged(wlan0_dev, {});
  Mock::VerifyAndClearExpectations(datapath_.get());

  // The logical default Device changes.
  ShillClient::Device eth0_dev;
  eth0_dev.ifname = "eth0";
  EXPECT_CALL(*datapath_,
              RemoveInboundIPv4DNAT(AutoDNATTarget::kParallels,
                                    ShillDeviceHasInterfaceName("wlan0"),
                                    parallels_addr));
  EXPECT_CALL(
      *datapath_,
      AddInboundIPv4DNAT(AutoDNATTarget::kParallels,
                         ShillDeviceHasInterfaceName("eth0"), parallels_addr));
  crostini->OnShillDefaultLogicalDeviceChanged(eth0_dev, wlan0_dev);
  Mock::VerifyAndClearExpectations(datapath_.get());

  // The logical default Device is not available anymore.
  EXPECT_CALL(*datapath_,
              RemoveInboundIPv4DNAT(AutoDNATTarget::kParallels,
                                    ShillDeviceHasInterfaceName("eth0"),
                                    parallels_addr));
  crostini->OnShillDefaultLogicalDeviceChanged({}, eth0_dev);
  Mock::VerifyAndClearExpectations(datapath_.get());
}

TEST_F(CrostiniServiceTest, VMTypeConversions) {
  EXPECT_EQ(CrostiniService::VMType::kTermina,
            CrostiniService::VMTypeFromDeviceType(Device::Type::kTerminaVM));
  EXPECT_EQ(CrostiniService::VMType::kParallels,
            CrostiniService::VMTypeFromDeviceType(Device::Type::kParallelsVM));
  EXPECT_EQ(std::nullopt,
            CrostiniService::VMTypeFromDeviceType(Device::Type::kARC0));
  EXPECT_EQ(std::nullopt,
            CrostiniService::VMTypeFromDeviceType(Device::Type::kARCContainer));
  EXPECT_EQ(std::nullopt,
            CrostiniService::VMTypeFromDeviceType(Device::Type::kARCVM));

  EXPECT_EQ(
      CrostiniService::VMType::kTermina,
      CrostiniService::VMTypeFromProtoGuestType(NetworkDevice::TERMINA_VM));
  EXPECT_EQ(
      CrostiniService::VMType::kParallels,
      CrostiniService::VMTypeFromProtoGuestType(NetworkDevice::PARALLELS_VM));
  EXPECT_EQ(std::nullopt,
            CrostiniService::VMTypeFromProtoGuestType(NetworkDevice::ARC));
  EXPECT_EQ(std::nullopt,
            CrostiniService::VMTypeFromProtoGuestType(NetworkDevice::ARCVM));
  EXPECT_EQ(std::nullopt,
            CrostiniService::VMTypeFromProtoGuestType(NetworkDevice::UNKNOWN));

  EXPECT_EQ(TrafficSource::kCrosVM, CrostiniService::TrafficSourceFromVMType(
                                        CrostiniService::VMType::kTermina));
  EXPECT_EQ(TrafficSource::kParallelsVM,
            CrostiniService::TrafficSourceFromVMType(
                CrostiniService::VMType::kParallels));

  EXPECT_EQ(GuestMessage::TERMINA_VM,
            CrostiniService::GuestMessageTypeFromVMType(
                CrostiniService::VMType::kTermina));
  EXPECT_EQ(GuestMessage::PARALLELS_VM,
            CrostiniService::GuestMessageTypeFromVMType(
                CrostiniService::VMType::kParallels));

  EXPECT_EQ(
      AddressManager::GuestType::kTerminaVM,
      CrostiniService::GuestTypeFromVMType(CrostiniService::VMType::kTermina));
  EXPECT_EQ(AddressManager::GuestType::kParallelsVM,
            CrostiniService::GuestTypeFromVMType(
                CrostiniService::VMType::kParallels));

  EXPECT_EQ(Device::Type::kTerminaVM,
            CrostiniService::VirtualDeviceTypeFromVMType(
                CrostiniService::VMType::kTermina));
  EXPECT_EQ(Device::Type::kParallelsVM,
            CrostiniService::VirtualDeviceTypeFromVMType(
                CrostiniService::VMType::kParallels));
}

}  // namespace
}  // namespace patchpanel
