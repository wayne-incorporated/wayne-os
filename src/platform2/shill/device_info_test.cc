// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/device_info.h"

#include <memory>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/netlink.h>  // Needs typedefs from sys/socket.h.
#include <linux/rtnetlink.h>
#include <linux/sockios.h>
#include <net/if_arp.h>
#include <sys/socket.h>

#include <base/check.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/functional/bind.h>
#include <base/memory/ref_counted.h>
#include <base/notreached.h>
#include <base/strings/string_number_conversions.h>
#include <base/test/bind.h>
#include <chromeos/patchpanel/dbus/fake_client.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "shill/cellular/mock_modem_info.h"
#include "shill/ipconfig.h"
#include "shill/logging.h"
#include "shill/manager.h"
#include "shill/mock_control.h"
#include "shill/mock_device.h"
#include "shill/mock_log.h"
#include "shill/mock_manager.h"
#include "shill/mock_metrics.h"
#include "shill/mock_routing_table.h"
#include "shill/net/ip_address.h"
#include "shill/net/mock_netlink_manager.h"
#include "shill/net/mock_rtnl_handler.h"
#include "shill/net/mock_sockets.h"
#include "shill/net/mock_time.h"
#include "shill/net/nl80211_message.h"
#include "shill/net/rtnl_link_stats.h"
#include "shill/net/rtnl_message.h"
#include "shill/network/mock_network.h"
#include "shill/network/network.h"
#include "shill/test_event_dispatcher.h"
#include "shill/vpn/mock_vpn_provider.h"

using testing::_;
using testing::AnyNumber;
using testing::ContainerEq;
using testing::DoAll;
using testing::ElementsAreArray;
using testing::HasSubstr;
using testing::Mock;
using testing::NotNull;
using testing::Return;
using testing::SetArgPointee;
using testing::StrictMock;
using testing::Test;

namespace shill {

class DeviceInfoTest : public Test {
 public:
  DeviceInfoTest()
      : manager_(&control_interface_, &dispatcher_, &metrics_),
        device_info_(&manager_),
        test_device_name_(kTestDeviceName) {}
  ~DeviceInfoTest() override = default;

  void SetUp() override {
    device_info_.rtnl_handler_ = &rtnl_handler_;
    device_info_.routing_table_ = &routing_table_;
    device_info_.netlink_manager_ = &netlink_manager_;
    device_info_.time_ = &time_;
    manager_.set_mock_device_info(&device_info_);
    patchpanel_client_ = new patchpanel::FakeClient();
    manager_.patchpanel_client_.reset(patchpanel_client_);
    CreateSysfsRoot();
  }

  DeviceRefPtr CreateDevice(const std::string& link_name,
                            const std::string& address,
                            int interface_index,
                            Technology technology) {
    return device_info_.CreateDevice(link_name, address, interface_index,
                                     technology);
  }

  void RegisterDevice(const DeviceRefPtr& device) {
    device_info_.RegisterDevice(device);
  }

  virtual std::set<int>& GetDelayedDevices() {
    return device_info_.delayed_devices_;
  }

  void SetSockets() {
    auto sockets = std::make_unique<MockSockets>();
    mock_sockets_ = sockets.get();
    device_info_.set_sockets_for_test(std::move(sockets));
  }

  // Takes ownership of |provider|.
  void SetVPNProvider(VPNProvider* provider) {
    manager_.vpn_provider_.reset(provider);
    manager_.UpdateProviderMapping();
  }

  void SetManagerRunning(bool running) { manager_.running_ = running; }

  void CreateSysfsRoot() {
    CHECK(temp_dir_.CreateUniqueTempDir());
    device_info_root_ = temp_dir_.GetPath().Append("sys/class/net");
    device_info_.device_info_root_ = device_info_root_;
  }

  void CreateInfoFile(const std::string& name, const std::string& contents) {
    base::FilePath info_path = GetInfoPath(name);
    LOG(INFO) << "Path " << info_path;
    EXPECT_TRUE(base::CreateDirectory(info_path.DirName()));
    std::string contents_newline(contents + "\n");
    EXPECT_TRUE(base::WriteFile(info_path, contents_newline.c_str(),
                                contents_newline.size()));
  }

  base::FilePath GetInfoPath(const std::string& name) {
    return device_info_root_.Append(test_device_name_).Append(name);
  }

 protected:
  static const int kTestDeviceIndex;
  static const char kTestDeviceName[];
  static const uint8_t kTestMacAddress[];
  static const char kTestIPAddress0[];
  static const int kTestIPAddressPrefix0;
  static const char kTestIPAddress1[];
  static const int kTestIPAddressPrefix1;
  static const char kTestIPAddress2[];
  static const char kTestIPAddress3[];
  static const char kTestIPAddress4[];
  static const char kTestIPAddress5[];
  static const char kTestIPAddress6[];
  static const char kTestIPAddress7[];
  static const int kReceiveByteCount;
  static const int kTransmitByteCount;
  static const char kVendorIdString[];
  static const char kProductIdString[];
  static const char kSubsystemIdString[];
  static const char kInvalidIdString[];
  static const int kVendorId;
  static const int kProductId;
  static const int kSubsystemId;
  static const int kDefaultTestHardwareId;

  std::unique_ptr<RTNLMessage> BuildLinkMessage(RTNLMessage::Mode mode);
  std::unique_ptr<RTNLMessage> BuildLinkMessageWithInterfaceName(
      RTNLMessage::Mode mode,
      const std::string& interface_name,
      int interface_index = kTestDeviceIndex);
  std::unique_ptr<RTNLMessage> BuildAddressMessage(RTNLMessage::Mode mode,
                                                   const IPAddress& address,
                                                   unsigned char flags,
                                                   unsigned char scope);
  void SendMessageToDeviceInfo(const RTNLMessage& message);

  void CreateWiFiDevice();

  MockControl control_interface_;
  MockMetrics metrics_;
  StrictMock<MockManager> manager_;
  DeviceInfo device_info_;
  EventDispatcherForTest dispatcher_;
  MockRoutingTable routing_table_;
  MockNetlinkManager netlink_manager_;
  StrictMock<MockRTNLHandler> rtnl_handler_;
  MockSockets* mock_sockets_;  // Owned by DeviceInfo.
  MockTime time_;
  patchpanel::FakeClient* patchpanel_client_;  // Owned by Manager

  base::ScopedTempDir temp_dir_;
  base::FilePath device_info_root_;
  std::string test_device_name_;
};

const int DeviceInfoTest::kTestDeviceIndex = 123456;
const char DeviceInfoTest::kTestDeviceName[] = "test-device";
const uint8_t DeviceInfoTest::kTestMacAddress[] = {0xaa, 0xbb, 0xcc,
                                                   0xdd, 0xee, 0xff};
const char DeviceInfoTest::kTestIPAddress0[] = "192.168.1.1";
const int DeviceInfoTest::kTestIPAddressPrefix0 = 24;
const char DeviceInfoTest::kTestIPAddress1[] = "fe80::1aa9:5ff:abcd:1234";
const int DeviceInfoTest::kTestIPAddressPrefix1 = 64;
const char DeviceInfoTest::kTestIPAddress2[] = "fe80::1aa9:5ff:abcd:1235";
const char DeviceInfoTest::kTestIPAddress3[] = "fe80::1aa9:5ff:abcd:1236";
const char DeviceInfoTest::kTestIPAddress4[] = "fe80::1aa9:5ff:abcd:1237";
const char DeviceInfoTest::kTestIPAddress5[] = "192.168.1.2";
const char DeviceInfoTest::kTestIPAddress6[] = "192.168.2.2";
const char DeviceInfoTest::kTestIPAddress7[] = "fe80::1aa9:5ff:abcd:1238";
const int DeviceInfoTest::kReceiveByteCount = 1234;
const int DeviceInfoTest::kTransmitByteCount = 5678;
const char DeviceInfoTest::kVendorIdString[] = "0x0123";
const char DeviceInfoTest::kProductIdString[] = "0x4567";
const char DeviceInfoTest::kSubsystemIdString[] = "0x89ab";
const char DeviceInfoTest::kInvalidIdString[] = "invalid";
const int DeviceInfoTest::kVendorId = 0x0123;
const int DeviceInfoTest::kProductId = 0x4567;
const int DeviceInfoTest::kSubsystemId = 0x89ab;
const int DeviceInfoTest::kDefaultTestHardwareId = -42;

std::unique_ptr<RTNLMessage> DeviceInfoTest::BuildLinkMessageWithInterfaceName(
    RTNLMessage::Mode mode,
    const std::string& interface_name,
    int interface_index) {
  auto message =
      std::make_unique<RTNLMessage>(RTNLMessage::kTypeLink, mode, 0, 0, 0,
                                    interface_index, IPAddress::kFamilyIPv4);
  message->SetAttribute(static_cast<uint16_t>(IFLA_IFNAME),
                        ByteString(interface_name, true));
  ByteString test_address(kTestMacAddress, sizeof(kTestMacAddress));
  message->SetAttribute(IFLA_ADDRESS, test_address);
  return message;
}

std::unique_ptr<RTNLMessage> DeviceInfoTest::BuildLinkMessage(
    RTNLMessage::Mode mode) {
  return BuildLinkMessageWithInterfaceName(mode, kTestDeviceName);
}

void DeviceInfoTest::SendMessageToDeviceInfo(const RTNLMessage& message) {
  if (message.type() == RTNLMessage::kTypeLink) {
    device_info_.LinkMsgHandler(message);
  } else {
    NOTREACHED();
  }
}

void DeviceInfoTest::CreateWiFiDevice() {
  // Mock a WiFi adapter.
  CreateInfoFile("uevent", "DEVTYPE=wlan");
  auto device = CreateDevice(kTestDeviceName, "address", kTestDeviceIndex,
                             Technology::kWiFi);
  if (device) {
    RegisterDevice(device);
  }
  auto message = BuildLinkMessage(RTNLMessage::kModeAdd);
  message->set_link_status(RTNLMessage::LinkStatus(0, IFF_LOWER_UP, 0));
  SendMessageToDeviceInfo(*message);
}

MATCHER_P(IsIPAddress, address, "") {
  // NB: IPAddress objects don't support the "==" operator as per style, so
  // we need a custom matcher.
  return address.Equals(arg);
}

TEST_F(DeviceInfoTest, StartStop) {
  auto& task_environment = dispatcher_.task_environment();
  EXPECT_EQ(nullptr, device_info_.link_listener_);
  EXPECT_TRUE(device_info_.infos_.empty());

  EXPECT_CALL(rtnl_handler_, RequestDump(RTNLHandler::kRequestLink));
  device_info_.Start();
  EXPECT_NE(nullptr, device_info_.link_listener_);
  EXPECT_TRUE(device_info_.infos_.empty());
  Mock::VerifyAndClearExpectations(&rtnl_handler_);

  // Start() should set up a periodic task to request link statistics.
  EXPECT_EQ(1, task_environment.GetPendingMainThreadTaskCount());
  EXPECT_CALL(rtnl_handler_, RequestDump(RTNLHandler::kRequestLink));
  task_environment.FastForwardBy(
      task_environment.NextMainThreadPendingTaskDelay());
  EXPECT_EQ(1, task_environment.GetPendingMainThreadTaskCount());
  EXPECT_CALL(rtnl_handler_, RequestDump(RTNLHandler::kRequestLink));
  task_environment.FastForwardBy(
      task_environment.NextMainThreadPendingTaskDelay());

  device_info_.Stop();
  EXPECT_EQ(nullptr, device_info_.link_listener_);
  EXPECT_TRUE(device_info_.infos_.empty());
}

TEST_F(DeviceInfoTest, RegisterDevice) {
  scoped_refptr<MockDevice> device0(
      new MockDevice(&manager_, "null0", "addr0", kTestDeviceIndex));

  EXPECT_CALL(*device0, Initialize());
  device_info_.RegisterDevice(device0);
}

TEST_F(DeviceInfoTest, DeviceEnumeration) {
  auto message = BuildLinkMessage(RTNLMessage::kModeAdd);
  message->set_link_status(RTNLMessage::LinkStatus(0, IFF_LOWER_UP, 0));
  EXPECT_EQ(nullptr, device_info_.GetDevice(kTestDeviceIndex));
  EXPECT_EQ(-1, device_info_.GetIndex(kTestDeviceName));
  SendMessageToDeviceInfo(*message);
  EXPECT_NE(nullptr, device_info_.GetDevice(kTestDeviceIndex));
  unsigned int flags = 0;
  EXPECT_TRUE(device_info_.GetFlags(kTestDeviceIndex, &flags));
  EXPECT_EQ(IFF_LOWER_UP, flags);
  ByteString address;
  EXPECT_TRUE(device_info_.GetMacAddress(kTestDeviceIndex, &address));
  EXPECT_FALSE(address.IsEmpty());
  EXPECT_TRUE(
      address.Equals(ByteString(kTestMacAddress, sizeof(kTestMacAddress))));
  EXPECT_EQ(kTestDeviceIndex, device_info_.GetIndex(kTestDeviceName));

  message = BuildLinkMessage(RTNLMessage::kModeAdd);
  message->set_link_status(RTNLMessage::LinkStatus(0, IFF_UP | IFF_RUNNING, 0));
  SendMessageToDeviceInfo(*message);
  EXPECT_TRUE(device_info_.GetFlags(kTestDeviceIndex, &flags));
  EXPECT_EQ(IFF_UP | IFF_RUNNING, flags);

  message = BuildLinkMessage(RTNLMessage::kModeDelete);
  EXPECT_CALL(manager_, DeregisterDevice(_)).Times(1);
  SendMessageToDeviceInfo(*message);
  EXPECT_EQ(nullptr, device_info_.GetDevice(kTestDeviceIndex));
  EXPECT_FALSE(device_info_.GetFlags(kTestDeviceIndex, nullptr));
  EXPECT_EQ(-1, device_info_.GetIndex(kTestDeviceName));
}

TEST_F(DeviceInfoTest, DeviceRemovedEvent) {
  // Remove a Wifi device.
  scoped_refptr<MockDevice> device0(
      new MockDevice(&manager_, "null0", "addr0", kTestDeviceIndex));
  device_info_.infos_[kTestDeviceIndex].device = device0;
  auto message = BuildLinkMessage(RTNLMessage::kModeDelete);
  EXPECT_CALL(*device0, technology()).WillRepeatedly(Return(Technology::kWiFi));
  EXPECT_CALL(manager_, DeregisterDevice(_)).Times(1);
  EXPECT_CALL(metrics_, DeregisterDevice(kTestDeviceIndex)).Times(1);
  SendMessageToDeviceInfo(*message);
  Mock::VerifyAndClearExpectations(device0.get());

  // Remove a Cellular device.
  scoped_refptr<MockDevice> device1(
      new MockDevice(&manager_, "null0", "addr0", kTestDeviceIndex));
  device_info_.infos_[kTestDeviceIndex].device = device1;
  EXPECT_CALL(*device1, technology())
      .WillRepeatedly(Return(Technology::kCellular));
  EXPECT_CALL(manager_, DeregisterDevice(_)).Times(1);
  EXPECT_CALL(metrics_, DeregisterDevice(kTestDeviceIndex)).Times(1);
  message = BuildLinkMessage(RTNLMessage::kModeDelete);
  SendMessageToDeviceInfo(*message);
}

TEST_F(DeviceInfoTest, GetUninitializedTechnologies) {
  std::vector<std::string> technologies =
      device_info_.GetUninitializedTechnologies();
  std::set<std::string> expected_technologies;

  EXPECT_THAT(std::set<std::string>(technologies.begin(), technologies.end()),
              ContainerEq(expected_technologies));

  device_info_.infos_[0].technology = Technology::kUnknown;
  EXPECT_THAT(std::set<std::string>(technologies.begin(), technologies.end()),
              ContainerEq(expected_technologies));

  device_info_.infos_[1].technology = Technology::kCellular;
  technologies = device_info_.GetUninitializedTechnologies();
  expected_technologies.insert(TechnologyName(Technology::kCellular));
  EXPECT_THAT(std::set<std::string>(technologies.begin(), technologies.end()),
              ContainerEq(expected_technologies));

  device_info_.infos_[2].technology = Technology::kWiFi;
  technologies = device_info_.GetUninitializedTechnologies();
  expected_technologies.insert(TechnologyName(Technology::kWiFi));
  EXPECT_THAT(std::set<std::string>(technologies.begin(), technologies.end()),
              ContainerEq(expected_technologies));

  scoped_refptr<MockDevice> device(
      new MockDevice(&manager_, "null0", "addr0", 1));
  device_info_.infos_[1].device = device;
  technologies = device_info_.GetUninitializedTechnologies();
  expected_technologies.erase(TechnologyName(Technology::kCellular));
  EXPECT_THAT(std::set<std::string>(technologies.begin(), technologies.end()),
              ContainerEq(expected_technologies));

  device_info_.infos_[3].technology = Technology::kCellular;
  technologies = device_info_.GetUninitializedTechnologies();
  EXPECT_THAT(std::set<std::string>(technologies.begin(), technologies.end()),
              ContainerEq(expected_technologies));

  device_info_.infos_[3].device = device;
  device_info_.infos_[1].device = nullptr;
  technologies = device_info_.GetUninitializedTechnologies();
  EXPECT_THAT(std::set<std::string>(technologies.begin(), technologies.end()),
              ContainerEq(expected_technologies));
}

TEST_F(DeviceInfoTest, GetByteCounts) {
  uint64_t rx_bytes, tx_bytes;
  EXPECT_FALSE(
      device_info_.GetByteCounts(kTestDeviceIndex, &rx_bytes, &tx_bytes));

  // No link statistics in the message.
  auto message = BuildLinkMessage(RTNLMessage::kModeAdd);
  SendMessageToDeviceInfo(*message);
  EXPECT_TRUE(
      device_info_.GetByteCounts(kTestDeviceIndex, &rx_bytes, &tx_bytes));
  EXPECT_EQ(0, rx_bytes);
  EXPECT_EQ(0, tx_bytes);

  // Short link statistics message.
  message = BuildLinkMessage(RTNLMessage::kModeAdd);
  struct old_rtnl_link_stats64 stats;
  memset(&stats, 0, sizeof(stats));
  stats.rx_bytes = kReceiveByteCount;
  stats.tx_bytes = kTransmitByteCount;
  ByteString stats_bytes0(reinterpret_cast<const unsigned char*>(&stats),
                          sizeof(stats) - 1);
  message->SetAttribute(IFLA_STATS64, stats_bytes0);
  SendMessageToDeviceInfo(*message);
  EXPECT_TRUE(
      device_info_.GetByteCounts(kTestDeviceIndex, &rx_bytes, &tx_bytes));
  EXPECT_EQ(0, rx_bytes);
  EXPECT_EQ(0, tx_bytes);

  // Correctly sized link statistics message.
  message = BuildLinkMessage(RTNLMessage::kModeAdd);
  ByteString stats_bytes1(reinterpret_cast<const unsigned char*>(&stats),
                          sizeof(stats));
  message->SetAttribute(IFLA_STATS64, stats_bytes1);
  SendMessageToDeviceInfo(*message);
  EXPECT_TRUE(
      device_info_.GetByteCounts(kTestDeviceIndex, &rx_bytes, &tx_bytes));
  EXPECT_EQ(kReceiveByteCount, rx_bytes);
  EXPECT_EQ(kTransmitByteCount, tx_bytes);
}

TEST_F(DeviceInfoTest, CreateDeviceCellular) {
  // A cellular device should be offered to ModemInfo.
  StrictMock<MockModemInfo> modem_info(nullptr, nullptr);
  EXPECT_CALL(manager_, modem_info()).WillOnce(Return(&modem_info));
  EXPECT_CALL(modem_info, OnDeviceInfoAvailable(kTestDeviceName)).Times(1);
  EXPECT_CALL(routing_table_, FlushRoutes(kTestDeviceIndex)).Times(1);
  EXPECT_FALSE(CreateDevice(kTestDeviceName, "address", kTestDeviceIndex,
                            Technology::kCellular));
}

TEST_F(DeviceInfoTest, CreateDeviceEthernet) {
  // An Ethernet device should cause routes and addresses to be flushed.
  EXPECT_CALL(routing_table_, FlushRoutes(kTestDeviceIndex)).Times(1);
  DeviceRefPtr device = CreateDevice(kTestDeviceName, "address",
                                     kTestDeviceIndex, Technology::kEthernet);
  EXPECT_NE(nullptr, device);
  Mock::VerifyAndClearExpectations(&routing_table_);
  Mock::VerifyAndClearExpectations(&rtnl_handler_);

  // The Ethernet device destructor should not call DeregisterService()
  // while being destructed, since the Manager may itself be partially
  // destructed at this time.
  EXPECT_CALL(manager_, DeregisterService(_)).Times(0);
  device = nullptr;
}

TEST_F(DeviceInfoTest, CreateDeviceVirtioEthernet) {
  // VirtioEthernet is identical to Ethernet from the perspective of this test.
  EXPECT_CALL(routing_table_, FlushRoutes(kTestDeviceIndex)).Times(1);
  DeviceRefPtr device =
      CreateDevice(kTestDeviceName, "address", kTestDeviceIndex,
                   Technology::kVirtioEthernet);
  EXPECT_NE(nullptr, device);
  Mock::VerifyAndClearExpectations(&routing_table_);
  Mock::VerifyAndClearExpectations(&rtnl_handler_);
}

MATCHER_P(IsGetInterfaceMessage, index, "") {
  if (arg->message_type() != Nl80211Message::GetMessageType()) {
    return false;
  }
  const Nl80211Message* msg = reinterpret_cast<const Nl80211Message*>(arg);
  if (msg->command() != NL80211_CMD_GET_INTERFACE) {
    return false;
  }
  uint32_t interface_index;
  if (!msg->const_attributes()->GetU32AttributeValue(NL80211_ATTR_IFINDEX,
                                                     &interface_index)) {
    return false;
  }
  // kInterfaceIndex is signed, but the attribute as handed from the kernel
  // is unsigned.  We're silently casting it away with this assignment.
  uint32_t test_interface_index = index;
  return interface_index == test_interface_index;
}

TEST_F(DeviceInfoTest, CreateDeviceWiFi) {
  // WiFi looks a lot like Ethernet too.
  EXPECT_CALL(routing_table_, FlushRoutes(kTestDeviceIndex));

  // Set the nl80211 message type to some non-default value.
  Nl80211Message::SetMessageType(1234);

  EXPECT_CALL(
      netlink_manager_,
      SendNl80211Message(IsGetInterfaceMessage(kTestDeviceIndex), _, _, _));
  EXPECT_FALSE(CreateDevice(kTestDeviceName, "address", kTestDeviceIndex,
                            Technology::kWiFi));
}

class MockLinkReadyListener {
 public:
  MOCK_METHOD(void, LinkReadyCallback, (const std::string&, int), ());

  DeviceInfo::LinkReadyCallback GetOnceCallback() {
    return base::BindOnce(&MockLinkReadyListener::LinkReadyCallback,
                          weak_factory_.GetWeakPtr());
  }

 private:
  base::WeakPtrFactory<MockLinkReadyListener> weak_factory_{this};
};

TEST_F(DeviceInfoTest, CreateDeviceTunnel) {
  EXPECT_CALL(routing_table_, FlushRoutes(kTestDeviceIndex)).Times(1);
  // Since the device was not expected, DeviceInfo will remove the interface.
  EXPECT_CALL(rtnl_handler_, RemoveInterface(kTestDeviceIndex)).Times(1);
  EXPECT_FALSE(CreateDevice(kTestDeviceName, "address", kTestDeviceIndex,
                            Technology::kTunnel));

  MockLinkReadyListener listener;
  device_info_.pending_links_.emplace(kTestDeviceName,
                                      listener.GetOnceCallback());
  EXPECT_CALL(listener, LinkReadyCallback(kTestDeviceName, kTestDeviceIndex))
      .Times(1);
  EXPECT_CALL(routing_table_, FlushRoutes(kTestDeviceIndex)).Times(1);
  EXPECT_CALL(rtnl_handler_, RemoveInterface(_)).Times(0);
  EXPECT_FALSE(CreateDevice(kTestDeviceName, "address", kTestDeviceIndex,
                            Technology::kTunnel));
}

TEST_F(DeviceInfoTest, CreateDevicePPP) {
  EXPECT_CALL(routing_table_, FlushRoutes(kTestDeviceIndex)).Times(1);
  // We do not remove PPP interfaces even if the provider does not accept it.
  EXPECT_CALL(rtnl_handler_, RemoveInterface(_)).Times(0);
  EXPECT_FALSE(CreateDevice(kTestDeviceName, "address", kTestDeviceIndex,
                            Technology::kPPP));
}

TEST_F(DeviceInfoTest, CreateDeviceLoopback) {
  // A loopback device should be brought up, and nothing else done to it.
  EXPECT_CALL(routing_table_, FlushRoutes(_)).Times(0);
  EXPECT_CALL(rtnl_handler_, RemoveInterfaceAddress(_, _)).Times(0);
  EXPECT_CALL(rtnl_handler_,
              SetInterfaceFlags(kTestDeviceIndex, IFF_UP, IFF_UP))
      .Times(1);
  EXPECT_FALSE(CreateDevice(kTestDeviceName, "address", kTestDeviceIndex,
                            Technology::kLoopback));
}

TEST_F(DeviceInfoTest, CreateDeviceCDCEthernet) {
  // A cdc_ether / cdc_ncm device should be postponed to a task.
  EXPECT_CALL(manager_, modem_info()).Times(0);
  EXPECT_CALL(routing_table_, FlushRoutes(_)).Times(0);
  EXPECT_CALL(rtnl_handler_, RemoveInterfaceAddress(_, _)).Times(0);
  EXPECT_TRUE(GetDelayedDevices().empty());
  EXPECT_FALSE(CreateDevice(kTestDeviceName, "address", kTestDeviceIndex,
                            Technology::kCDCEthernet));
  EXPECT_FALSE(GetDelayedDevices().empty());
  EXPECT_EQ(1, GetDelayedDevices().size());
  EXPECT_EQ(kTestDeviceIndex, *GetDelayedDevices().begin());
  EXPECT_EQ(1, dispatcher_.task_environment().GetPendingMainThreadTaskCount());
}

TEST_F(DeviceInfoTest, CreateDeviceUnknown) {
  // An unknown (blocked, unhandled, etc) device won't be flushed or
  // registered.
  EXPECT_CALL(routing_table_, FlushRoutes(_)).Times(0);
  EXPECT_CALL(rtnl_handler_, RemoveInterfaceAddress(_, _)).Times(0);
  EXPECT_TRUE(CreateDevice(kTestDeviceName, "address", kTestDeviceIndex,
                           Technology::kUnknown)
                  .get());
}

TEST_F(DeviceInfoTest, BlockedDevices) {
  // Manager is not running by default.
  EXPECT_CALL(rtnl_handler_, RequestDump(RTNLHandler::kRequestLink)).Times(0);
  device_info_.BlockDevice(kTestDeviceName);
  auto message = BuildLinkMessage(RTNLMessage::kModeAdd);
  SendMessageToDeviceInfo(*message);

  DeviceRefPtr device = device_info_.GetDevice(kTestDeviceIndex);
  ASSERT_NE(nullptr, device);
  EXPECT_TRUE(device->technology() == Technology::kBlocked);
}

TEST_F(DeviceInfoTest, BlockDeviceWithManagerRunning) {
  SetManagerRunning(true);
  EXPECT_CALL(rtnl_handler_, RequestDump(RTNLHandler::kRequestLink)).Times(1);
  device_info_.BlockDevice(kTestDeviceName);
  auto message = BuildLinkMessage(RTNLMessage::kModeAdd);
  SendMessageToDeviceInfo(*message);

  DeviceRefPtr device = device_info_.GetDevice(kTestDeviceIndex);
  ASSERT_NE(nullptr, device);
  EXPECT_TRUE(device->technology() == Technology::kBlocked);
}

TEST_F(DeviceInfoTest, RenamedBlockedDevice) {
  device_info_.BlockDevice(kTestDeviceName);
  auto message = BuildLinkMessage(RTNLMessage::kModeAdd);
  SendMessageToDeviceInfo(*message);

  DeviceRefPtr device = device_info_.GetDevice(kTestDeviceIndex);
  ASSERT_NE(nullptr, device);
  EXPECT_TRUE(device->technology() == Technology::kBlocked);

  // Rename the test device.
  const char kRenamedDeviceName[] = "renamed-device";
  auto rename_message = BuildLinkMessageWithInterfaceName(RTNLMessage::kModeAdd,
                                                          kRenamedDeviceName);
  EXPECT_CALL(manager_, DeregisterDevice(_));
  EXPECT_CALL(metrics_, DeregisterDevice(kTestDeviceIndex));
  SendMessageToDeviceInfo(*rename_message);

  DeviceRefPtr renamed_device = device_info_.GetDevice(kTestDeviceIndex);
  ASSERT_NE(nullptr, renamed_device);

  // Expect that a different device has been created.
  EXPECT_NE(device, renamed_device);

  // Since we didn't create a uevent file for kRenamedDeviceName, its
  // technology should be unknown.
  EXPECT_TRUE(renamed_device->technology() == Technology::kUnknown);
}

TEST_F(DeviceInfoTest, RenamedNonBlockedDevice) {
  const char kInitialDeviceName[] = "initial-device";
  auto initial_message = BuildLinkMessageWithInterfaceName(
      RTNLMessage::kModeAdd, kInitialDeviceName);
  SendMessageToDeviceInfo(*initial_message);
  auto message = BuildLinkMessage(RTNLMessage::kModeAdd);

  DeviceRefPtr initial_device = device_info_.GetDevice(kTestDeviceIndex);
  ASSERT_NE(nullptr, initial_device);

  // Since we didn't create a uevent file for kInitialDeviceName, its
  // technology should be unknown.
  EXPECT_TRUE(initial_device->technology() == Technology::kUnknown);

  // Rename the test device.
  const char kRenamedDeviceName[] = "renamed-device";
  device_info_.BlockDevice(kRenamedDeviceName);
  auto rename_message = BuildLinkMessageWithInterfaceName(RTNLMessage::kModeAdd,
                                                          kRenamedDeviceName);
  EXPECT_CALL(manager_, DeregisterDevice(_)).Times(0);
  EXPECT_CALL(metrics_, DeregisterDevice(kTestDeviceIndex)).Times(0);
  SendMessageToDeviceInfo(*rename_message);

  DeviceRefPtr renamed_device = device_info_.GetDevice(kTestDeviceIndex);
  ASSERT_NE(nullptr, renamed_device);

  // Expect that the the presence of a renamed device does not cause a new
  // Device entry to be created if the initial device was not blocked.
  EXPECT_EQ(initial_device, renamed_device);
  EXPECT_TRUE(initial_device->technology() == Technology::kUnknown);
}

TEST_F(DeviceInfoTest, HasSubdir) {
  base::ScopedTempDir temp_dir;
  EXPECT_TRUE(temp_dir.CreateUniqueTempDir());
  EXPECT_TRUE(base::CreateDirectory(temp_dir.GetPath().Append("child1")));
  base::FilePath child2 = temp_dir.GetPath().Append("child2");
  EXPECT_TRUE(base::CreateDirectory(child2));
  base::FilePath grandchild = child2.Append("grandchild");
  EXPECT_TRUE(base::CreateDirectory(grandchild));
  EXPECT_TRUE(base::CreateDirectory(grandchild.Append("greatgrandchild")));
  EXPECT_TRUE(
      DeviceInfo::HasSubdir(temp_dir.GetPath(), base::FilePath("grandchild")));
  EXPECT_TRUE(DeviceInfo::HasSubdir(temp_dir.GetPath(),
                                    base::FilePath("greatgrandchild")));
  EXPECT_FALSE(
      DeviceInfo::HasSubdir(temp_dir.GetPath(), base::FilePath("nonexistent")));
}

TEST_F(DeviceInfoTest, GetMacAddressFromKernelUnknownDevice) {
  SetSockets();
  EXPECT_CALL(*mock_sockets_, Socket(_, _, _)).Times(0);
  ByteString mac_address =
      device_info_.GetMacAddressFromKernel(kTestDeviceIndex);
  EXPECT_TRUE(mac_address.IsEmpty());
}

TEST_F(DeviceInfoTest, GetMacAddressFromKernelUnableToOpenSocket) {
  SetSockets();
  EXPECT_CALL(*mock_sockets_, Socket(PF_INET, _, 0)).WillOnce(Return(-1));
  auto message = BuildLinkMessage(RTNLMessage::kModeAdd);
  message->set_link_status(RTNLMessage::LinkStatus(0, IFF_LOWER_UP, 0));
  SendMessageToDeviceInfo(*message);
  EXPECT_NE(nullptr, device_info_.GetDevice(kTestDeviceIndex));
  ByteString mac_address =
      device_info_.GetMacAddressFromKernel(kTestDeviceIndex);
  EXPECT_TRUE(mac_address.IsEmpty());
}

TEST_F(DeviceInfoTest, GetMacAddressFromKernelIoctlFails) {
  SetSockets();
  const int kFd = 99;
  EXPECT_CALL(*mock_sockets_, Socket(PF_INET, _, 0)).WillOnce(Return(kFd));
  EXPECT_CALL(*mock_sockets_, Ioctl(kFd, SIOCGIFHWADDR, NotNull()))
      .WillOnce(Return(-1));
  EXPECT_CALL(*mock_sockets_, Close(kFd));

  auto message = BuildLinkMessage(RTNLMessage::kModeAdd);
  message->set_link_status(RTNLMessage::LinkStatus(0, IFF_LOWER_UP, 0));
  SendMessageToDeviceInfo(*message);
  EXPECT_NE(nullptr, device_info_.GetDevice(kTestDeviceIndex));

  ByteString mac_address =
      device_info_.GetMacAddressFromKernel(kTestDeviceIndex);
  EXPECT_TRUE(mac_address.IsEmpty());
}

MATCHER_P2(IfreqEquals, ifindex, ifname, "") {
  const struct ifreq* const ifr = static_cast<struct ifreq*>(arg);
  return (ifr != nullptr) && (ifr->ifr_ifindex == ifindex) &&
         (strcmp(ifname, ifr->ifr_name) == 0);
}

ACTION_P(SetIfreq, ifr) {
  struct ifreq* const ifr_arg = static_cast<struct ifreq*>(arg2);
  *ifr_arg = ifr;
}

TEST_F(DeviceInfoTest, GetMacAddressFromKernel) {
  SetSockets();
  const int kFd = 99;
  struct ifreq ifr;
  static uint8_t kMacAddress[] = {0x00, 0x01, 0x02, 0xaa, 0xbb, 0xcc};
  memcpy(ifr.ifr_hwaddr.sa_data, kMacAddress, sizeof(kMacAddress));
  EXPECT_CALL(*mock_sockets_, Socket(PF_INET, _, 0)).WillOnce(Return(kFd));
  EXPECT_CALL(
      *mock_sockets_,
      Ioctl(kFd, SIOCGIFHWADDR, IfreqEquals(kTestDeviceIndex, kTestDeviceName)))
      .WillOnce(DoAll(SetIfreq(ifr), Return(0)));
  EXPECT_CALL(*mock_sockets_, Close(kFd));

  auto message = BuildLinkMessage(RTNLMessage::kModeAdd);
  message->set_link_status(RTNLMessage::LinkStatus(0, IFF_LOWER_UP, 0));
  SendMessageToDeviceInfo(*message);
  EXPECT_NE(nullptr, device_info_.GetDevice(kTestDeviceIndex));

  ByteString mac_address =
      device_info_.GetMacAddressFromKernel(kTestDeviceIndex);
  EXPECT_THAT(kMacAddress,
              ElementsAreArray(mac_address.GetData(), sizeof(kMacAddress)));
}

MATCHER_P2(ArpreqEquals, ifname, peer, "") {
  const struct arpreq* const areq = static_cast<struct arpreq*>(arg);
  if (areq == nullptr) {
    return false;
  }

  const struct sockaddr_in* const protocol_address =
      reinterpret_cast<const struct sockaddr_in*>(&areq->arp_pa);
  const struct sockaddr_in* const mac_address =
      reinterpret_cast<const struct sockaddr_in*>(&areq->arp_ha);

  return strcmp(ifname, areq->arp_dev) == 0 &&
         protocol_address->sin_family == AF_INET &&
         memcmp(&protocol_address->sin_addr.s_addr,
                peer.address().GetConstData(),
                peer.address().GetLength()) == 0 &&
         mac_address->sin_family == ARPHRD_ETHER;
}

ACTION_P(SetArpreq, areq) {
  struct arpreq* const areq_arg = static_cast<struct arpreq*>(arg2);
  *areq_arg = areq;
}

TEST_F(DeviceInfoTest, OnNeighborReachabilityEvent) {
  device_info_.OnPatchpanelClientReady();

  scoped_refptr<MockDevice> device0(
      new MockDevice(&manager_, "null0", "addr0", kTestDeviceIndex));
  device_info_.RegisterDevice(device0);
  device0->set_network_for_testing(std::make_unique<Network>(
      kTestDeviceIndex, "null0", Technology::kEthernet,
      /*fixed_ip_params=*/false,
      /*control_interface=*/&control_interface_,
      /*dispatcher=*/&dispatcher_,
      /*metrics=*/&metrics_));
  MockNetworkEventHandler event_handler0;
  device0->GetPrimaryNetwork()->set_state_for_testing(
      Network::State::kConnected);
  device0->GetPrimaryNetwork()->RegisterEventHandler(&event_handler0);
  IPConfig::Properties props0 = {};
  props0.gateway = kTestIPAddress0;
  device0->GetPrimaryNetwork()->set_ipconfig(
      std::make_unique<IPConfig>(&control_interface_, "null0"));
  device0->GetPrimaryNetwork()->ipconfig()->UpdateProperties(props0);

  scoped_refptr<MockDevice> device1(
      new MockDevice(&manager_, "null1", "addr1", kTestDeviceIndex + 1));
  MockNetworkEventHandler event_handler1;
  device1->set_network_for_testing(std::make_unique<Network>(
      kTestDeviceIndex + 1, "null1", Technology::kWiFi,
      /*fixed_ip_params=*/false,
      /*control_interface=*/&control_interface_,
      /*dispatcher=*/&dispatcher_,
      /*metrics=*/&metrics_));
  device_info_.RegisterDevice(device1);
  device1->GetPrimaryNetwork()->set_state_for_testing(
      Network::State::kConnected);
  device1->GetPrimaryNetwork()->RegisterEventHandler(&event_handler1);
  IPConfig::Properties props1 = {};
  props1.gateway = kTestIPAddress2;
  device1->GetPrimaryNetwork()->set_ip6config(
      std::make_unique<IPConfig>(&control_interface_, "null1"));
  device1->GetPrimaryNetwork()->ip6config()->UpdateProperties(props1);

  using Role = patchpanel::Client::NeighborRole;
  using Status = patchpanel::Client::NeighborStatus;

  patchpanel::Client::NeighborReachabilityEvent event0;
  event0.ifindex = kTestDeviceIndex;
  event0.ip_addr = kTestIPAddress0;
  event0.role = Role::kGateway;
  event0.status = Status::kFailed;
  EXPECT_CALL(event_handler0,
              OnNeighborReachabilityEvent(
                  device0->GetPrimaryNetwork()->interface_index(),
                  *IPAddress::CreateFromString(kTestIPAddress0), Role::kGateway,
                  Status::kFailed));
  patchpanel_client_->TriggerNeighborReachabilityEvent(event0);
  Mock::VerifyAndClearExpectations(&event_handler0);

  patchpanel::Client::NeighborReachabilityEvent event1;
  event1.ifindex = kTestDeviceIndex;
  event1.ip_addr = kTestIPAddress1;
  event1.role = Role::kDnsServer;
  event1.status = Status::kFailed;
  EXPECT_CALL(event_handler0,
              OnNeighborReachabilityEvent(
                  device0->GetPrimaryNetwork()->interface_index(),
                  *IPAddress::CreateFromString(kTestIPAddress1),
                  Role::kDnsServer, Status::kFailed));
  patchpanel_client_->TriggerNeighborReachabilityEvent(event1);
  Mock::VerifyAndClearExpectations(&event_handler0);

  patchpanel::Client::NeighborReachabilityEvent event2;
  event2.ifindex = kTestDeviceIndex + 1;
  event2.ip_addr = kTestIPAddress2;
  event2.role = Role::kGatewayAndDnsServer;
  event2.status = Status::kReachable;
  EXPECT_CALL(event_handler1,
              OnNeighborReachabilityEvent(
                  device1->GetPrimaryNetwork()->interface_index(),
                  *IPAddress::CreateFromString(kTestIPAddress2),
                  Role::kGatewayAndDnsServer, Status::kReachable));
  patchpanel_client_->TriggerNeighborReachabilityEvent(event2);

  Mock::VerifyAndClearExpectations(&event_handler1);

  device0->GetPrimaryNetwork()->set_ipconfig(nullptr);
  device0->GetPrimaryNetwork()->UnregisterEventHandler(&event_handler0);
  device1->GetPrimaryNetwork()->set_ip6config(nullptr);
  device1->GetPrimaryNetwork()->UnregisterEventHandler(&event_handler1);
}

TEST_F(DeviceInfoTest, CreateWireGuardInterface) {
  const std::string kIfName = "wg0";
  const std::string kLinkKind = "wireguard";
  int link_ready_calls_num = 0;
  int on_failure_calls_num = 0;
  auto link_ready_cb = [&](const std::string&, int) { link_ready_calls_num++; };
  auto on_failure_cb = [&]() { on_failure_calls_num++; };

  RTNLHandler::ResponseCallback registered_response_cb;

  auto call_create_wireguard_interface = [&]() {
    return device_info_.CreateWireGuardInterface(
        kIfName, base::BindLambdaForTesting(link_ready_cb),
        base::BindLambdaForTesting(on_failure_cb));
  };

  // RTNLHandler::AddInterface() returns false directly.
  EXPECT_CALL(rtnl_handler_, AddInterface(kIfName, kLinkKind, _, _))
      .WillOnce(Return(false));
  EXPECT_FALSE(call_create_wireguard_interface());
  EXPECT_EQ(link_ready_calls_num, 0);
  EXPECT_EQ(on_failure_calls_num, 0);

  // RTNLHandler::AddInterface() returns true, but the kernel returns false.
  EXPECT_CALL(rtnl_handler_, AddInterface(kIfName, kLinkKind, _, _))
      .WillRepeatedly([&](const std::string& interface_name,
                          const std::string& link_kind, const ByteString&,
                          RTNLHandler::ResponseCallback response_callback) {
        registered_response_cb = std::move(response_callback);
        return true;
      });
  EXPECT_TRUE(call_create_wireguard_interface());
  std::move(registered_response_cb).Run(100);
  EXPECT_EQ(link_ready_calls_num, 0);
  EXPECT_EQ(on_failure_calls_num, 1);

  // RTNLHandler::AddInterface() returns true, and the kernel returns ack. No
  // callback to the client should be invoked now.
  EXPECT_TRUE(call_create_wireguard_interface());
  std::move(registered_response_cb).Run(0);
  EXPECT_EQ(link_ready_calls_num, 0);
  EXPECT_EQ(on_failure_calls_num, 1);

  // Link is ready.
  CreateDevice(kIfName, "192.168.1.1", 123, Technology::kTunnel);
  EXPECT_EQ(link_ready_calls_num, 1);
  EXPECT_EQ(on_failure_calls_num, 1);
}

TEST_F(DeviceInfoTest, CreateXFRMInterface) {
  const std::string kIfName = "xfrm0";
  const std::string kLinkKind = "xfrm";
  constexpr int kUnderlyingIfIndex = 5;
  constexpr int kIfId = 1;

  int link_ready_calls_num = 0;
  int on_failure_calls_num = 0;
  auto link_ready_cb = [&](const std::string&, int) { link_ready_calls_num++; };
  auto on_failure_cb = [&]() { on_failure_calls_num++; };

  ByteString actual_link_info_data;
  RTNLHandler::ResponseCallback registered_response_cb;

  auto call_create_xfrm_interface = [&]() {
    return device_info_.CreateXFRMInterface(
        kIfName, kUnderlyingIfIndex, kIfId,
        base::BindLambdaForTesting(link_ready_cb),
        base::BindLambdaForTesting(on_failure_cb));
  };

  // RTNLHandler::AddInterface() returns false directly.
  EXPECT_CALL(rtnl_handler_, AddInterface(kIfName, kLinkKind, _, _))
      .WillOnce(Return(false));
  EXPECT_FALSE(call_create_xfrm_interface());
  EXPECT_EQ(link_ready_calls_num, 0);
  EXPECT_EQ(on_failure_calls_num, 0);

  // RTNLHandler::AddInterface() returns true, but the kernel returns false.
  EXPECT_CALL(rtnl_handler_, AddInterface(kIfName, kLinkKind, _, _))
      .WillRepeatedly([&](const std::string& interface_name,
                          const std::string& link_kind,
                          const ByteString& link_info_data,
                          RTNLHandler::ResponseCallback response_callback) {
        actual_link_info_data = link_info_data;
        registered_response_cb = std::move(response_callback);
        return true;
      });
  EXPECT_TRUE(call_create_xfrm_interface());
  EXPECT_EQ(actual_link_info_data,
            RTNLMessage::PackAttrs(
                {{1, ByteString::CreateFromCPUUInt32(kUnderlyingIfIndex)},
                 {2, ByteString::CreateFromCPUUInt32(kIfId)}}));
  std::move(registered_response_cb).Run(100);
  EXPECT_EQ(link_ready_calls_num, 0);
  EXPECT_EQ(on_failure_calls_num, 1);

  // RTNLHandler::AddInterface() returns true, and the kernel returns ack. No
  // callback to the client should be invoked now.
  EXPECT_TRUE(call_create_xfrm_interface());
  std::move(registered_response_cb).Run(0);
  EXPECT_EQ(link_ready_calls_num, 0);
  EXPECT_EQ(on_failure_calls_num, 1);

  // Link is ready.
  CreateDevice(kIfName, "192.168.1.1", 123, Technology::kTunnel);
  EXPECT_EQ(link_ready_calls_num, 1);
  EXPECT_EQ(on_failure_calls_num, 1);
}

TEST_F(DeviceInfoTest, GetWiFiHardwareIds) {
  CreateWiFiDevice();

  CreateInfoFile("device/vendor", kVendorIdString);
  CreateInfoFile("device/device", kProductIdString);
  CreateInfoFile("device/subsystem_device", kSubsystemIdString);
  int vendor = kDefaultTestHardwareId;
  int product = kDefaultTestHardwareId;
  int subsystem = kDefaultTestHardwareId;
  EXPECT_TRUE(device_info_.GetWiFiHardwareIds(kTestDeviceIndex, &vendor,
                                              &product, &subsystem));
  EXPECT_EQ(vendor, kVendorId);
  EXPECT_EQ(product, kProductId);
  EXPECT_EQ(subsystem, kSubsystemId);
}

TEST_F(DeviceInfoTest, GetWiFiHardwareIdsNoDevice) {
  int vendor = kDefaultTestHardwareId;
  int product = kDefaultTestHardwareId;
  int subsystem = kDefaultTestHardwareId;
  EXPECT_FALSE(device_info_.GetWiFiHardwareIds(kTestDeviceIndex, &vendor,
                                               &product, &subsystem));
  // No device, all IDs left untouched.
  EXPECT_EQ(vendor, kDefaultTestHardwareId);
  EXPECT_EQ(product, kDefaultTestHardwareId);
  EXPECT_EQ(subsystem, kDefaultTestHardwareId);
}

TEST_F(DeviceInfoTest, GetWiFiHardwareIdsNotWiFi) {
  // Adapter is NOT a WiFi adapter, expect failure.
  CreateInfoFile("uevent", "DEVTYPE=NOTwlan");

  auto device = CreateDevice(kTestDeviceName, "address", kTestDeviceIndex,
                             Technology::kWiFi);
  if (device) {
    RegisterDevice(device);
  }
  auto message = BuildLinkMessage(RTNLMessage::kModeAdd);
  message->set_link_status(RTNLMessage::LinkStatus(0, IFF_LOWER_UP, 0));
  SendMessageToDeviceInfo(*message);

  int vendor = kDefaultTestHardwareId;
  int product = kDefaultTestHardwareId;
  int subsystem = kDefaultTestHardwareId;
  EXPECT_FALSE(device_info_.GetWiFiHardwareIds(kTestDeviceIndex, &vendor,
                                               &product, &subsystem));
  // Not a WiFi device, all IDs left untouched.
  EXPECT_EQ(vendor, kDefaultTestHardwareId);
  EXPECT_EQ(product, kDefaultTestHardwareId);
  EXPECT_EQ(subsystem, kDefaultTestHardwareId);
}

TEST_F(DeviceInfoTest, GetWiFiHardwareIdsNoVendor) {
  CreateWiFiDevice();

  // Vendor ID file is missing, expect failure.
  CreateInfoFile("device/device", kProductIdString);
  CreateInfoFile("device/subsystem_device", kSubsystemIdString);
  int vendor = kDefaultTestHardwareId;
  int product = kDefaultTestHardwareId;
  int subsystem = kDefaultTestHardwareId;
  EXPECT_FALSE(device_info_.GetWiFiHardwareIds(kTestDeviceIndex, &vendor,
                                               &product, &subsystem));
  // No vendor file, detection exits and will leave all IDs untouched.
  // This behavior will change once we add support for integrated chipsets.
  EXPECT_EQ(vendor, kDefaultTestHardwareId);
  EXPECT_EQ(product, kDefaultTestHardwareId);
  EXPECT_EQ(subsystem, kDefaultTestHardwareId);
}

TEST_F(DeviceInfoTest, GetWiFiHardwareIdsIntegrated) {
  CreateWiFiDevice();

  // Vendor ID file is missing, but the file for integrated chipsets is present
  // and valid.
  CreateInfoFile("device/uevent",
                 "TEST TEST \n OF_COMPATIBLE_0=qcom,wcn3990-wifi\n TEST TEST");
  int vendor = kDefaultTestHardwareId;
  int product = kDefaultTestHardwareId;
  int subsystem = kDefaultTestHardwareId;
  EXPECT_TRUE(device_info_.GetWiFiHardwareIds(kTestDeviceIndex, &vendor,
                                              &product, &subsystem));
  // Integrated chipsets are given the unassigned vendor ID 0x0000.
  EXPECT_EQ(vendor, Metrics::kWiFiIntegratedAdapterVendorId);
  // product and subsystem IDs for WCN3990.
  EXPECT_EQ(product, 3990);
  EXPECT_EQ(subsystem, 0);
}

TEST_F(DeviceInfoTest, GetWiFiHardwareIdsIntegratedInvalid) {
  CreateWiFiDevice();

  // Vendor ID file is missing, but the file for integrated chipsets is present.
  // However its format is invalid (missing "OF_COMPATIBLE_0=" prefix), expect
  // failure.
  CreateInfoFile("device/uevent", "qcom,wcn3990-wifi");
  int vendor = kDefaultTestHardwareId;
  int product = kDefaultTestHardwareId;
  int subsystem = kDefaultTestHardwareId;
  EXPECT_FALSE(device_info_.GetWiFiHardwareIds(kTestDeviceIndex, &vendor,
                                               &product, &subsystem));
  EXPECT_EQ(vendor, kDefaultTestHardwareId);
  EXPECT_EQ(product, kDefaultTestHardwareId);
  EXPECT_EQ(subsystem, kDefaultTestHardwareId);
}

TEST_F(DeviceInfoTest, GetWiFiHardwareIdsInvalidVendor) {
  CreateWiFiDevice();

  // Content of the vendor ID file is not a hexadecimal number, expect failure.
  CreateInfoFile("device/vendor", kInvalidIdString);
  CreateInfoFile("device/device", kProductIdString);
  CreateInfoFile("device/subsystem_device", kSubsystemIdString);
  int vendor = kDefaultTestHardwareId;
  int product = kDefaultTestHardwareId;
  int subsystem = kDefaultTestHardwareId;
  EXPECT_FALSE(device_info_.GetWiFiHardwareIds(kTestDeviceIndex, &vendor,
                                               &product, &subsystem));
  // Invalid vendor file, vendor ID left untouched.
  EXPECT_EQ(vendor, kDefaultTestHardwareId);
  EXPECT_EQ(product, kProductId);
  EXPECT_EQ(subsystem, kSubsystemId);
}

TEST_F(DeviceInfoTest, GetWiFiHardwareIdsNoProduct) {
  CreateWiFiDevice();

  CreateInfoFile("device/vendor", kVendorIdString);
  // Product ID file is missing, expect failure.
  CreateInfoFile("device/subsystem_device", kSubsystemIdString);
  int vendor = kDefaultTestHardwareId;
  int product = kDefaultTestHardwareId;
  int subsystem = kDefaultTestHardwareId;
  EXPECT_FALSE(device_info_.GetWiFiHardwareIds(kTestDeviceIndex, &vendor,
                                               &product, &subsystem));
  // No product file, product ID left untouched.
  EXPECT_EQ(vendor, kVendorId);
  EXPECT_EQ(product, kDefaultTestHardwareId);
  EXPECT_EQ(subsystem, kSubsystemId);
}

TEST_F(DeviceInfoTest, GetWiFiHardwareIdsInvalidProduct) {
  CreateWiFiDevice();

  CreateInfoFile("device/vendor", kVendorIdString);
  // Content of the product ID file is not a hexadecimal number, expect failure.
  CreateInfoFile("device/device", kInvalidIdString);
  CreateInfoFile("device/subsystem_device", kSubsystemIdString);
  int vendor = kDefaultTestHardwareId;
  int product = kDefaultTestHardwareId;
  int subsystem = kDefaultTestHardwareId;
  EXPECT_FALSE(device_info_.GetWiFiHardwareIds(kTestDeviceIndex, &vendor,
                                               &product, &subsystem));
  // Invalid product file, product ID left untouched.
  EXPECT_EQ(vendor, kVendorId);
  EXPECT_EQ(product, kDefaultTestHardwareId);
  EXPECT_EQ(subsystem, kSubsystemId);
}

TEST_F(DeviceInfoTest, GetWiFiHardwareIdsNoSubsystem) {
  CreateWiFiDevice();

  CreateInfoFile("device/vendor", kVendorIdString);
  CreateInfoFile("device/device", kProductIdString);
  int vendor = kDefaultTestHardwareId;
  int product = kDefaultTestHardwareId;
  int subsystem = kDefaultTestHardwareId;
  // Lack of subsystem is expected for SDIO adapters.
  EXPECT_TRUE(device_info_.GetWiFiHardwareIds(kTestDeviceIndex, &vendor,
                                              &product, &subsystem));
  EXPECT_EQ(vendor, kVendorId);
  EXPECT_EQ(product, kProductId);
  // SDIO adapters return subsystem ID 0.
  EXPECT_EQ(subsystem, 0);
}

TEST_F(DeviceInfoTest, GetWiFiHardwareIdsInvalidSubsystem) {
  CreateWiFiDevice();

  CreateInfoFile("device/vendor", kVendorIdString);
  CreateInfoFile("device/device", kProductIdString);
  // Content of the subsystem ID file is not a hexadecimal number,
  // expect failure.
  CreateInfoFile("device/subsystem_device", kInvalidIdString);
  int vendor = kDefaultTestHardwareId;
  int product = kDefaultTestHardwareId;
  int subsystem = kDefaultTestHardwareId;
  EXPECT_FALSE(device_info_.GetWiFiHardwareIds(kTestDeviceIndex, &vendor,
                                               &product, &subsystem));
  // Invalid subsystem file, subsystem ID left untouched.
  EXPECT_EQ(vendor, kVendorId);
  EXPECT_EQ(product, kProductId);
  EXPECT_EQ(subsystem, kDefaultTestHardwareId);
}

class DeviceInfoTechnologyTest : public DeviceInfoTest {
 public:
  DeviceInfoTechnologyTest() : DeviceInfoTest() {}
  ~DeviceInfoTechnologyTest() override = default;

  void SetUp() override {
    CreateSysfsRoot();
    // Most tests require that the uevent file exist.
    CreateInfoFile("uevent", "xxx");
  }

  Technology GetDeviceTechnology() {
    return device_info_.GetDeviceTechnology(test_device_name_, std::nullopt);
  }
  Technology GetDeviceTechnology(const std::string& kind) {
    return device_info_.GetDeviceTechnology(test_device_name_, kind);
  }

  void CreateInfoSymLink(const std::string& name, const std::string& contents);
  void SetDeviceName(const std::string& name) {
    test_device_name_ = name;
    EXPECT_TRUE(temp_dir_.Delete());  // nuke old temp dir
    SetUp();
  }
};

void DeviceInfoTechnologyTest::CreateInfoSymLink(const std::string& name,
                                                 const std::string& contents) {
  base::FilePath info_path = GetInfoPath(name);
  EXPECT_TRUE(base::CreateDirectory(info_path.DirName()));
  EXPECT_TRUE(base::CreateSymbolicLink(base::FilePath(contents), info_path));
}

TEST_F(DeviceInfoTechnologyTest, Unknown) {
  // With a uevent file but no driver symlink, we should get a pseudo-technology
  // which specifies this condition explicitly.
  EXPECT_EQ(Technology::kNoDeviceSymlink, GetDeviceTechnology());

  // Should be unknown without a uevent file.
  EXPECT_TRUE(base::DeleteFile(GetInfoPath("uevent")));
  EXPECT_EQ(Technology::kUnknown, GetDeviceTechnology());
}

TEST_F(DeviceInfoTechnologyTest, IgnoredVeth) {
  test_device_name_ = "veth0";
  // A new uevent file is needed since the device name has changed.
  CreateInfoFile("uevent", "xxx");
  // A device with a "veth" prefix should be ignored.
  EXPECT_EQ(Technology::kUnknown, GetDeviceTechnology("veth"));
}

TEST_F(DeviceInfoTechnologyTest, IgnoredArcMultinetBridgeDevice) {
  test_device_name_ = "arc_eth0";
  // A new uevent file is needed since the device name has changed.
  CreateInfoFile("uevent", "xxx");
  // A device with a "arc_" prefix should be ignored.
  EXPECT_EQ(Technology::kUnknown, GetDeviceTechnology("bridge"));
}

TEST_F(DeviceInfoTechnologyTest, Loopback) {
  CreateInfoFile("type", base::NumberToString(ARPHRD_LOOPBACK));
  EXPECT_EQ(Technology::kLoopback, GetDeviceTechnology());
}

// As long as it's not named 'veth*', we should detect it as Ethernet.
TEST_F(DeviceInfoTechnologyTest, Veth) {
  CreateInfoFile("uevent", "xxx");
  EXPECT_EQ(Technology::kEthernet, GetDeviceTechnology("veth"));
}

TEST_F(DeviceInfoTechnologyTest, PPP) {
  CreateInfoFile("type", base::NumberToString(ARPHRD_PPP));
  EXPECT_EQ(Technology::kPPP, GetDeviceTechnology());
}

TEST_F(DeviceInfoTechnologyTest, Tunnel) {
  CreateInfoFile("tun_flags", base::NumberToString(IFF_TUN));
  EXPECT_EQ(Technology::kTunnel, GetDeviceTechnology());
}

TEST_F(DeviceInfoTechnologyTest, WiFi) {
  CreateInfoFile("uevent", "DEVTYPE=wlan");
  EXPECT_EQ(Technology::kWiFi, GetDeviceTechnology());
  CreateInfoFile("uevent", "foo\nDEVTYPE=wlan");
  EXPECT_EQ(Technology::kWiFi, GetDeviceTechnology());
  CreateInfoFile("type", base::NumberToString(ARPHRD_IEEE80211_RADIOTAP));
  EXPECT_EQ(Technology::kWiFiMonitor, GetDeviceTechnology());
  // mac80211_hwsim creates ARPHRD_IEEE80211_RADIOTAP devices that don't list
  // DEVTYPE=wlan.
  CreateInfoFile("uevent", "INTERFACE=hwsim0");
  EXPECT_EQ(Technology::kWiFiMonitor, GetDeviceTechnology());
}

TEST_F(DeviceInfoTechnologyTest, Bridge) {
  CreateInfoFile("uevent", "DEVTYPE=bridge");
  EXPECT_EQ(Technology::kEthernet, GetDeviceTechnology("bridge"));
  CreateInfoFile("uevent", "bar\nDEVTYPE=bridge");
  EXPECT_EQ(Technology::kEthernet, GetDeviceTechnology("bridge"));
}

TEST_F(DeviceInfoTechnologyTest, Ifb) {
  test_device_name_ = "ifb0";
  CreateInfoFile("uevent", "INTERFACE=ifb0");
  EXPECT_EQ(Technology::kUnknown, GetDeviceTechnology("ifb"));
}

TEST_F(DeviceInfoTechnologyTest, RmnetData) {
  test_device_name_ = "rmnet_data0";
  EXPECT_EQ(Technology::kCellular, GetDeviceTechnology("rmnet"));
}

TEST_F(DeviceInfoTechnologyTest, RmnetIPA) {
  test_device_name_ = "rmnet_ipa0";
  CreateInfoFile("type", base::NumberToString(ARPHRD_RAWIP));
  EXPECT_EQ(Technology::kUnknown, GetDeviceTechnology());
}

TEST_F(DeviceInfoTechnologyTest, Ethernet) {
  CreateInfoSymLink("device/driver", "xxx");
  EXPECT_EQ(Technology::kEthernet, GetDeviceTechnology());
}

TEST_F(DeviceInfoTechnologyTest, CellularCdcMbim) {
  CreateInfoSymLink("device/driver", "cdc_mbim");
  EXPECT_EQ(Technology::kCellular, GetDeviceTechnology());
}

// Test path to the driver of an FM350 device. This is temporary coverage until
// the mtkt7xx driver exposes the driver symlink at the same "device/driver"
// endpoint as expected (b/225373673)
TEST_F(DeviceInfoTechnologyTest, CellularMtkt7xx) {
  CreateInfoSymLink("device/device/driver", "mtk_t7xx");
  EXPECT_EQ(Technology::kCellular, GetDeviceTechnology());
}

TEST_F(DeviceInfoTechnologyTest, CellularQmiWwan) {
  CreateInfoSymLink("device/driver", "qmi_wwan");
  EXPECT_EQ(Technology::kCellular, GetDeviceTechnology());
}

// Modem with absolute driver path with top-level tty file:
//   /sys/class/net/dev0/device -> /sys/devices/virtual/0/00
//   /sys/devices/virtual/0/00/driver -> /drivers/cdc_ether or /drivers/cdc_ncm
//   /sys/devices/virtual/0/01/tty [empty directory]
TEST_F(DeviceInfoTechnologyTest, CDCEthernetModem1) {
  base::FilePath device_root(
      temp_dir_.GetPath().Append("sys/devices/virtual/0"));
  base::FilePath device_path(device_root.Append("00"));
  base::FilePath driver_symlink(device_path.Append("driver"));
  EXPECT_TRUE(base::CreateDirectory(device_path));
  CreateInfoSymLink("device", device_path.value());
  EXPECT_TRUE(base::CreateSymbolicLink(base::FilePath("/drivers/cdc_ether"),
                                       driver_symlink));
  EXPECT_TRUE(base::CreateDirectory(device_root.Append("01/tty")));
  EXPECT_EQ(Technology::kCellular, GetDeviceTechnology());

  EXPECT_TRUE(base::DeleteFile(driver_symlink));
  EXPECT_TRUE(base::CreateSymbolicLink(base::FilePath("/drivers/cdc_ncm"),
                                       driver_symlink));
  EXPECT_EQ(Technology::kCellular, GetDeviceTechnology());
}

// Modem with relative driver path with top-level tty file.
//   /sys/class/net/dev0/device -> ../../../device_dir/0/00
//   /sys/device_dir/0/00/driver -> /drivers/cdc_ether or /drivers/cdc_ncm
//   /sys/device_dir/0/01/tty [empty directory]
TEST_F(DeviceInfoTechnologyTest, CDCEthernetModem2) {
  CreateInfoSymLink("device", "../../../device_dir/0/00");
  base::FilePath device_root(temp_dir_.GetPath().Append("sys/device_dir/0"));
  base::FilePath device_path(device_root.Append("00"));
  base::FilePath driver_symlink(device_path.Append("driver"));
  EXPECT_TRUE(base::CreateDirectory(device_path));
  EXPECT_TRUE(base::CreateSymbolicLink(base::FilePath("/drivers/cdc_ether"),
                                       driver_symlink));
  EXPECT_TRUE(base::CreateDirectory(device_root.Append("01/tty")));
  EXPECT_EQ(Technology::kCellular, GetDeviceTechnology());

  EXPECT_TRUE(base::DeleteFile(driver_symlink));
  EXPECT_TRUE(base::CreateSymbolicLink(base::FilePath("/drivers/cdc_ncm"),
                                       driver_symlink));
  EXPECT_EQ(Technology::kCellular, GetDeviceTechnology());
}

// Modem with relative driver path with lower-level tty file.
//   /sys/class/net/dev0/device -> ../../../device_dir/0/00
//   /sys/device_dir/0/00/driver -> /drivers/cdc_ether or /drivers/cdc_ncm
//   /sys/device_dir/0/01/yyy/tty [empty directory]
TEST_F(DeviceInfoTechnologyTest, CDCEthernetModem3) {
  CreateInfoSymLink("device", "../../../device_dir/0/00");
  base::FilePath device_root(temp_dir_.GetPath().Append("sys/device_dir/0"));
  base::FilePath device_path(device_root.Append("00"));
  base::FilePath driver_symlink(device_path.Append("driver"));
  EXPECT_TRUE(base::CreateDirectory(device_path));
  EXPECT_TRUE(base::CreateSymbolicLink(base::FilePath("/drivers/cdc_ether"),
                                       driver_symlink));
  EXPECT_TRUE(base::CreateDirectory(device_root.Append("01/yyy/tty")));
  EXPECT_EQ(Technology::kCellular, GetDeviceTechnology());

  EXPECT_TRUE(base::DeleteFile(driver_symlink));
  EXPECT_TRUE(base::CreateSymbolicLink(base::FilePath("/drivers/cdc_ncm"),
                                       driver_symlink));
  EXPECT_EQ(Technology::kCellular, GetDeviceTechnology());
}

TEST_F(DeviceInfoTechnologyTest, CDCEtherNonModem) {
  CreateInfoSymLink("device", "device_dir");
  CreateInfoSymLink("device_dir/driver", "cdc_ether");
  EXPECT_EQ(Technology::kCDCEthernet, GetDeviceTechnology());
}

TEST_F(DeviceInfoTechnologyTest, CDCNcmNonModem) {
  CreateInfoSymLink("device", "device_dir");
  CreateInfoSymLink("device_dir/driver", "cdc_ncm");
  EXPECT_EQ(Technology::kCDCEthernet, GetDeviceTechnology());
}

TEST_F(DeviceInfoTechnologyTest, PseudoModem) {
  SetDeviceName("pseudomodem");
  EXPECT_EQ(Technology::kCellular, GetDeviceTechnology("veth"));

  SetDeviceName("pseudomodem9");
  EXPECT_EQ(Technology::kCellular, GetDeviceTechnology("veth"));
}

class DeviceInfoForDelayedCreationTest : public DeviceInfo {
 public:
  explicit DeviceInfoForDelayedCreationTest(Manager* manager)
      : DeviceInfo(manager) {}
  MOCK_METHOD(DeviceRefPtr,
              CreateDevice,
              (const std::string&, const std::string&, int, Technology),
              (override));
  MOCK_METHOD(Technology,
              GetDeviceTechnology,
              (const std::string&, const std::optional<std::string>& kind),
              (const, override));
};

class DeviceInfoDelayedCreationTest : public DeviceInfoTest {
 public:
  DeviceInfoDelayedCreationTest() : test_device_info_(&manager_) {}
  ~DeviceInfoDelayedCreationTest() override = default;

  std::set<int>& GetDelayedDevices() override {
    return test_device_info_.delayed_devices_;
  }

  void DelayedDeviceCreationTask() {
    test_device_info_.DelayedDeviceCreationTask();
  }

  void AddDelayedDevice(Technology delayed_technology) {
    auto message = BuildLinkMessage(RTNLMessage::kModeAdd);
    EXPECT_CALL(test_device_info_, GetDeviceTechnology(kTestDeviceName, _))
        .WillOnce(Return(delayed_technology));
    EXPECT_CALL(
        test_device_info_,
        CreateDevice(kTestDeviceName, _, kTestDeviceIndex, delayed_technology))
        .WillOnce(Return(DeviceRefPtr()));
    test_device_info_.AddLinkMsgHandler(*message);
    Mock::VerifyAndClearExpectations(&test_device_info_);
    // We need to insert the device index ourselves since we have mocked
    // out CreateDevice.  This insertion is tested in CreateDeviceCDCEthernet
    // above.
    GetDelayedDevices().insert(kTestDeviceIndex);
  }

  void AddDeviceWithNoIFLAAddress(Technology delayed_technology) {
    auto message = std::make_unique<RTNLMessage>(
        RTNLMessage::kTypeLink, RTNLMessage::kModeAdd, 0, 0, 0,
        kTestDeviceIndex, IPAddress::kFamilyIPv4);
    message->SetAttribute(static_cast<uint16_t>(IFLA_IFNAME),
                          ByteString(std::string(kTestDeviceName),
                                     /*copy_terminator=*/true));

    EXPECT_CALL(test_device_info_, GetDeviceTechnology(kTestDeviceName, _))
        .WillOnce(Return(delayed_technology));
    // When message does not have IFLA_ADDRESS and technology is either WiFi
    // or Ethernet, the AddLinkMsgHandler function does not create device
    EXPECT_CALL(test_device_info_, CreateDevice(_, _, _, _)).Times(0);
    test_device_info_.AddLinkMsgHandler(*message);
  }

  void EnsureDelayedDevice(Technology reported_device_technology,
                           Technology created_device_technology) {
    EXPECT_CALL(test_device_info_, GetDeviceTechnology(_, _))
        .WillOnce(Return(reported_device_technology));
    EXPECT_CALL(test_device_info_,
                CreateDevice(kTestDeviceName, _, kTestDeviceIndex,
                             created_device_technology))
        .WillOnce(Return(DeviceRefPtr()));
    DelayedDeviceCreationTask();
    EXPECT_TRUE(GetDelayedDevices().empty());
  }

  void EnsureNoDelayedDevice() { EXPECT_TRUE(GetDelayedDevices().empty()); }

  void TriggerOnWiFiInterfaceInfoReceived(const Nl80211Message& message) {
    test_device_info_.OnWiFiInterfaceInfoReceived(message);
  }

 protected:
  DeviceInfoForDelayedCreationTest test_device_info_;
};

TEST_F(DeviceInfoDelayedCreationTest, NoDevices) {
  EXPECT_TRUE(GetDelayedDevices().empty());
  EXPECT_CALL(test_device_info_, GetDeviceTechnology(_, _)).Times(0);
  DelayedDeviceCreationTask();
}

TEST_F(DeviceInfoDelayedCreationTest, CDCEthernetDevice) {
  AddDelayedDevice(Technology::kCDCEthernet);
  EnsureDelayedDevice(Technology::kCDCEthernet, Technology::kEthernet);
}

TEST_F(DeviceInfoDelayedCreationTest, CellularDevice) {
  AddDelayedDevice(Technology::kCDCEthernet);
  EnsureDelayedDevice(Technology::kCellular, Technology::kCellular);
}

TEST_F(DeviceInfoDelayedCreationTest, TunnelDevice) {
  AddDelayedDevice(Technology::kNoDeviceSymlink);
  EnsureDelayedDevice(Technology::kTunnel, Technology::kTunnel);
}

TEST_F(DeviceInfoDelayedCreationTest, NoDeviceSymlinkEthernet) {
  AddDelayedDevice(Technology::kNoDeviceSymlink);
  EXPECT_CALL(manager_, ignore_unknown_ethernet()).WillOnce(Return(false));
  EnsureDelayedDevice(Technology::kNoDeviceSymlink, Technology::kEthernet);
}

TEST_F(DeviceInfoDelayedCreationTest, NoDeviceSymlinkIgnored) {
  AddDelayedDevice(Technology::kNoDeviceSymlink);
  EXPECT_CALL(manager_, ignore_unknown_ethernet()).WillOnce(Return(true));
  EnsureDelayedDevice(Technology::kNoDeviceSymlink, Technology::kUnknown);
}

TEST_F(DeviceInfoDelayedCreationTest, GuestInterface) {
  AddDelayedDevice(Technology::kNoDeviceSymlink);
  EnsureDelayedDevice(Technology::kGuestInterface, Technology::kGuestInterface);
}

TEST_F(DeviceInfoDelayedCreationTest, WiFiInterface) {
  AddDeviceWithNoIFLAAddress(Technology::kWiFi);
  EnsureNoDelayedDevice();
}

TEST_F(DeviceInfoDelayedCreationTest, EthernetInterface) {
  AddDeviceWithNoIFLAAddress(Technology::kEthernet);
  EnsureNoDelayedDevice();
}

TEST_F(DeviceInfoDelayedCreationTest, WiFiDevice) {
  ScopedMockLog log;
  EXPECT_CALL(log, Log(logging::LOGGING_ERROR, _,
                       HasSubstr("Message is not a new interface response")));
  GetInterfaceMessage non_interface_response_message;
  TriggerOnWiFiInterfaceInfoReceived(non_interface_response_message);
  Mock::VerifyAndClearExpectations(&log);

  EXPECT_CALL(log, Log(logging::LOGGING_ERROR, _,
                       HasSubstr("Message contains no interface index")));
  NewInterfaceMessage message;
  TriggerOnWiFiInterfaceInfoReceived(message);
  Mock::VerifyAndClearExpectations(&log);

  message.attributes()->CreateNl80211Attribute(
      NL80211_ATTR_IFINDEX, NetlinkMessage::MessageContext());
  message.attributes()->SetU32AttributeValue(NL80211_ATTR_IFINDEX,
                                             kTestDeviceIndex);
  EXPECT_CALL(log, Log(logging::LOGGING_ERROR, _,
                       HasSubstr("Message contains no interface type")));
  TriggerOnWiFiInterfaceInfoReceived(message);
  Mock::VerifyAndClearExpectations(&log);

  message.attributes()->CreateNl80211Attribute(
      NL80211_ATTR_IFTYPE, NetlinkMessage::MessageContext());
  message.attributes()->SetU32AttributeValue(NL80211_ATTR_IFTYPE,
                                             NL80211_IFTYPE_AP);
  EXPECT_CALL(log, Log(logging::LOGGING_ERROR, _,
                       HasSubstr("Message contains no phy index")));
  TriggerOnWiFiInterfaceInfoReceived(message);
  Mock::VerifyAndClearExpectations(&log);

  message.attributes()->CreateNl80211Attribute(
      NL80211_ATTR_WIPHY, NetlinkMessage::MessageContext());
  message.attributes()->SetU32AttributeValue(NL80211_ATTR_WIPHY, 0);
  EXPECT_CALL(log, Log(logging::LOGGING_ERROR, _,
                       HasSubstr("Could not find device info for interface")));
  TriggerOnWiFiInterfaceInfoReceived(message);
  Mock::VerifyAndClearExpectations(&log);

  // Use the AddDelayedDevice() method to create a device info entry with no
  // associated device.
  AddDelayedDevice(Technology::kNoDeviceSymlink);

  EXPECT_CALL(log, Log(logging::LOGGING_INFO, _,
                       HasSubstr("it is not in station mode")));
  TriggerOnWiFiInterfaceInfoReceived(message);
  Mock::VerifyAndClearExpectations(&log);
  Mock::VerifyAndClearExpectations(&manager_);
  message.attributes()->SetU32AttributeValue(NL80211_ATTR_IFTYPE,
                                             NL80211_IFTYPE_STATION);
  EXPECT_CALL(manager_, RegisterDevice(_));
  EXPECT_CALL(manager_, device_info())
      .WillRepeatedly(Return(&test_device_info_));
  EXPECT_CALL(log, Log(_, _, _)).Times(AnyNumber());
  EXPECT_CALL(log,
              Log(logging::LOGGING_INFO, _, HasSubstr("Creating WiFi device")));
  TriggerOnWiFiInterfaceInfoReceived(message);
  Mock::VerifyAndClearExpectations(&log);
  Mock::VerifyAndClearExpectations(&manager_);

  EXPECT_CALL(manager_, RegisterDevice(_)).Times(0);
  EXPECT_CALL(log, Log(logging::LOGGING_ERROR, _,
                       HasSubstr("Device already created for interface")));
  TriggerOnWiFiInterfaceInfoReceived(message);
}

}  // namespace shill
