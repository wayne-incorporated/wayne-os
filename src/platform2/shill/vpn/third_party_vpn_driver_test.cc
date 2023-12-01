// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/vpn/third_party_vpn_driver.h"

#include <utility>

#include <base/functional/bind.h>
#include <base/memory/ptr_util.h>
#include <gtest/gtest.h>

#include "shill/callbacks.h"
#include "shill/mock_adaptors.h"
#include "shill/mock_control.h"
#include "shill/mock_device_info.h"
#include "shill/mock_file_io.h"
#include "shill/mock_manager.h"
#include "shill/mock_metrics.h"
#include "shill/mock_virtual_device.h"
#include "shill/net/mock_io_handler_factory.h"
#include "shill/test_event_dispatcher.h"
#include "shill/vpn/mock_vpn_driver.h"
#include "shill/vpn/mock_vpn_provider.h"
#include "shill/vpn/vpn_provider.h"

using testing::_;
using testing::Mock;
using testing::NiceMock;
using testing::Return;
using testing::SetArgPointee;

namespace shill {

class ThirdPartyVpnDriverTest : public testing::Test {
 public:
  ThirdPartyVpnDriverTest()
      : manager_(&control_, &dispatcher_, &metrics_),
        device_info_(&manager_),
        driver_(new ThirdPartyVpnDriver(&manager_, nullptr)),
        adaptor_interface_(new ThirdPartyVpnMockAdaptor()) {
    manager_.set_mock_device_info(&device_info_);
    driver_->io_handler_factory_ = &io_handler_factory_;
  }

  ~ThirdPartyVpnDriverTest() override = default;

  void SetUp() override {
    driver_->adaptor_interface_.reset(adaptor_interface_);
    driver_->file_io_ = &mock_file_io_;
  }

  void TearDown() override { driver_->file_io_ = nullptr; }

  MOCK_METHOD(void, TestCallback, (const Error&));

 protected:
  static const char kConfigName[];
  static const char kInterfaceName[];
  static const int kInterfaceIndex;

  MockControl control_;
  EventDispatcherForTest dispatcher_;
  MockMetrics metrics_;
  MockFileIO mock_file_io_;
  MockManager manager_;
  NiceMock<MockDeviceInfo> device_info_;
  MockIOHandlerFactory io_handler_factory_;
  MockVPNDriverEventHandler event_handler_;
  std::unique_ptr<ThirdPartyVpnDriver> driver_;
  ThirdPartyVpnMockAdaptor* adaptor_interface_;  // Owned by |driver_|
};

const char ThirdPartyVpnDriverTest::kConfigName[] = "default-1";
const char ThirdPartyVpnDriverTest::kInterfaceName[] = "tun0";
const int ThirdPartyVpnDriverTest::kInterfaceIndex = 123;

TEST_F(ThirdPartyVpnDriverTest, VPNType) {
  EXPECT_EQ(driver_->vpn_type(), VPNType::kThirdParty);
}

TEST_F(ThirdPartyVpnDriverTest, ConnectAndDisconnect) {
  const std::string interface = kInterfaceName;
  IOHandler* io_handler = new IOHandler();  // Owned by |driver_|
  int fd = 1;

  DeviceInfo::LinkReadyCallback link_ready_callback;
  EXPECT_CALL(device_info_, CreateTunnelInterface(_))
      .WillOnce([&link_ready_callback](DeviceInfo::LinkReadyCallback callback) {
        link_ready_callback = std::move(callback);
        return true;
      });
  driver_->ConnectAsync(&event_handler_);

  EXPECT_CALL(device_info_, OpenTunnelInterface(interface))
      .WillOnce(Return(fd));
  EXPECT_CALL(io_handler_factory_, CreateIOInputHandler(fd, _, _))
      .WillOnce(Return(io_handler));
  EXPECT_CALL(*adaptor_interface_, EmitPlatformMessage(static_cast<uint32_t>(
                                       ThirdPartyVpnDriver::kConnected)));
  std::move(link_ready_callback).Run(kInterfaceName, kInterfaceIndex);
  EXPECT_EQ(driver_->active_client_, driver_.get());
  EXPECT_TRUE(driver_->parameters_expected_);
  EXPECT_EQ(driver_->io_handler_.get(), io_handler);

  EXPECT_CALL(*adaptor_interface_, EmitPlatformMessage(static_cast<uint32_t>(
                                       ThirdPartyVpnDriver::kDisconnected)));
  EXPECT_CALL(mock_file_io_, Close(fd));
  driver_->Disconnect();
  EXPECT_FALSE(driver_->event_handler_);
  EXPECT_EQ(nullptr, driver_->io_handler_);
}

TEST_F(ThirdPartyVpnDriverTest, ReconnectionEvents) {
  const std::string interface = kInterfaceName;
  IOHandler* io_handler = new IOHandler();  // Owned by |driver_|
  int fd = 1;

  EXPECT_CALL(device_info_, OpenTunnelInterface(interface))
      .WillOnce(Return(fd));
  EXPECT_CALL(io_handler_factory_, CreateIOInputHandler(fd, _, _))
      .WillOnce(Return(io_handler));
  EXPECT_CALL(device_info_, CreateTunnelInterface(_)).WillOnce(Return(true));
  driver_->ConnectAsync(&event_handler_);
  driver_->OnLinkReady(kInterfaceName, kInterfaceIndex);

  driver_->reconnect_supported_ = true;

  // Roam from one Online network to another -> kLinkChanged.
  EXPECT_CALL(*adaptor_interface_, EmitPlatformMessage(static_cast<uint32_t>(
                                       ThirdPartyVpnDriver::kLinkChanged)));
  driver_->OnDefaultPhysicalServiceEvent(
      VPNDriver::kDefaultPhysicalServiceChanged);

  // Default physical service is not Online -> kLinkDown.
  EXPECT_CALL(*adaptor_interface_, EmitPlatformMessage(static_cast<uint32_t>(
                                       ThirdPartyVpnDriver::kLinkDown)));
  driver_->OnDefaultPhysicalServiceEvent(
      VPNDriver::kDefaultPhysicalServiceDown);

  // Default physical service comes Online -> kLinkUp.
  EXPECT_CALL(
      *adaptor_interface_,
      EmitPlatformMessage(static_cast<uint32_t>(ThirdPartyVpnDriver::kLinkUp)));
  driver_->OnDefaultPhysicalServiceEvent(VPNDriver::kDefaultPhysicalServiceUp);

  // Default physical service vanishes, but the app doesn't support
  // reconnecting -> kDisconnected.
  driver_->reconnect_supported_ = false;
  EXPECT_CALL(*adaptor_interface_, EmitPlatformMessage(static_cast<uint32_t>(
                                       ThirdPartyVpnDriver::kDisconnected)));
  driver_->OnDefaultPhysicalServiceEvent(
      VPNDriver::kDefaultPhysicalServiceDown);

  driver_->Disconnect();
}

TEST_F(ThirdPartyVpnDriverTest, PowerEvents) {
  const std::string interface = kInterfaceName;
  IOHandler* io_handler = new IOHandler();  // Owned by |driver_|
  int fd = 1;

  EXPECT_CALL(device_info_, OpenTunnelInterface(interface))
      .WillOnce(Return(fd));
  EXPECT_CALL(io_handler_factory_, CreateIOInputHandler(fd, _, _))
      .WillOnce(Return(io_handler));
  EXPECT_CALL(device_info_, CreateTunnelInterface(_)).WillOnce(Return(true));
  driver_->ConnectAsync(&event_handler_);
  driver_->OnLinkReady(kInterfaceName, kInterfaceIndex);

  driver_->reconnect_supported_ = true;

  ResultCallback callback = base::BindOnce(
      &ThirdPartyVpnDriverTest::TestCallback, base::Unretained(this));
  EXPECT_CALL(*adaptor_interface_, EmitPlatformMessage(static_cast<uint32_t>(
                                       ThirdPartyVpnDriver::kSuspend)));
  EXPECT_CALL(*this, TestCallback(_));
  driver_->OnBeforeSuspend(std::move(callback));

  EXPECT_CALL(
      *adaptor_interface_,
      EmitPlatformMessage(static_cast<uint32_t>(ThirdPartyVpnDriver::kResume)));
  driver_->OnAfterResume();

  EXPECT_CALL(*adaptor_interface_, EmitPlatformMessage(static_cast<uint32_t>(
                                       ThirdPartyVpnDriver::kDisconnected)));
  driver_->Disconnect();
}

TEST_F(ThirdPartyVpnDriverTest, OnConnectTimeout) {
  EXPECT_CALL(device_info_, CreateTunnelInterface(_)).WillOnce(Return(true));
  driver_->ConnectAsync(&event_handler_);

  EXPECT_CALL(event_handler_, OnDriverFailure(_, _));
  driver_->OnConnectTimeout();
  EXPECT_FALSE(driver_->event_handler_);
}

TEST_F(ThirdPartyVpnDriverTest, SendPacket) {
  int fd = 1;
  std::string error;
  std::vector<uint8_t> ip_packet(5, 0);
  driver_->SendPacket(ip_packet, &error);
  EXPECT_EQ(error, "Unexpected call");

  error.clear();
  ThirdPartyVpnDriver::active_client_ = driver_.get();
  driver_->SendPacket(ip_packet, &error);
  EXPECT_EQ(error, "Device not open");

  driver_->tun_fd_ = fd;
  error.clear();
  EXPECT_CALL(mock_file_io_, Write(fd, ip_packet.data(), ip_packet.size()))
      .WillOnce(Return(ip_packet.size() - 1));
  EXPECT_CALL(
      *adaptor_interface_,
      EmitPlatformMessage(static_cast<uint32_t>(ThirdPartyVpnDriver::kError)));
  driver_->SendPacket(ip_packet, &error);
  EXPECT_EQ(error, "Partial write");

  error.clear();
  EXPECT_CALL(mock_file_io_, Write(fd, ip_packet.data(), ip_packet.size()))
      .WillOnce(Return(ip_packet.size()));
  driver_->SendPacket(ip_packet, &error);
  EXPECT_TRUE(error.empty());

  driver_->tun_fd_ = -1;

  EXPECT_CALL(*adaptor_interface_, EmitPlatformMessage(static_cast<uint32_t>(
                                       ThirdPartyVpnDriver::kDisconnected)));
}

TEST_F(ThirdPartyVpnDriverTest, UpdateConnectionState) {
  std::string error;
  driver_->UpdateConnectionState(Service::kStateConfiguring, &error);
  EXPECT_EQ(error, "Unexpected call");

  error.clear();
  ThirdPartyVpnDriver::active_client_ = driver_.get();
  driver_->UpdateConnectionState(Service::kStateConfiguring, &error);
  EXPECT_EQ(error, "Invalid argument");

  error.clear();
  driver_->event_handler_ = &event_handler_;
  EXPECT_CALL(event_handler_, OnDriverFailure(_, _)).Times(0);
  driver_->UpdateConnectionState(Service::kStateOnline, &error);
  EXPECT_TRUE(error.empty());
  Mock::VerifyAndClearExpectations(&event_handler_);

  EXPECT_CALL(event_handler_, OnDriverFailure(_, _)).Times(1);
  EXPECT_CALL(*adaptor_interface_, EmitPlatformMessage(static_cast<uint32_t>(
                                       ThirdPartyVpnDriver::kDisconnected)))
      .Times(1);
  driver_->UpdateConnectionState(Service::kStateFailure, &error);
  EXPECT_TRUE(error.empty());
  Mock::VerifyAndClearExpectations(&event_handler_);
  Mock::VerifyAndClearExpectations(adaptor_interface_);
}

TEST_F(ThirdPartyVpnDriverTest, SetParameters) {
  manager_.vpn_provider_ = std::make_unique<MockVPNProvider>();
  manager_.vpn_provider_->manager_ = &manager_;
  manager_.UpdateProviderMapping();

  std::map<std::string, std::string> parameters;
  std::string error;
  std::string warning;
  driver_->SetParameters(parameters, &error, &warning);
  EXPECT_EQ(error, "Unexpected call");

  error.clear();
  ThirdPartyVpnDriver::active_client_ = driver_.get();
  driver_->parameters_expected_ = true;
  driver_->SetParameters(parameters, &error, &warning);
  EXPECT_EQ(error,
            "address is missing;subnet_prefix is missing;"
            "exclusion_list is missing;inclusion_list is missing;");
  EXPECT_TRUE(warning.empty());

  error.clear();
  parameters["address"] = "1234.1.1.1";
  driver_->SetParameters(parameters, &error, &warning);
  EXPECT_EQ(error,
            "address is not a valid IP;subnet_prefix is missing;"
            "exclusion_list is missing;inclusion_list is missing;");
  EXPECT_TRUE(warning.empty());

  error.clear();
  parameters["address"] = "123.211.21.18";
  driver_->SetParameters(parameters, &error, &warning);
  EXPECT_EQ(error,
            "subnet_prefix is missing;"
            "exclusion_list is missing;inclusion_list is missing;");
  EXPECT_TRUE(warning.empty());

  error.clear();
  parameters["subnet_prefix"] = "123";
  driver_->SetParameters(parameters, &error, &warning);
  EXPECT_EQ(error,
            "subnet_prefix not in expected range;"
            "exclusion_list is missing;inclusion_list is missing;");
  EXPECT_TRUE(warning.empty());

  error.clear();
  parameters["subnet_prefix"] = "12";
  driver_->SetParameters(parameters, &error, &warning);
  EXPECT_EQ(error, "exclusion_list is missing;inclusion_list is missing;");
  EXPECT_TRUE(warning.empty());

  error.clear();
  parameters["dns_servers"] = "12 123123 43902374";
  driver_->SetParameters(parameters, &error, &warning);
  EXPECT_EQ(error, "exclusion_list is missing;inclusion_list is missing;");
  EXPECT_EQ(warning,
            "12 for dns_servers is invalid;"
            "123123 for dns_servers is invalid;"
            "43902374 for dns_servers is invalid;");

  error.clear();
  warning.clear();
  parameters["exclusion_list"] =
      "400.400.400.400/12 1.1.1.1/44 1.1.1.1/-1 "
      "123.211.21.0/23 123.211.21.1/23 123.211.21.0/25 "
      "1.1.1.1.1/12 1.1.1/13";
  parameters["dns_servers"] = "";
  driver_->SetParameters(parameters, &error, &warning);
  EXPECT_EQ(error, "inclusion_list is missing;");
  EXPECT_EQ(warning,
            "400.400.400.400/12 for exclusion_list is invalid;"
            "1.1.1.1/44 for exclusion_list is invalid;"
            "1.1.1.1/-1 for exclusion_list is invalid;"
            "Duplicate entry for 123.211.21.1/23 in exclusion_list found;"
            "1.1.1.1.1/12 for exclusion_list is invalid;"
            "1.1.1/13 for exclusion_list is invalid;");

  error.clear();
  warning.clear();
  parameters["exclusion_list"] = "0.0.0.0/0 123.211.21.29/31 123.211.21.1/24";
  parameters["inclusion_list"] =
      "400.400.400.400/12 1.1.1.1/44 1.1.1.1/-1 "
      "123.211.22.0/24 123.211.22.1/24 "
      "1.1.1.1.1/12 1.1.1/13 123.211.21.0/24";
  driver_->SetParameters(parameters, &error, &warning);
  EXPECT_TRUE(error.empty());
  EXPECT_EQ(warning,
            "400.400.400.400/12 for inclusion_list is invalid;"
            "1.1.1.1/44 for inclusion_list is invalid;"
            "1.1.1.1/-1 for inclusion_list is invalid;"
            "Duplicate entry for 123.211.22.1/24 in inclusion_list found;"
            "1.1.1.1.1/12 for inclusion_list is invalid;"
            "1.1.1/13 for inclusion_list is invalid;"
            "Duplicate entry for 123.211.21.0/24 in inclusion_list found;");

  error.clear();
  warning.clear();
  parameters["dns_servers"] = "123.211.21.18 123.211.21.19";
  parameters["inclusion_list"] = "123.211.61.29/7 123.211.42.29/17";
  driver_->parameters_expected_ = true;
  driver_->SetParameters(parameters, &error, &warning);
  EXPECT_EQ(driver_->ipv4_properties_->exclusion_list.size(), 3);
  EXPECT_EQ(driver_->ipv4_properties_->exclusion_list[0], "123.211.21.29/31");
  EXPECT_EQ(driver_->ipv4_properties_->exclusion_list[1], "0.0.0.0/0");
  EXPECT_EQ(driver_->ipv4_properties_->exclusion_list[2], "123.211.21.1/24");
  EXPECT_EQ(driver_->ipv4_properties_->inclusion_list.size(), 2);
  EXPECT_EQ(driver_->ipv4_properties_->inclusion_list[0], "123.211.61.29/7");
  EXPECT_EQ(driver_->ipv4_properties_->inclusion_list[1], "123.211.42.29/17");
  EXPECT_TRUE(error.empty());
  EXPECT_TRUE(warning.empty());
  EXPECT_TRUE(driver_->parameters_expected_);
}

}  // namespace shill
