// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/vpn/arc_vpn_driver.h"

#include <memory>

#include <base/functional/bind.h>
#include <base/memory/ptr_util.h>
#include <gtest/gtest.h>

#include "shill/mock_control.h"
#include "shill/mock_device_info.h"
#include "shill/mock_manager.h"
#include "shill/mock_metrics.h"
#include "shill/mock_virtual_device.h"
#include "shill/store/fake_store.h"
#include "shill/test_event_dispatcher.h"
#include "shill/vpn/mock_vpn_driver.h"
#include "shill/vpn/mock_vpn_provider.h"
#include "shill/vpn/vpn_provider.h"

using testing::_;
using testing::NiceMock;
using testing::Return;

namespace shill {

namespace {

const char kInterfaceName[] = "arcbr0";
const int kInterfaceIndex = 123;
const char kStorageId[] = "fakestorage";

}  // namespace

class ArcVpnDriverTest : public testing::Test {
 public:
  ArcVpnDriverTest()
      : manager_(&control_, &dispatcher_, &metrics_),
        device_info_(&manager_),
        device_(new MockVirtualDevice(
            &manager_, kInterfaceName, kInterfaceIndex, Technology::kVPN)),
        store_(),
        driver_(new ArcVpnDriver(&manager_, nullptr)) {
    manager_.set_mock_device_info(&device_info_);
  }

  ~ArcVpnDriverTest() override = default;

  void SetUp() override {
    manager_.vpn_provider_ = std::make_unique<MockVPNProvider>();
    manager_.vpn_provider_->manager_ = &manager_;
    manager_.UpdateProviderMapping();
  }

  void TearDown() override {
    manager_.vpn_provider_.reset();
    device_ = nullptr;
  }

  void LoadPropertiesFromStore(bool tunnel_chrome) {
    const std::string kProviderHostValue = "arcvpn";
    const std::string kProviderTypeValue = "arcvpn";

    store_.SetString(kStorageId, kProviderHostProperty, kProviderHostValue);
    store_.SetString(kStorageId, kProviderTypeProperty, kProviderTypeValue);
    store_.SetString(kStorageId, kArcVpnTunnelChromeProperty,
                     tunnel_chrome ? "true" : "false");
    driver_->Load(&store_, kStorageId);
  }

 protected:
  MockControl control_;
  EventDispatcherForTest dispatcher_;
  MockMetrics metrics_;
  MockManager manager_;
  NiceMock<MockDeviceInfo> device_info_;
  scoped_refptr<MockVirtualDevice> device_;
  FakeStore store_;
  MockVPNDriverEventHandler event_handler_;
  std::unique_ptr<ArcVpnDriver> driver_;
};

TEST_F(ArcVpnDriverTest, VPNType) {
  EXPECT_EQ(driver_->vpn_type(), VPNType::kARC);
}

TEST_F(ArcVpnDriverTest, ConnectAsync) {
  LoadPropertiesFromStore(true);
  EXPECT_CALL(device_info_, GetIndex(_)).WillOnce(Return(kInterfaceIndex));
  EXPECT_CALL(event_handler_,
              OnDriverConnected(std::string(VPNProvider::kArcBridgeIfName),
                                kInterfaceIndex))
      .Times(1);
  driver_->ConnectAsync(&event_handler_);
  dispatcher_.task_environment().RunUntilIdle();
}

TEST_F(ArcVpnDriverTest, GetIPv4Properties) {
  const auto ip_properties = driver_->GetIPv4Properties();
  ASSERT_NE(ip_properties, nullptr);
  EXPECT_TRUE(ip_properties->blackhole_ipv6);
  EXPECT_FALSE(ip_properties->default_route);
}

}  // namespace shill
