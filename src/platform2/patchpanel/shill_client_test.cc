// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "patchpanel/shill_client.h"

#include <algorithm>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <chromeos/dbus/service_constants.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "patchpanel/fake_shill_client.h"

namespace patchpanel {
namespace {

class ShillClientTest : public testing::Test {
 protected:
  void SetUp() override {
    helper_ = std::make_unique<FakeShillClientHelper>();
    client_ = helper_->FakeClient();
    client_->RegisterDefaultLogicalDeviceChangedHandler(base::BindRepeating(
        &ShillClientTest::DefaultLogicalDeviceChangedHandler,
        base::Unretained(this)));
    client_->RegisterDefaultPhysicalDeviceChangedHandler(base::BindRepeating(
        &ShillClientTest::DefaultPhysicalDeviceChangedHandler,
        base::Unretained(this)));
    client_->RegisterDevicesChangedHandler(base::BindRepeating(
        &ShillClientTest::DevicesChangedHandler, base::Unretained(this)));
    client_->RegisterIPConfigsChangedHandler(base::BindRepeating(
        &ShillClientTest::IPConfigsChangedHandler, base::Unretained(this)));
    client_->RegisterIPv6NetworkChangedHandler(base::BindRepeating(
        &ShillClientTest::IPv6NetworkChangedHandler, base::Unretained(this)));
    default_logical_ifname_.clear();
    added_.clear();
    removed_.clear();
  }

  void DefaultLogicalDeviceChangedHandler(
      const ShillClient::Device& new_device,
      const ShillClient::Device& prev_device) {
    default_logical_ifname_ = new_device.ifname;
  }

  void DefaultPhysicalDeviceChangedHandler(
      const ShillClient::Device& new_device,
      const ShillClient::Device& prev_device) {
    default_physical_ifname_ = new_device.ifname;
  }

  void DevicesChangedHandler(const std::vector<ShillClient::Device>& added,
                             const std::vector<ShillClient::Device>& removed) {
    added_ = added;
    removed_ = removed;
  }

  void IPConfigsChangedHandler(const ShillClient::Device& device) {
    ipconfig_change_calls_.push_back(device);
  }

  void IPv6NetworkChangedHandler(const ShillClient::Device& device) {
    ipv6_network_change_calls_.push_back(device);
  }

 protected:
  std::string default_logical_ifname_;
  std::string default_physical_ifname_;
  std::vector<ShillClient::Device> added_;
  std::vector<ShillClient::Device> removed_;
  std::vector<ShillClient::Device> ipconfig_change_calls_;
  std::vector<ShillClient::Device> ipv6_network_change_calls_;
  std::unique_ptr<FakeShillClient> client_;
  std::unique_ptr<FakeShillClientHelper> helper_;
};

TEST_F(ShillClientTest, DevicesChangedHandlerCalledOnDevicesPropertyChange) {
  dbus::ObjectPath eth0_path = dbus::ObjectPath("/device/eth0");
  ShillClient::Device eth0_dev;
  eth0_dev.type = ShillClient::Device::Type::kEthernet;
  eth0_dev.ifindex = 1;
  eth0_dev.ifname = "eth0";
  eth0_dev.service_path = "/service/1";
  client_->SetFakeDeviceProperties(eth0_path, eth0_dev);

  dbus::ObjectPath eth1_path = dbus::ObjectPath("/device/eth1");
  ShillClient::Device eth1_dev;
  eth1_dev.type = ShillClient::Device::Type::kEthernet;
  eth1_dev.ifindex = 2;
  eth1_dev.ifname = "eth1";
  eth1_dev.service_path = "/service/2";
  client_->SetFakeDeviceProperties(eth1_path, eth1_dev);

  dbus::ObjectPath wlan0_path = dbus::ObjectPath("/device/wlan0");
  ShillClient::Device wlan_dev;
  wlan_dev.type = ShillClient::Device::Type::kWifi;
  wlan_dev.ifindex = 3;
  wlan_dev.ifname = "wlan0";
  wlan_dev.service_path = "/service/3";
  client_->SetFakeDeviceProperties(wlan0_path, wlan_dev);

  std::vector<dbus::ObjectPath> devices = {eth0_path, wlan0_path};
  auto value = brillo::Any(devices);
  client_->SetFakeDefaultLogicalDevice("eth0");
  client_->SetFakeDefaultPhysicalDevice("eth0");

  client_->NotifyManagerPropertyChange(shill::kDevicesProperty, value);
  EXPECT_EQ(added_.size(), devices.size());
  EXPECT_NE(std::find_if(added_.begin(), added_.end(),
                         [](const ShillClient::Device& dev) {
                           return dev.ifname == "eth0";
                         }),
            added_.end());
  EXPECT_NE(std::find_if(added_.begin(), added_.end(),
                         [](const ShillClient::Device& dev) {
                           return dev.ifname == "wlan0";
                         }),
            added_.end());
  EXPECT_EQ(removed_.size(), 0);

  // Implies the default callback was run;
  EXPECT_EQ(default_logical_ifname_, "eth0");
  EXPECT_EQ(default_physical_ifname_, "eth0");
  EXPECT_NE(std::find_if(added_.begin(), added_.end(),
                         [this](const ShillClient::Device& dev) {
                           return dev.ifname == default_logical_ifname_;
                         }),
            added_.end());

  devices.pop_back();
  devices.emplace_back(eth1_path);
  value = brillo::Any(devices);
  client_->NotifyManagerPropertyChange(shill::kDevicesProperty, value);
  EXPECT_EQ(added_.size(), 1);
  EXPECT_EQ(added_[0].ifname, "eth1");
  EXPECT_EQ(removed_.size(), 1);
  EXPECT_EQ(removed_[0].ifname, "wlan0");
}

TEST_F(ShillClientTest, VerifyDevicesPrefixStripped) {
  dbus::ObjectPath eth0_path = dbus::ObjectPath("/device/eth0");
  ShillClient::Device eth0_dev;
  eth0_dev.type = ShillClient::Device::Type::kEthernet;
  eth0_dev.ifindex = 1;
  eth0_dev.ifname = "eth0";
  eth0_dev.service_path = "/service/1";
  client_->SetFakeDeviceProperties(eth0_path, eth0_dev);
  std::vector<dbus::ObjectPath> devices = {eth0_path};
  auto value = brillo::Any(devices);
  client_->SetFakeDefaultLogicalDevice("eth0");
  client_->SetFakeDefaultPhysicalDevice("eth0");

  client_->NotifyManagerPropertyChange(shill::kDevicesProperty, value);
  EXPECT_EQ(added_.size(), 1);
  EXPECT_EQ(added_[0].ifname, "eth0");
  // Implies the default callback was run;
  EXPECT_EQ(default_logical_ifname_, "eth0");
  EXPECT_EQ(default_physical_ifname_, "eth0");
}

TEST_F(ShillClientTest, DefaultDeviceChangedHandlerCalledOnNewDefaultDevice) {
  client_->SetFakeDefaultLogicalDevice("eth0");
  client_->SetFakeDefaultPhysicalDevice("eth0");
  client_->NotifyManagerPropertyChange(shill::kDefaultServiceProperty,
                                       brillo::Any() /* ignored */);
  EXPECT_EQ(default_logical_ifname_, "eth0");
  EXPECT_EQ(default_physical_ifname_, "eth0");

  client_->SetFakeDefaultLogicalDevice("wlan0");
  client_->SetFakeDefaultPhysicalDevice("wlan0");
  client_->NotifyManagerPropertyChange(shill::kDefaultServiceProperty,
                                       brillo::Any() /* ignored */);
  EXPECT_EQ(default_logical_ifname_, "wlan0");
  EXPECT_EQ(default_physical_ifname_, "wlan0");
}

TEST_F(ShillClientTest, DefaultDeviceChangedHandlerNotCalledForSameDefault) {
  client_->SetFakeDefaultLogicalDevice("eth0");
  client_->SetFakeDefaultPhysicalDevice("eth0");
  client_->NotifyManagerPropertyChange(shill::kDefaultServiceProperty,
                                       brillo::Any() /* ignored */);
  EXPECT_EQ(default_logical_ifname_, "eth0");
  EXPECT_EQ(default_physical_ifname_, "eth0");

  default_logical_ifname_.clear();
  default_physical_ifname_.clear();
  client_->NotifyManagerPropertyChange(shill::kDefaultServiceProperty,
                                       brillo::Any() /* ignored */);
  // Implies the callback was not run the second time.
  EXPECT_EQ(default_logical_ifname_, "");
  EXPECT_EQ(default_physical_ifname_, "");
}

TEST_F(ShillClientTest, DefaultDeviceChanges) {
  dbus::ObjectPath eth0_path = dbus::ObjectPath("/device/eth0");
  ShillClient::Device eth0_dev;
  eth0_dev.type = ShillClient::Device::Type::kEthernet;
  eth0_dev.ifindex = 1;
  eth0_dev.ifname = "eth0";
  eth0_dev.service_path = "/service/1";
  client_->SetFakeDeviceProperties(eth0_path, eth0_dev);

  dbus::ObjectPath wlan0_path = dbus::ObjectPath("/device/wlan0");
  ShillClient::Device wlan_dev;
  wlan_dev.type = ShillClient::Device::Type::kWifi;
  wlan_dev.ifindex = 3;
  wlan_dev.ifname = "wlan0";
  wlan_dev.service_path = "/service/3";
  client_->SetFakeDeviceProperties(wlan0_path, wlan_dev);

  // One network device appears.
  std::vector<dbus::ObjectPath> devices = {wlan0_path};
  auto value = brillo::Any(devices);
  client_->SetFakeDefaultLogicalDevice("wlan0");
  client_->SetFakeDefaultPhysicalDevice("wlan0");
  client_->NotifyManagerPropertyChange(shill::kDevicesProperty, value);
  EXPECT_EQ(default_logical_ifname_, "wlan0");
  EXPECT_EQ(default_physical_ifname_, "wlan0");

  // A second device appears.
  default_logical_ifname_.clear();
  default_physical_ifname_.clear();
  devices = {eth0_path, wlan0_path};
  value = brillo::Any(devices);
  client_->NotifyManagerPropertyChange(shill::kDevicesProperty, value);
  EXPECT_EQ(default_logical_ifname_, "");
  EXPECT_EQ(default_physical_ifname_, "");

  // The second device becomes the default interface.
  client_->SetFakeDefaultLogicalDevice("eth0");
  client_->SetFakeDefaultPhysicalDevice("eth0");
  client_->NotifyManagerPropertyChange(shill::kDefaultServiceProperty,
                                       brillo::Any() /* ignored */);
  EXPECT_EQ(default_logical_ifname_, "eth0");
  EXPECT_EQ(default_physical_ifname_, "eth0");

  // The first device disappears.
  devices = {eth0_path};
  value = brillo::Any(devices);
  client_->NotifyManagerPropertyChange(shill::kDevicesProperty, value);
  // The default device is still the same.
  EXPECT_EQ(default_logical_ifname_, "eth0");
  EXPECT_EQ(default_physical_ifname_, "eth0");

  // All devices have disappeared.
  devices = {};
  value = brillo::Any(devices);
  client_->SetFakeDefaultLogicalDevice("");
  client_->SetFakeDefaultPhysicalDevice("");
  client_->NotifyManagerPropertyChange(shill::kDevicesProperty, value);
  EXPECT_EQ(default_logical_ifname_, "");
  EXPECT_EQ(default_physical_ifname_, "");
}

TEST_F(ShillClientTest, ListenToDeviceChangeSignalOnNewDevices) {
  dbus::ObjectPath eth0_path = dbus::ObjectPath("/device/eth0");
  ShillClient::Device eth0_dev;
  eth0_dev.type = ShillClient::Device::Type::kEthernet;
  eth0_dev.ifindex = 1;
  eth0_dev.ifname = "eth0";
  eth0_dev.service_path = "/service/1";
  client_->SetFakeDeviceProperties(eth0_path, eth0_dev);

  dbus::ObjectPath wlan0_path = dbus::ObjectPath("/device/wlan0");
  ShillClient::Device wlan_dev;
  wlan_dev.type = ShillClient::Device::Type::kWifi;
  wlan_dev.ifindex = 3;
  wlan_dev.ifname = "wlan0";
  wlan_dev.service_path = "/service/3";
  client_->SetFakeDeviceProperties(wlan0_path, wlan_dev);

  // Adds a device.
  std::vector<dbus::ObjectPath> devices = {wlan0_path};
  auto value = brillo::Any(devices);
  EXPECT_CALL(*helper_->mock_proxy(),
              DoConnectToSignal(shill::kFlimflamDeviceInterface,
                                shill::kMonitorPropertyChanged, _, _))
      .Times(1);
  client_->NotifyManagerPropertyChange(shill::kDevicesProperty, value);

  // Adds another device. DoConnectToSignal() called only for the new added one.
  devices = {wlan0_path, eth0_path};
  value = brillo::Any(devices);
  EXPECT_CALL(*helper_->mock_proxy(),
              DoConnectToSignal(shill::kFlimflamDeviceInterface,
                                shill::kMonitorPropertyChanged, _, _))
      .Times(1);
  client_->NotifyManagerPropertyChange(shill::kDevicesProperty, value);
}

TEST_F(ShillClientTest, TriggerOnIPConfigsChangeHandlerOnce) {
  // Adds a fake WiFi device.
  dbus::ObjectPath wlan0_path = dbus::ObjectPath("/device/wlan0");
  ShillClient::Device wlan_dev;
  wlan_dev.type = ShillClient::Device::Type::kWifi;
  wlan_dev.ifindex = 1;
  wlan_dev.ifname = "wlan0";
  wlan_dev.service_path = "/service/1";
  wlan_dev.ipconfig.ipv4_prefix_length = 24;
  wlan_dev.ipconfig.ipv4_address = "192.168.10.48";
  wlan_dev.ipconfig.ipv4_gateway = "192.168.10.1";
  client_->SetFakeDeviceProperties(wlan0_path, wlan_dev);
  std::vector<dbus::ObjectPath> devices = {wlan0_path};
  auto devices_value = brillo::Any(devices);

  // The device will first appear before it acquires a new IP configuration.
  client_->NotifyManagerPropertyChange(shill::kDevicesProperty, devices_value);

  // Spurious shill::kIPConfigsProperty update with no configuration change,
  // listeners are not triggered.
  client_->NotifyDevicePropertyChange(wlan0_path, shill::kIPConfigsProperty,
                                      brillo::Any());
  ASSERT_TRUE(ipconfig_change_calls_.empty());

  // Update IP configuration
  wlan_dev.ipconfig.ipv4_dns_addresses = {"1.1.1.1"};
  client_->SetFakeDeviceProperties(wlan0_path, wlan_dev);

  // A shill::kIPConfigsProperty update triggers listeners.
  client_->NotifyDevicePropertyChange(wlan0_path, shill::kIPConfigsProperty,
                                      brillo::Any());
  ASSERT_EQ(ipconfig_change_calls_.size(), 1u);
  EXPECT_EQ(ipconfig_change_calls_.back().ifname, "wlan0");
  EXPECT_EQ(ipconfig_change_calls_.back().ipconfig.ipv4_prefix_length, 24);
  EXPECT_EQ(ipconfig_change_calls_.back().ipconfig.ipv4_address,
            "192.168.10.48");
  EXPECT_EQ(ipconfig_change_calls_.back().ipconfig.ipv4_gateway,
            "192.168.10.1");
  EXPECT_EQ(ipconfig_change_calls_.back().ipconfig.ipv4_dns_addresses,
            std::vector<std::string>({"1.1.1.1"}));

  // Removes the device. The device will first lose its IP configuration before
  // disappearing.
  ShillClient::Device disconnected_dev = wlan_dev;
  disconnected_dev.ipconfig = {};
  client_->SetFakeDeviceProperties(wlan0_path, disconnected_dev);
  client_->NotifyDevicePropertyChange(wlan0_path, shill::kIPConfigsProperty,
                                      brillo::Any());
  client_->NotifyManagerPropertyChange(shill::kDevicesProperty, brillo::Any());
  ASSERT_EQ(ipconfig_change_calls_.size(), 2u);
  EXPECT_EQ(ipconfig_change_calls_.back().ifname, "wlan0");
  EXPECT_EQ(ipconfig_change_calls_.back().ipconfig.ipv4_prefix_length, 0);
  EXPECT_EQ(ipconfig_change_calls_.back().ipconfig.ipv4_address, "");
  EXPECT_EQ(ipconfig_change_calls_.back().ipconfig.ipv4_gateway, "");
  EXPECT_TRUE(
      ipconfig_change_calls_.back().ipconfig.ipv4_dns_addresses.empty());

  // Adds the device again. The device will first appear before it acquires a
  // new IP configuration.
  client_->NotifyManagerPropertyChange(shill::kDevicesProperty, devices_value);
  client_->SetFakeDeviceProperties(wlan0_path, wlan_dev);
  client_->NotifyDevicePropertyChange(wlan0_path, shill::kIPConfigsProperty,
                                      brillo::Any());
  ASSERT_EQ(ipconfig_change_calls_.size(), 3u);
  EXPECT_EQ(ipconfig_change_calls_.back().ifname, "wlan0");
  EXPECT_EQ(ipconfig_change_calls_.back().ipconfig.ipv4_prefix_length, 24);
  EXPECT_EQ(ipconfig_change_calls_.back().ipconfig.ipv4_address,
            "192.168.10.48");
  EXPECT_EQ(ipconfig_change_calls_.back().ipconfig.ipv4_gateway,
            "192.168.10.1");
  EXPECT_EQ(ipconfig_change_calls_.back().ipconfig.ipv4_dns_addresses,
            std::vector<std::string>({"1.1.1.1"}));
}

TEST_F(ShillClientTest, TriggerOnIPv6NetworkChangedHandler) {
  // Adds a fake WiFi device.
  dbus::ObjectPath wlan0_path = dbus::ObjectPath("/device/wlan0");
  ShillClient::Device wlan_dev;
  wlan_dev.type = ShillClient::Device::Type::kWifi;
  wlan_dev.ifindex = 1;
  wlan_dev.ifname = "wlan0";
  wlan_dev.service_path = "/service/1";
  wlan_dev.ipconfig.ipv6_prefix_length = 64;
  wlan_dev.ipconfig.ipv6_address = "2001:db8::aabb:ccdd:1122:eeff";
  wlan_dev.ipconfig.ipv6_gateway = "fe80::abcd:1234";
  wlan_dev.ipconfig.ipv6_dns_addresses = {"2001:db8::1111"};
  std::vector<dbus::ObjectPath> devices = {wlan0_path};
  auto devices_value = brillo::Any(devices);

  // The device will first appear before it acquires a new IP configuration. The
  // listeners are triggered
  client_->NotifyManagerPropertyChange(shill::kDevicesProperty, devices_value);
  client_->SetFakeDeviceProperties(wlan0_path, wlan_dev);
  client_->NotifyDevicePropertyChange(wlan0_path, shill::kIPConfigsProperty,
                                      brillo::Any());
  ASSERT_EQ(ipconfig_change_calls_.size(), 1u);
  EXPECT_EQ(ipconfig_change_calls_.back().ifname, "wlan0");
  EXPECT_EQ(ipconfig_change_calls_.back().ipconfig.ipv6_prefix_length, 64);
  EXPECT_EQ(ipconfig_change_calls_.back().ipconfig.ipv6_address,
            "2001:db8::aabb:ccdd:1122:eeff");
  EXPECT_EQ(ipconfig_change_calls_.back().ipconfig.ipv6_gateway,
            "fe80::abcd:1234");
  EXPECT_EQ(ipconfig_change_calls_.back().ipconfig.ipv6_dns_addresses,
            std::vector<std::string>({"2001:db8::1111"}));
  ASSERT_EQ(ipv6_network_change_calls_.size(), 1u);
  EXPECT_EQ(ipv6_network_change_calls_.back().ifname, "wlan0");
  EXPECT_EQ(ipv6_network_change_calls_.back().ipconfig.ipv6_prefix_length, 64);
  EXPECT_EQ(ipv6_network_change_calls_.back().ipconfig.ipv6_address,
            "2001:db8::aabb:ccdd:1122:eeff");

  // Removes the device. The device will first lose its IP configuration before
  // disappearing.
  ShillClient::Device disconnected_dev = wlan_dev;
  disconnected_dev.ipconfig = {};
  client_->SetFakeDeviceProperties(wlan0_path, disconnected_dev);
  client_->NotifyDevicePropertyChange(wlan0_path, shill::kIPConfigsProperty,
                                      brillo::Any());
  client_->NotifyManagerPropertyChange(shill::kDevicesProperty, brillo::Any());
  ASSERT_EQ(ipconfig_change_calls_.size(), 2u);
  EXPECT_EQ(ipconfig_change_calls_.back().ifname, "wlan0");
  EXPECT_EQ(ipconfig_change_calls_.back().ipconfig.ipv6_prefix_length, 0);
  EXPECT_EQ(ipconfig_change_calls_.back().ipconfig.ipv6_address, "");
  EXPECT_EQ(ipconfig_change_calls_.back().ipconfig.ipv6_gateway, "");
  EXPECT_TRUE(
      ipconfig_change_calls_.back().ipconfig.ipv6_dns_addresses.empty());
  ASSERT_EQ(ipv6_network_change_calls_.size(), 2u);
  EXPECT_EQ(ipv6_network_change_calls_.back().ifname, "wlan0");
  EXPECT_EQ(ipv6_network_change_calls_.back().ipconfig.ipv6_prefix_length, 0);
  EXPECT_EQ(ipv6_network_change_calls_.back().ipconfig.ipv6_address, "");

  // Adds the device again. The device will first appear before it acquires a
  // new IP configuration, without DNS.
  wlan_dev.ipconfig.ipv6_dns_addresses = {};
  client_->NotifyManagerPropertyChange(shill::kDevicesProperty, devices_value);
  client_->SetFakeDeviceProperties(wlan0_path, wlan_dev);
  client_->NotifyDevicePropertyChange(wlan0_path, shill::kIPConfigsProperty,
                                      brillo::Any());
  ASSERT_EQ(ipconfig_change_calls_.size(), 3u);
  EXPECT_EQ(ipconfig_change_calls_.back().ifname, "wlan0");
  EXPECT_EQ(ipconfig_change_calls_.back().ipconfig.ipv6_prefix_length, 64);
  EXPECT_EQ(ipconfig_change_calls_.back().ipconfig.ipv6_address,
            "2001:db8::aabb:ccdd:1122:eeff");
  EXPECT_EQ(ipconfig_change_calls_.back().ipconfig.ipv6_gateway,
            "fe80::abcd:1234");
  EXPECT_TRUE(
      ipconfig_change_calls_.back().ipconfig.ipv6_dns_addresses.empty());
  ASSERT_EQ(ipv6_network_change_calls_.size(), 3u);
  EXPECT_EQ(ipv6_network_change_calls_.back().ifname, "wlan0");
  EXPECT_EQ(ipv6_network_change_calls_.back().ipconfig.ipv6_prefix_length, 64);
  EXPECT_EQ(ipv6_network_change_calls_.back().ipconfig.ipv6_address,
            "2001:db8::aabb:ccdd:1122:eeff");

  // Adds IPv6 DNS, IPv6NetworkChangedHandler is not triggered.
  wlan_dev.ipconfig.ipv6_dns_addresses = {"2001:db8::1111"};
  client_->SetFakeDeviceProperties(wlan0_path, wlan_dev);
  client_->NotifyDevicePropertyChange(wlan0_path, shill::kIPConfigsProperty,
                                      brillo::Any());
  ASSERT_EQ(ipconfig_change_calls_.size(), 4u);
  EXPECT_EQ(ipconfig_change_calls_.back().ifname, "wlan0");
  EXPECT_EQ(ipconfig_change_calls_.back().ipconfig.ipv6_dns_addresses,
            std::vector<std::string>({"2001:db8::1111"}));
  ASSERT_EQ(ipv6_network_change_calls_.size(), 3u);
}

}  // namespace
}  // namespace patchpanel
