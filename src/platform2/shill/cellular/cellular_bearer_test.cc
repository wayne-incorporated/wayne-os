// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/cellular/cellular_bearer.h"

#include <ModemManager/ModemManager.h>

#include <memory>
#include <string>

#include "shill/dbus/dbus_properties_proxy.h"
#include "shill/dbus/fake_properties_proxy.h"
#include "shill/mock_control.h"
#include "shill/testing.h"

using testing::_;
using testing::ByMove;
using testing::Return;
using testing::ReturnNull;

namespace shill {

namespace {

const RpcIdentifier kBearerDBusPath =
    RpcIdentifier("/org/freedesktop/ModemManager/Bearer/0");
const char kBearerDBusService[] = "org.freedesktop.ModemManager";
const char kDataInterface[] = "/dev/ppp0";
const char kIPv4Address[] = "10.0.0.1";
const char kIPv4Gateway[] = "10.0.0.254";
const int kIPv4SubnetPrefix = 8;
const uint32_t kIPv4Mtu = 1300;
const char* const kIPv4DNS[] = {"10.0.0.2", "8.8.4.4", "8.8.8.8"};
const char kIPv6Address[] = "0:0:0:0:0:ffff:a00:1";
const char kIPv6Gateway[] = "0:0:0:0:0:ffff:a00:fe";
const int kIPv6SubnetPrefix = 16;
const uint32_t kIPv6Mtu = 1400;
const char* const kIPv6DNS[] = {"0:0:0:0:0:ffff:a00:fe",
                                "0:0:0:0:0:ffff:808:404",
                                "0:0:0:0:0:ffff:808:808"};

}  // namespace

class CellularBearerTest : public testing::Test {
 public:
  CellularBearerTest()
      : control_(new MockControl()),
        bearer_(control_.get(), kBearerDBusPath, kBearerDBusService) {}

 protected:
  void VerifyDefaultProperties() {
    EXPECT_EQ(kBearerDBusPath, bearer_.dbus_path());
    EXPECT_EQ(kBearerDBusService, bearer_.dbus_service());
    EXPECT_FALSE(bearer_.connected());
    EXPECT_EQ("", bearer_.data_interface());
    EXPECT_EQ(CellularBearer::IPConfigMethod::kUnknown,
              bearer_.ipv4_config_method());
    EXPECT_EQ(nullptr, bearer_.ipv4_config_properties());
    EXPECT_EQ(CellularBearer::IPConfigMethod::kUnknown,
              bearer_.ipv6_config_method());
    EXPECT_EQ(nullptr, bearer_.ipv6_config_properties());
  }

  static KeyValueStore ConstructIPv4ConfigProperties(
      MMBearerIpMethod ipconfig_method) {
    KeyValueStore ipconfig_properties;
    ipconfig_properties.Set<uint32_t>("method", ipconfig_method);
    if (ipconfig_method == MM_BEARER_IP_METHOD_STATIC) {
      ipconfig_properties.Set<std::string>("address", kIPv4Address);
      ipconfig_properties.Set<std::string>("gateway", kIPv4Gateway);
      ipconfig_properties.Set<uint32_t>("prefix", kIPv4SubnetPrefix);
      ipconfig_properties.Set<std::string>("dns1", kIPv4DNS[0]);
      ipconfig_properties.Set<std::string>("dns2", kIPv4DNS[1]);
      ipconfig_properties.Set<std::string>("dns3", kIPv4DNS[2]);
      ipconfig_properties.Set<uint32_t>("mtu", kIPv4Mtu);
    }
    return ipconfig_properties;
  }

  static KeyValueStore ConstructIPv6ConfigProperties(
      MMBearerIpMethod ipconfig_method) {
    KeyValueStore ipconfig_properties;
    ipconfig_properties.Set<uint32_t>("method", ipconfig_method);
    if (ipconfig_method == MM_BEARER_IP_METHOD_STATIC) {
      ipconfig_properties.Set<std::string>("address", kIPv6Address);
      ipconfig_properties.Set<std::string>("gateway", kIPv6Gateway);
      ipconfig_properties.Set<uint32_t>("prefix", kIPv6SubnetPrefix);
      ipconfig_properties.Set<std::string>("dns1", kIPv6DNS[0]);
      ipconfig_properties.Set<std::string>("dns2", kIPv6DNS[1]);
      ipconfig_properties.Set<std::string>("dns3", kIPv6DNS[2]);
      ipconfig_properties.Set<uint32_t>("mtu", kIPv6Mtu);
    }
    return ipconfig_properties;
  }

  static void SetBearerProperties(FakePropertiesProxy* fake_properties_proxy) {
    bool connected = true;
    const std::string interface_name = MM_DBUS_INTERFACE_BEARER;
    const std::string data_interface = kDataInterface;
    MMBearerIpMethod ipv4_config_method = MM_BEARER_IP_METHOD_STATIC;
    MMBearerIpMethod ipv6_config_method = MM_BEARER_IP_METHOD_STATIC;

    fake_properties_proxy->SetForTesting(
        interface_name, MM_BEARER_PROPERTY_CONNECTED, brillo::Any(connected));
    fake_properties_proxy->SetForTesting(interface_name,
                                         MM_BEARER_PROPERTY_INTERFACE,
                                         brillo::Any(data_interface));
    fake_properties_proxy->SetForTesting(
        interface_name, MM_BEARER_PROPERTY_IP4CONFIG,
        brillo::Any(ConstructIPv4ConfigProperties(ipv4_config_method)));
    fake_properties_proxy->SetForTesting(
        interface_name, MM_BEARER_PROPERTY_IP6CONFIG,
        brillo::Any(ConstructIPv6ConfigProperties(ipv6_config_method)));
  }

  void VerifyStaticIPv4ConfigMethodAndProperties() {
    EXPECT_EQ(CellularBearer::IPConfigMethod::kStatic,
              bearer_.ipv4_config_method());
    const IPConfig::Properties* ipv4_config_properties =
        bearer_.ipv4_config_properties();
    ASSERT_NE(nullptr, ipv4_config_properties);
    EXPECT_EQ(IPAddress::kFamilyIPv4, ipv4_config_properties->address_family);
    EXPECT_EQ(kIPv4Address, ipv4_config_properties->address);
    EXPECT_EQ(kIPv4Gateway, ipv4_config_properties->gateway);
    EXPECT_EQ(kIPv4SubnetPrefix, ipv4_config_properties->subnet_prefix);
    ASSERT_EQ(3, ipv4_config_properties->dns_servers.size());
    EXPECT_EQ(kIPv4DNS[0], ipv4_config_properties->dns_servers[0]);
    EXPECT_EQ(kIPv4DNS[1], ipv4_config_properties->dns_servers[1]);
    EXPECT_EQ(kIPv4DNS[2], ipv4_config_properties->dns_servers[2]);
    EXPECT_EQ(kIPv4Mtu, ipv4_config_properties->mtu);
  }

  void VerifyStaticIPv6ConfigMethodAndProperties() {
    EXPECT_EQ(CellularBearer::IPConfigMethod::kStatic,
              bearer_.ipv6_config_method());
    const IPConfig::Properties* ipv6_config_properties =
        bearer_.ipv6_config_properties();
    ASSERT_NE(nullptr, ipv6_config_properties);
    EXPECT_EQ(IPAddress::kFamilyIPv6, ipv6_config_properties->address_family);
    EXPECT_EQ(kIPv6Address, ipv6_config_properties->address);
    EXPECT_EQ(kIPv6Gateway, ipv6_config_properties->gateway);
    EXPECT_EQ(kIPv6SubnetPrefix, ipv6_config_properties->subnet_prefix);
    ASSERT_EQ(3, ipv6_config_properties->dns_servers.size());
    EXPECT_EQ(kIPv6DNS[0], ipv6_config_properties->dns_servers[0]);
    EXPECT_EQ(kIPv6DNS[1], ipv6_config_properties->dns_servers[1]);
    EXPECT_EQ(kIPv6DNS[2], ipv6_config_properties->dns_servers[2]);
    EXPECT_EQ(kIPv6Mtu, ipv6_config_properties->mtu);
  }

  std::unique_ptr<MockControl> control_;
  CellularBearer bearer_;
};

TEST_F(CellularBearerTest, Constructor) {
  VerifyDefaultProperties();
}

TEST_F(CellularBearerTest, Init) {
  std::unique_ptr<DBusPropertiesProxy> dbus_properties_proxy =
      DBusPropertiesProxy::CreateDBusPropertiesProxyForTesting(
          std::make_unique<FakePropertiesProxy>());
  SetBearerProperties(static_cast<FakePropertiesProxy*>(
      dbus_properties_proxy->GetDBusPropertiesProxyForTesting()));
  EXPECT_CALL(*control_,
              CreateDBusPropertiesProxy(kBearerDBusPath, kBearerDBusService))
      .WillOnce(Return(ByMove(std::move(dbus_properties_proxy))));

  bearer_.Init();
  EXPECT_TRUE(bearer_.connected());
  EXPECT_EQ(kDataInterface, bearer_.data_interface());
  VerifyStaticIPv4ConfigMethodAndProperties();
  VerifyStaticIPv6ConfigMethodAndProperties();
}

TEST_F(CellularBearerTest, InitAndCreateDBusPropertiesProxyFails) {
  EXPECT_CALL(*control_,
              CreateDBusPropertiesProxy(kBearerDBusPath, kBearerDBusService))
      .WillOnce(ReturnNull());
  bearer_.Init();
  VerifyDefaultProperties();
}

TEST_F(CellularBearerTest, OnPropertiesChanged) {
  KeyValueStore properties;

  // If interface is not MM_DBUS_INTERFACE_BEARER, no updates should be done.
  bearer_.OnPropertiesChanged("", properties);
  VerifyDefaultProperties();

  properties.Set<bool>(MM_BEARER_PROPERTY_CONNECTED, true);
  bearer_.OnPropertiesChanged("", properties);
  VerifyDefaultProperties();

  // Update 'interface' property.
  properties.Clear();
  properties.Set<std::string>(MM_BEARER_PROPERTY_INTERFACE, kDataInterface);
  bearer_.OnPropertiesChanged(MM_DBUS_INTERFACE_BEARER, properties);
  EXPECT_EQ(kDataInterface, bearer_.data_interface());

  // Update 'connected' property.
  properties.Clear();
  properties.Set<bool>(MM_BEARER_PROPERTY_CONNECTED, true);
  bearer_.OnPropertiesChanged(MM_DBUS_INTERFACE_BEARER, properties);
  EXPECT_TRUE(bearer_.connected());
  // 'interface' property remains unchanged.
  EXPECT_EQ(kDataInterface, bearer_.data_interface());

  // Update 'ip4config' property.
  properties.Clear();
  properties.Set<KeyValueStore>(
      MM_BEARER_PROPERTY_IP4CONFIG,
      ConstructIPv4ConfigProperties(MM_BEARER_IP_METHOD_UNKNOWN));
  bearer_.OnPropertiesChanged(MM_DBUS_INTERFACE_BEARER, properties);
  EXPECT_EQ(CellularBearer::IPConfigMethod::kUnknown,
            bearer_.ipv4_config_method());

  properties.Clear();
  properties.Set<KeyValueStore>(
      MM_BEARER_PROPERTY_IP4CONFIG,
      ConstructIPv4ConfigProperties(MM_BEARER_IP_METHOD_PPP));
  bearer_.OnPropertiesChanged(MM_DBUS_INTERFACE_BEARER, properties);
  EXPECT_EQ(CellularBearer::IPConfigMethod::kPPP, bearer_.ipv4_config_method());

  properties.Clear();
  properties.Set<KeyValueStore>(
      MM_BEARER_PROPERTY_IP4CONFIG,
      ConstructIPv4ConfigProperties(MM_BEARER_IP_METHOD_STATIC));
  bearer_.OnPropertiesChanged(MM_DBUS_INTERFACE_BEARER, properties);
  EXPECT_EQ(CellularBearer::IPConfigMethod::kStatic,
            bearer_.ipv4_config_method());
  VerifyStaticIPv4ConfigMethodAndProperties();

  properties.Clear();
  properties.Set<KeyValueStore>(
      MM_BEARER_PROPERTY_IP4CONFIG,
      ConstructIPv4ConfigProperties(MM_BEARER_IP_METHOD_DHCP));
  bearer_.OnPropertiesChanged(MM_DBUS_INTERFACE_BEARER, properties);
  EXPECT_EQ(CellularBearer::IPConfigMethod::kDHCP,
            bearer_.ipv4_config_method());

  // Update 'ip6config' property.
  properties.Clear();
  properties.Set<KeyValueStore>(
      MM_BEARER_PROPERTY_IP6CONFIG,
      ConstructIPv6ConfigProperties(MM_BEARER_IP_METHOD_UNKNOWN));
  bearer_.OnPropertiesChanged(MM_DBUS_INTERFACE_BEARER, properties);
  EXPECT_EQ(CellularBearer::IPConfigMethod::kUnknown,
            bearer_.ipv6_config_method());

  properties.Clear();
  properties.Set<KeyValueStore>(
      MM_BEARER_PROPERTY_IP6CONFIG,
      ConstructIPv6ConfigProperties(MM_BEARER_IP_METHOD_PPP));
  bearer_.OnPropertiesChanged(MM_DBUS_INTERFACE_BEARER, properties);
  EXPECT_EQ(CellularBearer::IPConfigMethod::kPPP, bearer_.ipv6_config_method());

  properties.Clear();
  properties.Set<KeyValueStore>(
      MM_BEARER_PROPERTY_IP6CONFIG,
      ConstructIPv6ConfigProperties(MM_BEARER_IP_METHOD_STATIC));
  bearer_.OnPropertiesChanged(MM_DBUS_INTERFACE_BEARER, properties);
  EXPECT_EQ(CellularBearer::IPConfigMethod::kStatic,
            bearer_.ipv6_config_method());
  VerifyStaticIPv6ConfigMethodAndProperties();

  properties.Clear();
  properties.Set<KeyValueStore>(
      MM_BEARER_PROPERTY_IP6CONFIG,
      ConstructIPv6ConfigProperties(MM_BEARER_IP_METHOD_DHCP));
  bearer_.OnPropertiesChanged(MM_DBUS_INTERFACE_BEARER, properties);
  EXPECT_EQ(CellularBearer::IPConfigMethod::kDHCP,
            bearer_.ipv6_config_method());
}

}  // namespace shill
