// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/service.h"

#include <base/check.h>
#include <base/strings/string_number_conversions.h>
#include <chromeos/dbus/service_constants.h>
#include <gtest/gtest.h>

#include "shill/ipconfig.h"
#include "shill/mock_connection.h"
#include "shill/mock_control.h"
#include "shill/mock_device_info.h"
#include "shill/mock_manager.h"
#include "shill/mock_metrics.h"
#include "shill/network/network_config.h"
#include "shill/service_under_test.h"
#include "shill/store/fake_store.h"
#include "shill/store/property_store.h"
#include "shill/test_event_dispatcher.h"

using testing::_;
using testing::DoAll;
using testing::Return;
using testing::SetArgPointee;
using testing::StrictMock;
using testing::Test;

namespace shill {

namespace {

const char kAddress[] = "10.0.0.1";
const char kGateway[] = "10.0.0.254";
const int32_t kMtu = 512;

const char kNameServer0[] = "10.0.1.253";
const char kNameServer1[] = "10.0.1.252";
const char kNameServers[] = "10.0.1.253,10.0.1.252";

const char kSearchDomains[] = "example.com,chromium.org";
const char kSearchDomain0[] = "example.com";
const char kSearchDomain1[] = "chromium.org";

const int32_t kPrefixLen = 24;

const char kExcludedRoutes[] = "192.168.1.0/24,192.168.2.0/24";
const char kExcludedRoute0[] = "192.168.1.0/24";
const char kExcludedRoute1[] = "192.168.2.0/24";

const char kIncludedRoutes[] = "0.0.0.0/0,10.8.0.0/16";
const char kIncludedRoute0[] = "0.0.0.0/0";
const char kIncludedRoute1[] = "10.8.0.0/16";

}  // namespace

// TODO(b/232177767): This test verifies the implementation inside Service,
// StaticIPParameters and Network. We should verify the logic in the first two
// classes against the interface of Network instead. Rework this test once the
// Network class is finalized.
class StaticIPParametersTest : public Test {
 public:
  StaticIPParametersTest() {
    manager_ = std::make_unique<MockManager>(&control_interface_, &dispatcher_,
                                             &metrics_);
    service_ = new ServiceUnderTest(manager_.get());

    const std::string ifname = "eth1";
    network_ =
        std::make_unique<Network>(1, ifname, Technology::kEthernet, false,
                                  &control_interface_, &dispatcher_, &metrics_);
    network_->set_connection_for_testing(std::make_unique<MockConnection>());
    network_->set_ipconfig(
        std::make_unique<IPConfig>(&control_interface_, ifname));
    // Call SetupConnection() explicitly to make this IPConfig object being
    // selected.
    network_->SetupConnection(network_->ipconfig());
  }

  ~StaticIPParametersTest() {
    service_ = nullptr;
    network_ = nullptr;
    manager_ = nullptr;
  }

  // Attaching the Network should trigger the event that Service pushes the
  // static config into service, and since there is Connection and ipconfig() in
  // the Network, the new IPConfig will be applied.
  void AttachNetwork() {
    service_->SetAttachedNetwork(network_->AsWeakPtr());
    dispatcher_.task_environment().RunUntilIdle();
  }

  // Triggers that the Network applies the saved config it keeps, by a static
  // config change without running the pending tasks.
  void TriggerRestore() { service_->NotifyStaticIPConfigChanged(); }

  void ExpectEmptyIPConfig() {
    const auto& ipconfig_props = GetIPConfig()->properties();
    EXPECT_TRUE(ipconfig_props.address.empty());
    EXPECT_TRUE(ipconfig_props.gateway.empty());
    EXPECT_EQ(IPConfig::kUndefinedMTU, ipconfig_props.mtu);
    EXPECT_TRUE(ipconfig_props.dns_servers.empty());
    EXPECT_TRUE(ipconfig_props.domain_search.empty());
    EXPECT_FALSE(ipconfig_props.subnet_prefix);
    EXPECT_TRUE(ipconfig_props.exclusion_list.empty());
    EXPECT_TRUE(ipconfig_props.inclusion_list.empty());
    EXPECT_TRUE(ipconfig_props.default_route);
  }
  // Modify an IP address string in some predictable way.  There's no need
  // for the output string to be valid from a networking perspective.
  std::string VersionedAddress(const std::string& address, int version) {
    std::string returned_address = address;
    CHECK(returned_address.length());
    returned_address[returned_address.length() - 1] += version;
    return returned_address;
  }
  void ExpectPopulatedIPConfigWithVersion(int version) {
    const auto& ipconfig_props = GetIPConfig()->properties();
    EXPECT_EQ(VersionedAddress(kAddress, version), ipconfig_props.address);
    EXPECT_EQ(VersionedAddress(kGateway, version), ipconfig_props.gateway);
    EXPECT_EQ(kMtu + version, ipconfig_props.mtu);

    EXPECT_EQ(2, ipconfig_props.dns_servers.size());
    EXPECT_EQ(VersionedAddress(kNameServer0, version),
              ipconfig_props.dns_servers[0]);
    EXPECT_EQ(VersionedAddress(kNameServer1, version),
              ipconfig_props.dns_servers[1]);

    // VersionedAddress() increments the final character of each domain
    // name.
    EXPECT_EQ(2, ipconfig_props.domain_search.size());
    EXPECT_EQ(VersionedAddress(kSearchDomain0, version),
              ipconfig_props.domain_search[0]);
    EXPECT_EQ(VersionedAddress(kSearchDomain1, version),
              ipconfig_props.domain_search[1]);

    EXPECT_EQ(kPrefixLen + version, ipconfig_props.subnet_prefix);

    EXPECT_EQ(2, ipconfig_props.exclusion_list.size());
    EXPECT_EQ(VersionedAddress(kExcludedRoute0, version),
              ipconfig_props.exclusion_list[0]);
    EXPECT_EQ(VersionedAddress(kExcludedRoute1, version),
              ipconfig_props.exclusion_list[1]);

    EXPECT_EQ(2, ipconfig_props.inclusion_list.size());
    EXPECT_EQ(VersionedAddress(kIncludedRoute0, version),
              ipconfig_props.inclusion_list[0]);
    EXPECT_EQ(VersionedAddress(kIncludedRoute1, version),
              ipconfig_props.inclusion_list[1]);
    EXPECT_FALSE(ipconfig_props.default_route);
  }
  void ExpectPopulatedIPConfig() { ExpectPopulatedIPConfigWithVersion(0); }
  void ExpectPropertiesWithVersion(const std::string& property_prefix,
                                   int version) {
    KeyValueStore args;
    Error unused_error;
    EXPECT_TRUE(service_->mutable_store()->GetKeyValueStoreProperty(
        property_prefix + "Config", &args, &unused_error));
    EXPECT_EQ(VersionedAddress(kAddress, version),
              args.Get<std::string>(kAddressProperty));
    EXPECT_EQ(VersionedAddress(kGateway, version),
              args.Get<std::string>(kGatewayProperty));
    EXPECT_EQ(kMtu + version, args.Get<int32_t>(kMtuProperty));
    std::vector<std::string> kTestNameServers(
        {VersionedAddress(kNameServer0, version),
         VersionedAddress(kNameServer1, version)});
    EXPECT_EQ(kTestNameServers, args.Get<Strings>(kNameServersProperty));
    std::vector<std::string> kTestSearchDomains(
        {VersionedAddress(kSearchDomain0, version),
         VersionedAddress(kSearchDomain1, version)});
    EXPECT_EQ(kTestSearchDomains, args.Get<Strings>(kSearchDomainsProperty));
    EXPECT_EQ(kPrefixLen + version, args.Get<int32_t>(kPrefixlenProperty));
    std::vector<std::string> kTestExcludedRoutes(
        {VersionedAddress(kExcludedRoute0, version),
         VersionedAddress(kExcludedRoute1, version)});
    EXPECT_EQ(kTestExcludedRoutes, args.Get<Strings>(kExcludedRoutesProperty));
    std::vector<std::string> kTestIncludedRoutes(
        {VersionedAddress(kIncludedRoute0, version),
         VersionedAddress(kIncludedRoute1, version)});
    EXPECT_EQ(kTestIncludedRoutes, args.Get<Strings>(kIncludedRoutesProperty));
  }
  void ExpectProperties(const std::string& property_prefix) {
    ExpectPropertiesWithVersion(property_prefix, 0);
  }
  void PopulateIPConfig() {
    IPConfig::Properties ipconfig_props;
    ipconfig_props.address = kAddress;
    ipconfig_props.gateway = kGateway;
    ipconfig_props.mtu = kMtu;
    ipconfig_props.dns_servers = {kNameServer0, kNameServer1};
    ipconfig_props.domain_search = {kSearchDomain0, kSearchDomain1};
    ipconfig_props.subnet_prefix = kPrefixLen;
    ipconfig_props.exclusion_list = {kExcludedRoute0, kExcludedRoute1};
    ipconfig_props.inclusion_list = {kIncludedRoute0, kIncludedRoute1};
    ipconfig_props.default_route = false;
    GetIPConfig()->UpdateProperties(ipconfig_props);
  }
  void SetStaticProperties() { SetStaticPropertiesWithVersion(0); }
  void SetStaticPropertiesWithVersion(int version) {
    KeyValueStore args;
    args.Set<std::string>(kAddressProperty,
                          VersionedAddress(kAddress, version));
    args.Set<std::string>(kGatewayProperty,
                          VersionedAddress(kGateway, version));
    args.Set<int32_t>(kMtuProperty, kMtu + version);
    args.Set<Strings>(kNameServersProperty,
                      {VersionedAddress(kNameServer0, version),
                       VersionedAddress(kNameServer1, version)});
    args.Set<Strings>(kSearchDomainsProperty,
                      {VersionedAddress(kSearchDomain0, version),
                       VersionedAddress(kSearchDomain1, version)});
    args.Set<int32_t>(kPrefixlenProperty, kPrefixLen + version);
    args.Set<Strings>(kExcludedRoutesProperty,
                      {VersionedAddress(kExcludedRoute0, version),
                       VersionedAddress(kExcludedRoute1, version)});
    args.Set<Strings>(kIncludedRoutesProperty,
                      {VersionedAddress(kIncludedRoute0, version),
                       VersionedAddress(kIncludedRoute1, version)});

    Error error;
    service_->mutable_store()->SetKeyValueStoreProperty(kStaticIPConfigProperty,
                                                        args, &error);
  }
  void SetStaticPropertiesWithoutRoute(PropertyStore* store) {
    KeyValueStore args;
    args.Set<std::string>(kAddressProperty, kAddress);
    args.Set<std::string>(kGatewayProperty, kGateway);
    args.Set<int32_t>(kMtuProperty, kMtu);
    Error error;
    store->SetKeyValueStoreProperty(kStaticIPConfigProperty, args, &error);
  }

  KeyValueStore GetStaticArgs() {
    KeyValueStore ret;
    Error unused_err;
    CHECK(service_->store().GetKeyValueStoreProperty(kStaticIPConfigProperty,
                                                     &ret, &unused_err));
    return ret;
  }
  KeyValueStore GetSavedArgs() {
    KeyValueStore ret;
    Error unused_err;
    CHECK(service_->store().GetKeyValueStoreProperty(kSavedIPConfigProperty,
                                                     &ret, &unused_err));
    return ret;
  }
  IPConfig* GetIPConfig() {
    auto* ipconfig = network_->GetCurrentIPConfig();
    CHECK(ipconfig);
    return ipconfig;
  }

 protected:
  MockControl control_interface_;
  EventDispatcherForTest dispatcher_;
  MockMetrics metrics_;
  std::unique_ptr<MockManager> manager_;

  scoped_refptr<ServiceUnderTest> service_;
  std::unique_ptr<Network> network_;
};

TEST_F(StaticIPParametersTest, InitState) {
  ExpectEmptyIPConfig();
  AttachNetwork();
  ExpectEmptyIPConfig();
}

TEST_F(StaticIPParametersTest, ApplyEmptyParameters) {
  PopulateIPConfig();
  AttachNetwork();
  ExpectPopulatedIPConfig();
}

TEST_F(StaticIPParametersTest, DefaultRoute) {
  SetStaticPropertiesWithoutRoute(service_->mutable_store());
  AttachNetwork();
  EXPECT_TRUE(GetIPConfig()->properties().default_route);
  SetStaticProperties();
  dispatcher_.task_environment().RunUntilIdle();
  EXPECT_FALSE(GetIPConfig()->properties().default_route);
  TriggerRestore();
  EXPECT_TRUE(GetIPConfig()->properties().default_route);
}

TEST_F(StaticIPParametersTest, ControlInterface) {
  Error unused_error;
  int version = 0;
  auto* store = service_->mutable_store();
  SetStaticProperties();

  EXPECT_TRUE(store->Contains("StaticIPConfig"));
  auto current_args = GetStaticArgs();
  current_args.Remove("Address");
  current_args.Remove("Mtu");
  store->SetKeyValueStoreProperty("StaticIPConfig", current_args,
                                  &unused_error);

  current_args = GetStaticArgs();
  EXPECT_FALSE(current_args.Contains<std::string>("Address"));
  EXPECT_FALSE(current_args.Contains<int32_t>("PrefixLen"));
  EXPECT_EQ(kGateway, current_args.Get<std::string>("Gateway"));
  EXPECT_FALSE(current_args.Contains<int32_t>("Mtu"));
  std::vector<std::string> kTestNameServers(
      {VersionedAddress(kNameServer0, version),
       VersionedAddress(kNameServer1, version)});
  EXPECT_EQ(kTestNameServers, current_args.Get<Strings>("NameServers"));
  std::vector<std::string> kTestSearchDomains(
      {VersionedAddress(kSearchDomain0, version),
       VersionedAddress(kSearchDomain1, version)});
  EXPECT_EQ(kTestSearchDomains, current_args.Get<Strings>("SearchDomains"));
  std::vector<std::string> kTestExcludedRoutes(
      {VersionedAddress(kExcludedRoute0, version),
       VersionedAddress(kExcludedRoute1, version)});
  EXPECT_EQ(kTestExcludedRoutes, current_args.Get<Strings>("ExcludedRoutes"));
  std::vector<std::string> kTestIncludedRoutes(
      {VersionedAddress(kIncludedRoute0, version),
       VersionedAddress(kIncludedRoute1, version)});
  EXPECT_EQ(kTestIncludedRoutes, current_args.Get<Strings>("IncludedRoutes"));
}

TEST_F(StaticIPParametersTest, Profile) {
  FakeStore store;
  const std::string& id = service_->GetStorageIdentifier();
  store.SetString(id, "StaticIP.Address", kAddress);
  store.SetString(id, "StaticIP.Gateway", kGateway);
  store.SetInt(id, "StaticIP.Mtu", kMtu);
  store.SetString(id, "StaticIP.NameServers", kNameServers);
  store.SetString(id, "StaticIP.SearchDomains", kSearchDomains);
  store.SetInt(id, "StaticIP.Prefixlen", kPrefixLen);
  store.SetString(id, "StaticIP.ExcludedRoutes", kExcludedRoutes);
  store.SetString(id, "StaticIP.IncludedRoutes", kIncludedRoutes);

  service_->Load(&store);
  AttachNetwork();
  ExpectPopulatedIPConfig();

  service_->Save(&store);

  std::string address;
  EXPECT_TRUE(store.GetString(id, "StaticIP.Address", &address));
  EXPECT_EQ(address, kAddress);
  std::string gateway;
  EXPECT_TRUE(store.GetString(id, "StaticIP.Gateway", &gateway));
  EXPECT_EQ(gateway, kGateway);
  int mtu;
  EXPECT_TRUE(store.GetInt(id, "StaticIP.Mtu", &mtu));
  EXPECT_EQ(mtu, kMtu);
  std::string nameservers;
  EXPECT_TRUE(store.GetString(id, "StaticIP.NameServers", &nameservers));
  EXPECT_EQ(nameservers, kNameServers);
  std::string searchdomains;
  EXPECT_TRUE(store.GetString(id, "StaticIP.SearchDomains", &searchdomains));
  EXPECT_EQ(searchdomains, kSearchDomains);
  int prefixlen;
  EXPECT_TRUE(store.GetInt(id, "StaticIP.Prefixlen", &prefixlen));
  EXPECT_EQ(prefixlen, kPrefixLen);
  std::string excludedroutes;
  EXPECT_TRUE(store.GetString(id, "StaticIP.ExcludedRoutes", &excludedroutes));
  EXPECT_EQ(excludedroutes, kExcludedRoutes);
  std::string includedroutes;
  EXPECT_TRUE(store.GetString(id, "StaticIP.IncludedRoutes", &includedroutes));
  EXPECT_EQ(includedroutes, kIncludedRoutes);
}

TEST_F(StaticIPParametersTest, SavedParameters) {
  Error unused_error;

  AttachNetwork();
  PopulateIPConfig();

  // Set the config property will cause Network push a task to configure the
  // IPConfig using that.
  SetStaticPropertiesWithVersion(1);
  dispatcher_.task_environment().RunUntilIdle();

  // The version 0 properties in IPConfig are now in SavedIP.* properties, while
  // the version 1 StaticIP parameters are now in IPConfig.
  ExpectPropertiesWithVersion("SavedIP", 0);
  ExpectPopulatedIPConfigWithVersion(1);

  // Clear all "StaticIP" parameters. Current IPConfig will be recovered from
  // saved config, and the saved config should be cleared.
  service_->mutable_store()->SetKeyValueStoreProperty(
      "StaticIPConfig", KeyValueStore(), &unused_error);
  dispatcher_.task_environment().RunUntilIdle();
  EXPECT_TRUE(GetSavedArgs().IsEmpty());
  ExpectPopulatedIPConfigWithVersion(0);

  // Reset current IPConfig to version 0.
  PopulateIPConfig();

  // Set static config to version to, and the current IPConfig should also be
  // updated to version 2, and the saved config should record the previous
  // IPConfig value with version 0.
  SetStaticPropertiesWithVersion(2);
  dispatcher_.task_environment().RunUntilIdle();
  ExpectPopulatedIPConfigWithVersion(2);
  ExpectPropertiesWithVersion("SavedIP", 0);

  // Static IP parameters should be unchanged.
  ExpectPropertiesWithVersion("StaticIP", 2);
}

}  // namespace shill
