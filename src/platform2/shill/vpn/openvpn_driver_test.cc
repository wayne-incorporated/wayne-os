// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/vpn/openvpn_driver.h"

#include <iterator>
#include <memory>
#include <utility>

#include <base/check.h>
#include <base/containers/contains.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/memory/ptr_util.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <chromeos/dbus/service_constants.h>
#include <gtest/gtest.h>

#include "shill/error.h"
#include "shill/ipconfig.h"
#include "shill/logging.h"
#include "shill/mock_adaptors.h"
#include "shill/mock_certificate_file.h"
#include "shill/mock_control.h"
#include "shill/mock_device_info.h"
#include "shill/mock_event_dispatcher.h"
#include "shill/mock_manager.h"
#include "shill/mock_metrics.h"
#include "shill/mock_virtual_device.h"
#include "shill/net/mock_process_manager.h"
#include "shill/rpc_task.h"
#include "shill/technology.h"
#include "shill/virtual_device.h"
#include "shill/vpn/fake_vpn_util.h"
#include "shill/vpn/mock_openvpn_management_server.h"
#include "shill/vpn/mock_vpn_driver.h"
#include "shill/vpn/mock_vpn_provider.h"
#include "shill/vpn/vpn_provider.h"
#include "shill/vpn/vpn_service.h"

using testing::_;
using testing::DoAll;
using testing::Eq;
using testing::Field;
using testing::Mock;
using testing::NiceMock;
using testing::Return;
using testing::SetArgPointee;

namespace shill {

struct AuthenticationExpectations {
  AuthenticationExpectations()
      : remote_authentication_type(Metrics::kVpnRemoteAuthenticationTypeMax) {}
  AuthenticationExpectations(
      const std::string& ca_cert_in,
      const std::string& client_cert_in,
      const std::string& user_in,
      const std::string& otp_in,
      const std::string& token_in,
      Metrics::VpnRemoteAuthenticationType remote_authentication_type_in,
      const std::vector<Metrics::VpnUserAuthenticationType>&
          user_authentication_types_in)
      : ca_cert(ca_cert_in),
        client_cert(client_cert_in),
        user(user_in),
        otp(otp_in),
        token(token_in),
        remote_authentication_type(remote_authentication_type_in),
        user_authentication_types(user_authentication_types_in) {}
  std::string ca_cert;
  std::string client_cert;
  std::string user;
  std::string otp;
  std::string token;
  Metrics::VpnRemoteAuthenticationType remote_authentication_type;
  std::vector<Metrics::VpnUserAuthenticationType> user_authentication_types;
};

class OpenVPNDriverTest
    : public testing::TestWithParam<AuthenticationExpectations>,
      public RpcTaskDelegate {
 public:
  OpenVPNDriverTest()
      : manager_(&control_, &dispatcher_, &metrics_),
        device_info_(&manager_),
        driver_(new OpenVPNDriver(&manager_, &process_manager_)),
        certificate_file_(new MockCertificateFile()),
        extra_certificates_file_(new MockCertificateFile()),
        management_server_(new NiceMock<MockOpenVPNManagementServer>()) {
    manager_.set_mock_device_info(&device_info_);
    driver_->management_server_.reset(management_server_);
    driver_->certificate_file_.reset(certificate_file_);  // Passes ownership.
    driver_->extra_certificates_file_.reset(
        extra_certificates_file_);  // Passes ownership.
    CHECK(temporary_directory_.CreateUniqueTempDir());
    driver_->openvpn_config_directory_ =
        temporary_directory_.GetPath().Append(kOpenVPNConfigDirectory);
    driver_->vpn_util_ = std::make_unique<FakeVPNUtil>();
  }

  ~OpenVPNDriverTest() override = default;

  void SetUp() override {
    manager_.vpn_provider_ = std::make_unique<MockVPNProvider>();
    manager_.vpn_provider_->manager_ = &manager_;
    manager_.UpdateProviderMapping();
  }

  void TearDown() override {
    driver_->pid_ = 0;
    SetEventHandler(nullptr);
    if (!lsb_release_file_.empty()) {
      EXPECT_TRUE(base::DeleteFile(lsb_release_file_));
      lsb_release_file_.clear();
    }
  }

 protected:
  static const char kOption[];
  static const char kProperty[];
  static const char kValue[];
  static const char kOption2[];
  static const char kProperty2[];
  static const char kValue2[];
  static const char kGateway1[];
  static const char kNetmask1[];
  static const int kPrefix1;
  static const char kNetwork1[];
  static const char kGateway2[];
  static const char kNetmask2[];
  static const int kPrefix2;
  static const char kNetwork2[];
  static const char kInterfaceName[];
  static const int kInterfaceIndex;
  static const char kOpenVPNConfigDirectory[];

  void SetArg(const std::string& arg, const std::string& value) {
    driver_->args()->Set<std::string>(arg, value);
  }

  void SetArgArray(const std::string& arg,
                   const std::vector<std::string>& value) {
    driver_->args()->Set<Strings>(arg, value);
  }

  KeyValueStore* GetArgs() { return driver_->args(); }

  KeyValueStore GetProviderProperties(const PropertyStore& store) {
    KeyValueStore props;
    Error error;
    EXPECT_TRUE(
        store.GetKeyValueStoreProperty(kProviderProperty, &props, &error));
    return props;
  }

  void RemoveStringArg(const std::string& arg) { driver_->args()->Remove(arg); }

  bool InitManagementChannelOptions(
      std::vector<std::vector<std::string>>* options, Error* error) {
    return driver_->InitManagementChannelOptions(options, error);
  }

  Sockets* GetSockets() { return &driver_->sockets_; }

  void SetEventHandler(VPNDriver::EventHandler* handler) {
    driver_->event_handler_ = handler;
  }

  static base::TimeDelta GetDefaultConnectTimeout() {
    return OpenVPNDriver::kConnectTimeout;
  }

  static base::TimeDelta GetReconnectOfflineTimeout() {
    return OpenVPNDriver::kReconnectOfflineTimeout;
  }

  static base::TimeDelta GetReconnectTLSErrorTimeout() {
    return OpenVPNDriver::kReconnectTLSErrorTimeout;
  }

  static base::TimeDelta GetReconnectTimeout(
      OpenVPNDriver::ReconnectReason reason) {
    return OpenVPNDriver::GetReconnectTimeout(reason);
  }

  void SetClientState(const std::string& state) {
    management_server_->state_ = state;
  }

  // Used to assert that a flag appears in the options.
  void ExpectInFlags(const std::vector<std::vector<std::string>>& options,
                     const std::vector<std::string>& arguments);
  void ExpectNotInFlags(const std::vector<std::vector<std::string>>& options,
                        const std::string& flag);

  void SetupLSBRelease();

  // Inherited from RpcTaskDelegate.
  void GetLogin(std::string* user, std::string* password) override;
  void Notify(const std::string& reason,
              const std::map<std::string, std::string>& dict) override;

  MockControl control_;
  MockEventDispatcher dispatcher_;
  MockMetrics metrics_;
  MockProcessManager process_manager_;
  MockManager manager_;
  NiceMock<MockDeviceInfo> device_info_;
  MockVPNDriverEventHandler event_handler_;
  std::unique_ptr<OpenVPNDriver> driver_;
  MockCertificateFile* certificate_file_;         // Owned by |driver_|.
  MockCertificateFile* extra_certificates_file_;  // Owned by |driver_|.
  base::ScopedTempDir temporary_directory_;

  // Owned by |driver_|.
  NiceMock<MockOpenVPNManagementServer>* management_server_;

  base::FilePath lsb_release_file_;
};

const char OpenVPNDriverTest::kOption[] = "openvpn-option";
const char OpenVPNDriverTest::kProperty[] = "OpenVPN.SomeProperty";
const char OpenVPNDriverTest::kValue[] = "some-property-value";
const char OpenVPNDriverTest::kOption2[] = "openvpn-option2";
const char OpenVPNDriverTest::kProperty2[] = "OpenVPN.SomeProperty2";
const char OpenVPNDriverTest::kValue2[] = "some-property-value2";
const char OpenVPNDriverTest::kGateway1[] = "10.242.2.13";
const char OpenVPNDriverTest::kNetmask1[] = "255.255.255.255";
const int OpenVPNDriverTest::kPrefix1 = 32;
const char OpenVPNDriverTest::kNetwork1[] = "10.242.2.1";
const char OpenVPNDriverTest::kGateway2[] = "10.242.2.14";
const char OpenVPNDriverTest::kNetmask2[] = "255.255.0.0";
const int OpenVPNDriverTest::kPrefix2 = 16;
const char OpenVPNDriverTest::kNetwork2[] = "192.168.0.0";
const char OpenVPNDriverTest::kInterfaceName[] = "tun0";
const int OpenVPNDriverTest::kInterfaceIndex = 123;
const char OpenVPNDriverTest::kOpenVPNConfigDirectory[] = "openvpn";

void OpenVPNDriverTest::GetLogin(std::string* /*user*/,
                                 std::string* /*password*/) {}

void OpenVPNDriverTest::Notify(
    const std::string& /*reason*/,
    const std::map<std::string, std::string>& /*dict*/) {}

void OpenVPNDriverTest::ExpectInFlags(
    const std::vector<std::vector<std::string>>& options,
    const std::vector<std::string>& option) {
  EXPECT_TRUE(base::Contains(options, option));
}

void OpenVPNDriverTest::ExpectNotInFlags(
    const std::vector<std::vector<std::string>>& options,
    const std::string& flag) {
  for (const auto& option : options) {
    EXPECT_NE(flag, option[0]);
  }
}

void OpenVPNDriverTest::SetupLSBRelease() {
  static const char kLSBReleaseContents[] =
      "\n"
      "=\n"
      "foo=\n"
      "=bar\n"
      "zoo==\n"
      "CHROMEOS_RELEASE_BOARD=x86-alex\n"
      "CHROMEOS_RELEASE_NAME=Chromium OS\n"
      "CHROMEOS_RELEASE_VERSION=2202.0\n";
  EXPECT_TRUE(base::CreateTemporaryFile(&lsb_release_file_));
  EXPECT_EQ(std::size(kLSBReleaseContents),
            base::WriteFile(lsb_release_file_, kLSBReleaseContents,
                            std::size(kLSBReleaseContents)));
  EXPECT_EQ(OpenVPNDriver::kLSBReleaseFile, driver_->lsb_release_file_.value());
  driver_->lsb_release_file_ = lsb_release_file_;
}

TEST_F(OpenVPNDriverTest, VPNType) {
  EXPECT_EQ(driver_->vpn_type(), VPNType::kOpenVPN);
}

TEST_F(OpenVPNDriverTest, ConnectAsync) {
  static const char kHost[] = "192.168.2.254";
  SetArg(kProviderHostProperty, kHost);
  EXPECT_CALL(*management_server_, Start(_, _)).WillOnce(Return(true));
  EXPECT_CALL(manager_, IsConnected()).WillOnce(Return(false));
  EXPECT_CALL(process_manager_, StartProcessInMinijail).WillOnce(Return(10101));
  EXPECT_CALL(device_info_, CreateTunnelInterface(_)).WillOnce(Return(true));
  base::TimeDelta timeout = driver_->ConnectAsync(&event_handler_);
  EXPECT_EQ(timeout, GetDefaultConnectTimeout());

  driver_->OnLinkReady(kInterfaceName, kInterfaceIndex);
}

TEST_F(OpenVPNDriverTest, Notify) {
  constexpr auto kIPv4Addr = "1.2.3.4";
  constexpr auto kIPv6Addr = "fd01::1";
  SetEventHandler(&event_handler_);
  driver_->interface_name_ = kInterfaceName;
  driver_->interface_index_ = kInterfaceIndex;

  // OpenVPN process does not give us a valid config.
  EXPECT_CALL(event_handler_,
              OnDriverConnected(kInterfaceName, kInterfaceIndex))
      .Times(0);
  driver_->Notify("up", {});
  ASSERT_EQ(driver_->GetIPv4Properties(), nullptr);
  ASSERT_EQ(driver_->GetIPv6Properties(), nullptr);

  // Sets up the environment again.
  SetEventHandler(&event_handler_);
  driver_->interface_name_ = kInterfaceName;
  driver_->interface_index_ = kInterfaceIndex;

  // Gets IPv4 configurations.
  EXPECT_CALL(event_handler_,
              OnDriverConnected(kInterfaceName, kInterfaceIndex));
  driver_->Notify("up", {{"ifconfig_local", kIPv4Addr}});
  ASSERT_NE(driver_->GetIPv4Properties(), nullptr);
  EXPECT_EQ(driver_->GetIPv4Properties()->address, kIPv4Addr);
  ASSERT_EQ(driver_->GetIPv6Properties(), nullptr);

  // Gets IPv6 configurations. This also tests that existing properties are
  // reused if no new ones provided. (Note that normally v4 and v6 configuration
  // should come together.)
  EXPECT_CALL(event_handler_,
              OnDriverConnected(kInterfaceName, kInterfaceIndex));
  driver_->Notify("up", {{"ifconfig_ipv6_local", kIPv6Addr}});
  ASSERT_NE(driver_->GetIPv4Properties(), nullptr);
  EXPECT_EQ(driver_->GetIPv4Properties()->address, kIPv4Addr);
  ASSERT_NE(driver_->GetIPv6Properties(), nullptr);
  EXPECT_EQ(driver_->GetIPv6Properties()->address, kIPv6Addr);

  EXPECT_CALL(event_handler_,
              OnDriverConnected(kInterfaceName, kInterfaceIndex));
  driver_->Notify("up", {});
  ASSERT_NE(driver_->GetIPv4Properties(), nullptr);
  EXPECT_EQ(driver_->GetIPv4Properties()->address, kIPv4Addr);
  ASSERT_NE(driver_->GetIPv6Properties(), nullptr);
  EXPECT_EQ(driver_->GetIPv6Properties()->address, kIPv6Addr);
}

TEST_P(OpenVPNDriverTest, NotifyUMA) {
  std::map<std::string, std::string> config = {{"ifconfig_local", "1.2.3.4"}};
  SetEventHandler(&event_handler_);

  // Check that UMA metrics are emitted on Notify.
  EXPECT_CALL(metrics_, SendEnumToUMA(Metrics::kMetricVpnDriver,
                                      Metrics::kVpnDriverOpenVpn));
  EXPECT_CALL(metrics_,
              SendEnumToUMA(Metrics::kMetricVpnRemoteAuthenticationType,
                            GetParam().remote_authentication_type));
  for (const auto& authentication_type : GetParam().user_authentication_types) {
    EXPECT_CALL(metrics_,
                SendEnumToUMA(Metrics::kMetricVpnUserAuthenticationType,
                              authentication_type));
  }

  Error unused_error;
  PropertyStore store;
  driver_->InitPropertyStore(&store);
  if (!GetParam().ca_cert.empty()) {
    store.SetStringsProperty(kOpenVPNCaCertPemProperty, {GetParam().ca_cert},
                             &unused_error);
  }
  if (!GetParam().client_cert.empty()) {
    store.SetStringProperty(kOpenVPNClientCertIdProperty,
                            GetParam().client_cert, &unused_error);
  }
  if (!GetParam().user.empty()) {
    store.SetStringProperty(kOpenVPNUserProperty, GetParam().user,
                            &unused_error);
  }
  if (!GetParam().otp.empty()) {
    store.SetStringProperty(kOpenVPNOTPProperty, GetParam().otp, &unused_error);
  }
  if (!GetParam().token.empty()) {
    store.SetStringProperty(kOpenVPNTokenProperty, GetParam().token,
                            &unused_error);
  }
  driver_->Notify("up", config);
  Mock::VerifyAndClearExpectations(&metrics_);
}

INSTANTIATE_TEST_SUITE_P(
    OpenVPNDriverAuthenticationTypes,
    OpenVPNDriverTest,
    ::testing::Values(
        AuthenticationExpectations(
            "",
            "",
            "",
            "",
            "",
            Metrics::kVpnRemoteAuthenticationTypeOpenVpnDefault,
            {Metrics::kVpnUserAuthenticationTypeOpenVpnNone}),
        AuthenticationExpectations(
            "",
            "client_cert",
            "",
            "",
            "",
            Metrics::kVpnRemoteAuthenticationTypeOpenVpnDefault,
            {Metrics::kVpnUserAuthenticationTypeOpenVpnCertificate}),
        AuthenticationExpectations(
            "",
            "client_cert",
            "user",
            "",
            "",
            Metrics::kVpnRemoteAuthenticationTypeOpenVpnDefault,
            {Metrics::kVpnUserAuthenticationTypeOpenVpnCertificate,
             Metrics::kVpnUserAuthenticationTypeOpenVpnUsernamePassword}),
        AuthenticationExpectations(
            "",
            "",
            "user",
            "",
            "",
            Metrics::kVpnRemoteAuthenticationTypeOpenVpnDefault,
            {Metrics::kVpnUserAuthenticationTypeOpenVpnUsernamePassword}),
        AuthenticationExpectations(
            "",
            "client_cert",
            "user",
            "otp",
            "",
            Metrics::kVpnRemoteAuthenticationTypeOpenVpnDefault,
            {Metrics::kVpnUserAuthenticationTypeOpenVpnCertificate,
             Metrics::kVpnUserAuthenticationTypeOpenVpnUsernamePassword,
             Metrics::kVpnUserAuthenticationTypeOpenVpnUsernamePasswordOtp}),
        AuthenticationExpectations(
            "",
            "client_cert",
            "user",
            "otp",
            "token",
            Metrics::kVpnRemoteAuthenticationTypeOpenVpnDefault,
            {Metrics::kVpnUserAuthenticationTypeOpenVpnCertificate,
             Metrics::kVpnUserAuthenticationTypeOpenVpnUsernamePassword,
             Metrics::kVpnUserAuthenticationTypeOpenVpnUsernamePasswordOtp,
             Metrics::kVpnUserAuthenticationTypeOpenVpnUsernameToken}),
        AuthenticationExpectations(
            "ca_cert",
            "client_cert",
            "user",
            "otp",
            "token",
            Metrics::kVpnRemoteAuthenticationTypeOpenVpnCertificate,
            {Metrics::kVpnUserAuthenticationTypeOpenVpnCertificate,
             Metrics::kVpnUserAuthenticationTypeOpenVpnUsernamePassword,
             Metrics::kVpnUserAuthenticationTypeOpenVpnUsernamePasswordOtp,
             Metrics::kVpnUserAuthenticationTypeOpenVpnUsernameToken})));

TEST_F(OpenVPNDriverTest, GetRouteOptionEntry) {
  OpenVPNDriver::RouteOptions routes;
  EXPECT_EQ(nullptr, OpenVPNDriver::GetRouteOptionEntry("foo", "bar", &routes));
  EXPECT_TRUE(routes.empty());
  EXPECT_EQ(nullptr, OpenVPNDriver::GetRouteOptionEntry("foo", "foo", &routes));
  EXPECT_TRUE(routes.empty());
  EXPECT_EQ(nullptr,
            OpenVPNDriver::GetRouteOptionEntry("foo", "fooz", &routes));
  EXPECT_TRUE(routes.empty());
  IPConfig::Route* route =
      OpenVPNDriver::GetRouteOptionEntry("foo", "foo12", &routes);
  EXPECT_EQ(1, routes.size());
  EXPECT_EQ(route, &routes[12]);
  route = OpenVPNDriver::GetRouteOptionEntry("foo", "foo13", &routes);
  EXPECT_EQ(2, routes.size());
  EXPECT_EQ(route, &routes[13]);
}

TEST_F(OpenVPNDriverTest, ParseIPv4RouteOption) {
  OpenVPNDriver::RouteOptions routes;
  const auto invoke = [&routes](const std::string& key,
                                const std::string& value) {
    return OpenVPNDriver::ParseIPv4RouteOption(key, value, &routes);
  };
  EXPECT_FALSE(invoke("foo", "bar"));
  EXPECT_TRUE(routes.empty());
  EXPECT_TRUE(invoke("gateway_2", kGateway2));
  EXPECT_TRUE(invoke("netmask_2", kNetmask2));
  EXPECT_TRUE(invoke("network_2", kNetwork2));
  EXPECT_EQ(1, routes.size());
  EXPECT_TRUE(invoke("gateway_1", kGateway1));
  EXPECT_TRUE(invoke("netmask_1", kNetmask1));
  EXPECT_TRUE(invoke("network_1", kNetwork1));
  EXPECT_EQ(2, routes.size());
  EXPECT_EQ(kGateway1, routes[1].gateway);
  EXPECT_EQ(kPrefix1, routes[1].prefix);
  EXPECT_EQ(kNetwork1, routes[1].host);
  EXPECT_EQ(kGateway2, routes[2].gateway);
  EXPECT_EQ(kPrefix2, routes[2].prefix);
  EXPECT_EQ(kNetwork2, routes[2].host);
}

TEST_F(OpenVPNDriverTest, ParseIPv6RouteOption) {
  OpenVPNDriver::RouteOptions routes;
  const auto invoke = [&routes](const std::string& key,
                                const std::string& value) {
    return OpenVPNDriver::ParseIPv6RouteOption(key, value, &routes);
  };
  EXPECT_FALSE(invoke("foo", "bar"));
  EXPECT_FALSE(invoke("network_1", "fd00::/64"));  // network_* is for IPv4
  EXPECT_TRUE(routes.empty());

  // Do not verify routes.empty() here, since a valid key with an invalid value
  // will actually create an entry.
  EXPECT_FALSE(invoke("ipv6_network_1", "fd00::"));

  constexpr char kAddr1[] = "fd00::";
  constexpr int kPrefix1 = 64;
  constexpr char kGateway1[] = "fd00::1";
  constexpr char kAddr2[] = "fd01::";
  constexpr int kPrefix2 = 96;
  constexpr char kGateway2[] = "fd01::1";
  const auto prefix_str = [](const char* addr, int prefix) {
    return base::StringPrintf("%s/%d", addr, prefix);
  };
  EXPECT_TRUE(invoke("ipv6_network_2", prefix_str(kAddr2, kPrefix2)));
  EXPECT_TRUE(invoke("ipv6_gateway_2", kGateway2));
  EXPECT_TRUE(invoke("ipv6_network_1", prefix_str(kAddr1, kPrefix1)));
  EXPECT_TRUE(invoke("ipv6_gateway_1", kGateway1));
  EXPECT_EQ(2, routes.size());
  EXPECT_EQ(kAddr1, routes[1].host);
  EXPECT_EQ(kPrefix1, routes[1].prefix);
  EXPECT_EQ(kGateway1, routes[1].gateway);
  EXPECT_EQ(kAddr2, routes[2].host);
  EXPECT_EQ(kPrefix2, routes[2].prefix);
  EXPECT_EQ(kGateway2, routes[2].gateway);
}

TEST_F(OpenVPNDriverTest, SplitPortFromHost) {
  std::string name, port;
  EXPECT_FALSE(OpenVPNDriver::SplitPortFromHost("", nullptr, nullptr));
  EXPECT_FALSE(OpenVPNDriver::SplitPortFromHost("", &name, &port));
  EXPECT_FALSE(OpenVPNDriver::SplitPortFromHost("v.com", &name, &port));
  EXPECT_FALSE(OpenVPNDriver::SplitPortFromHost("v.com:", &name, &port));
  EXPECT_FALSE(OpenVPNDriver::SplitPortFromHost(":1234", &name, &port));
  EXPECT_FALSE(OpenVPNDriver::SplitPortFromHost("v.com:f:1234", &name, &port));
  EXPECT_FALSE(OpenVPNDriver::SplitPortFromHost("v.com:x", &name, &port));
  EXPECT_FALSE(OpenVPNDriver::SplitPortFromHost("v.com:-1", &name, &port));
  EXPECT_FALSE(OpenVPNDriver::SplitPortFromHost("v.com:+1", &name, &port));
  EXPECT_FALSE(OpenVPNDriver::SplitPortFromHost("v.com:65536", &name, &port));
  EXPECT_TRUE(OpenVPNDriver::SplitPortFromHost("v.com:0", &name, &port));
  EXPECT_EQ("v.com", name);
  EXPECT_EQ("0", port);
  EXPECT_TRUE(OpenVPNDriver::SplitPortFromHost("w.com:65535", &name, &port));
  EXPECT_EQ("w.com", name);
  EXPECT_EQ("65535", port);
  EXPECT_TRUE(OpenVPNDriver::SplitPortFromHost("x.com:12345", &name, &port));
  EXPECT_EQ("x.com", name);
  EXPECT_EQ("12345", port);
}

TEST_F(OpenVPNDriverTest, ParseForeignOptions) {
  // This also tests that std::map is a sorted container.
  std::map<int, std::string> options;
  options[5] = "dhcp-option DOMAIN five.com";
  options[2] = "dhcp-option DOMAIN two.com";
  options[8] = "dhcp-option DOMAIN eight.com";
  options[7] = "dhcp-option DOMAIN seven.com";
  options[4] = "dhcp-Option DOmAIN four.com";      // cases do not matter
  options[9] = "dhcp-option dns 1.2.3.4 1.2.3.4";  // ignore invalid
  options[10] = "dhcp-option dns 1.2.3.4";
  std::vector<std::string> search_domains;
  std::vector<std::string> name_servers;
  OpenVPNDriver::ParseForeignOptions(options, &search_domains, &name_servers);
  ASSERT_EQ(5, search_domains.size());
  EXPECT_EQ("two.com", search_domains[0]);
  EXPECT_EQ("four.com", search_domains[1]);
  EXPECT_EQ("five.com", search_domains[2]);
  EXPECT_EQ("seven.com", search_domains[3]);
  EXPECT_EQ("eight.com", search_domains[4]);
  ASSERT_EQ(1, name_servers.size());
  EXPECT_EQ("1.2.3.4", name_servers[0]);
}

TEST_F(OpenVPNDriverTest, ParseIPConfiguration) {
  std::map<std::string, std::string> config;
  std::unique_ptr<IPConfig::Properties> ipv4_props;
  std::unique_ptr<IPConfig::Properties> ipv6_props;

  const auto invoke = [&](bool ignore_redirect_gateway) {
    auto ret =
        OpenVPNDriver::ParseIPConfiguration(config, ignore_redirect_gateway);
    ipv4_props = std::move(ret.ipv4_props);
    ipv6_props = std::move(ret.ipv6_props);
  };

  config["ifconfig_loCal"] = "4.5.6.7";
  invoke(false);
  ASSERT_NE(ipv4_props, nullptr);
  ASSERT_EQ(ipv6_props, nullptr);
  EXPECT_EQ(IPAddress::kFamilyIPv4, ipv4_props->address_family);
  EXPECT_EQ(32, ipv4_props->subnet_prefix);

  // An "ifconfig_remote" parameter that looks like a netmask should be
  // applied to the subnet prefix instead of to the peer address.
  config["ifconfig_remotE"] = "255.255.0.0";
  invoke(false);
  ASSERT_NE(ipv4_props, nullptr);
  ASSERT_EQ(ipv6_props, nullptr);
  EXPECT_EQ(16, ipv4_props->subnet_prefix);
  EXPECT_EQ("", ipv4_props->peer_address);

  config["ifconFig_netmAsk"] = "255.255.255.0";
  config["ifconfig_remotE"] = "33.44.55.66";
  config["route_vpN_gateway"] = "192.168.1.1";
  config["trusted_ip"] = "99.88.77.66";
  config["tun_mtu"] = "1000";
  config["foreign_option_2"] = "dhcp-option DNS 4.4.4.4";
  config["foreign_option_1"] = "dhcp-option DNS 1.1.1.1";
  config["foreign_option_3"] = "dhcp-option DNS 2.2.2.2";
  config["route_network_2"] = kNetwork2;
  config["route_network_1"] = kNetwork1;
  config["route_netmask_2"] = kNetmask2;
  config["route_netmask_1"] = kNetmask1;
  config["route_gateway_2"] = kGateway2;
  config["route_gateway_1"] = kGateway1;
  config["foo"] = "bar";
  invoke(false);
  ASSERT_NE(ipv4_props, nullptr);
  ASSERT_EQ(ipv6_props, nullptr);
  EXPECT_EQ(IPAddress::kFamilyIPv4, ipv4_props->address_family);
  EXPECT_EQ("4.5.6.7", ipv4_props->address);
  EXPECT_EQ("0.0.0.0", ipv4_props->gateway);
  EXPECT_EQ(24, ipv4_props->subnet_prefix);
  EXPECT_EQ("", ipv4_props->peer_address);
  EXPECT_TRUE(ipv4_props->exclusion_list.empty());
  EXPECT_EQ(1000, ipv4_props->mtu);
  ASSERT_EQ(3, ipv4_props->dns_servers.size());
  EXPECT_EQ("1.1.1.1", ipv4_props->dns_servers[0]);
  EXPECT_EQ("4.4.4.4", ipv4_props->dns_servers[1]);
  EXPECT_EQ("2.2.2.2", ipv4_props->dns_servers[2]);
  ASSERT_EQ(3, ipv4_props->inclusion_list.size());
  ASSERT_EQ("33.44.55.66/32", ipv4_props->inclusion_list[0]);
  ASSERT_EQ(base::StringPrintf("%s/%d", kNetwork1, kPrefix1),
            ipv4_props->inclusion_list[1]);
  ASSERT_EQ(base::StringPrintf("%s/%d", kNetwork2, kPrefix2),
            ipv4_props->inclusion_list[2]);
  EXPECT_FALSE(ipv4_props->default_route);

  config["redirect_gateway"] = "def1";
  invoke(false);
  ASSERT_NE(ipv4_props, nullptr);
  ASSERT_EQ(ipv6_props, nullptr);
  EXPECT_TRUE(ipv4_props->default_route);
  EXPECT_TRUE(ipv4_props->blackhole_ipv6);

  // Don't set a default route if the user asked to ignore it.
  invoke(true);
  ASSERT_NE(ipv4_props, nullptr);
  ASSERT_EQ(ipv6_props, nullptr);
  EXPECT_FALSE(ipv4_props->default_route);

  // Set IPv6 properties, both v4 and v6 properties should not be nullptr.
  config["ifconfig_ipv6_local"] = "fd00::1";
  config["ifconfig_ipv6_netbits"] = "64";
  config["route_ipv6_network_1"] = "fd02::/96";
  config["route_ipv6_gateway_1"] = "fd02::1";
  invoke(false);
  ASSERT_NE(ipv4_props, nullptr);
  ASSERT_NE(ipv6_props, nullptr);
  EXPECT_TRUE(ipv4_props->default_route);
  EXPECT_FALSE(ipv4_props->blackhole_ipv6);
  EXPECT_EQ(kTypeVPN, ipv6_props->method);
  EXPECT_EQ(IPAddress::kFamilyIPv6, ipv6_props->address_family);
  EXPECT_EQ("fd00::1", ipv6_props->address);
  EXPECT_EQ(64, ipv6_props->subnet_prefix);
  EXPECT_EQ(2, ipv6_props->inclusion_list.size());
  EXPECT_EQ("fd00::/64", ipv6_props->inclusion_list[0]);
  EXPECT_EQ("fd02::/96", ipv6_props->inclusion_list[1]);
  EXPECT_FALSE(ipv6_props->default_route);
  // Original MTU value is too small for IPv6, so should be reset.
  EXPECT_EQ(0, ipv6_props->mtu);
  ASSERT_EQ(3, ipv6_props->dns_servers.size());
  EXPECT_EQ("1.1.1.1", ipv6_props->dns_servers[0]);
  EXPECT_EQ("4.4.4.4", ipv6_props->dns_servers[1]);
  EXPECT_EQ("2.2.2.2", ipv6_props->dns_servers[2]);

  // Update MTU value.
  config["tun_mtu"] = "1500";
  invoke(false);
  ASSERT_NE(ipv4_props, nullptr);
  ASSERT_NE(ipv6_props, nullptr);
  EXPECT_EQ(1500, ipv4_props->mtu);
  EXPECT_EQ(1500, ipv6_props->mtu);
}

TEST_F(OpenVPNDriverTest, InitOptionsNoHost) {
  Error error;
  std::vector<std::vector<std::string>> options;
  driver_->InitOptions(&options, &error);
  EXPECT_EQ(Error::kInvalidArguments, error.type());
  EXPECT_TRUE(options.empty());
}

TEST_F(OpenVPNDriverTest, InitOptionsNoPrimaryHost) {
  Error error;
  std::vector<std::vector<std::string>> options;
  std::vector<std::string> extra_hosts{"1.2.3.4"};
  SetArgArray(kOpenVPNExtraHostsProperty, extra_hosts);
  driver_->InitOptions(&options, &error);
  EXPECT_EQ(Error::kInvalidArguments, error.type());
  EXPECT_TRUE(options.empty());
}

TEST_F(OpenVPNDriverTest, InitOptions) {
  static const char kHost[] = "192.168.2.254";
  static const char kTLSAuthContents[] = "SOME-RANDOM-CONTENTS\n";
  static const char kID[] = "TestPKCS11ID";
  static const char kKU0[] = "00";
  static const char kKU1[] = "01";
  static const char kTLSVersionMin[] = "1.2";
  base::FilePath empty_cert;
  SetArg(kProviderHostProperty, kHost);
  SetArg(kOpenVPNTLSAuthContentsProperty, kTLSAuthContents);
  SetArg(kOpenVPNClientCertIdProperty, kID);
  SetArg(kOpenVPNRemoteCertKUProperty,
         std::string(kKU0) + " " + std::string(kKU1));
  SetArg(kOpenVPNTLSVersionMinProperty, kTLSVersionMin);
  driver_->rpc_task_.reset(new RpcTask(&control_, this));
  driver_->interface_name_ = kInterfaceName;
  EXPECT_CALL(*management_server_, Start(_, _)).WillOnce(Return(true));
  EXPECT_CALL(manager_, IsConnected()).WillOnce(Return(false));

  Error error;
  std::vector<std::vector<std::string>> options;
  driver_->InitOptions(&options, &error);
  EXPECT_TRUE(error.IsSuccess());
  EXPECT_EQ(std::vector<std::string>{"client"}, options[0]);
  ExpectInFlags(options, {"remote", kHost});
  ExpectInFlags(options, {"setenv", kRpcTaskPathVariable,
                          RpcTaskMockAdaptor::kRpcId.value()});
  ExpectInFlags(options, {"dev", kInterfaceName});
  EXPECT_EQ(kInterfaceName, driver_->interface_name_);
  ASSERT_FALSE(driver_->tls_auth_file_.empty());
  ExpectInFlags(options, {"tls-auth", driver_->tls_auth_file_.value()});
  std::string contents;
  EXPECT_TRUE(base::ReadFileToString(driver_->tls_auth_file_, &contents));
  EXPECT_EQ(kTLSAuthContents, contents);
  ExpectInFlags(options, {"pkcs11-id", kID});
  ExpectInFlags(options, {"ca", OpenVPNDriver::kDefaultCACertificates});
  ExpectInFlags(options, {"syslog"});
  ExpectNotInFlags(options, "auth-user-pass");
  ExpectInFlags(options, {"remote-cert-ku", kKU0, kKU1});
  ExpectInFlags(options, {"tls-version-min", kTLSVersionMin});
}

TEST_F(OpenVPNDriverTest, InitOptionsHostWithPort) {
  SetArg(kProviderHostProperty, "v.com:1234");
  driver_->rpc_task_.reset(new RpcTask(&control_, this));
  driver_->interface_name_ = kInterfaceName;
  EXPECT_CALL(*management_server_, Start(_, _)).WillOnce(Return(true));
  EXPECT_CALL(manager_, IsConnected()).WillOnce(Return(false));

  Error error;
  std::vector<std::vector<std::string>> options;
  driver_->InitOptions(&options, &error);
  EXPECT_TRUE(error.IsSuccess());
  ExpectInFlags(options, {"remote", "v.com", "1234"});
}

TEST_F(OpenVPNDriverTest, InitOptionsHostWithExtraHosts) {
  SetArg(kProviderHostProperty, "1.2.3.4");
  SetArgArray(kOpenVPNExtraHostsProperty,
              {"abc.com:123", "127.0.0.1", "v.com:8000"});
  driver_->rpc_task_.reset(new RpcTask(&control_, this));
  driver_->interface_name_ = kInterfaceName;
  EXPECT_CALL(*management_server_, Start(_, _)).WillOnce(Return(true));
  EXPECT_CALL(manager_, IsConnected()).WillOnce(Return(false));

  Error error;
  std::vector<std::vector<std::string>> options;
  driver_->InitOptions(&options, &error);
  EXPECT_TRUE(error.IsSuccess());
  ExpectInFlags(options, {
                             "remote",
                             "1.2.3.4",
                         });
  ExpectInFlags(options, {"remote", "abc.com", "123"});
  ExpectInFlags(options, {"remote", "127.0.0.1"});
  ExpectInFlags(options, {"remote", "v.com", "8000"});
}

TEST_F(OpenVPNDriverTest, InitOptionsAdvanced) {
  SetArg(kProviderHostProperty, "example.com");
  SetArg(kOpenVPNAuthProperty, "MD5");
  SetArg(kOpenVPNCipherProperty, "AES-192-CBC");
  SetArg(kOpenVPNCompressProperty, "lzo");
  SetArg(kOpenVPNKeyDirectionProperty, "1");
  SetArg(kOpenVPNTLSAuthContentsProperty, "SOME-RANDOM-CONTENTS\n");

  driver_->rpc_task_.reset(new RpcTask(&control_, this));
  driver_->interface_name_ = kInterfaceName;
  EXPECT_CALL(*management_server_, Start(_, _)).WillOnce(Return(true));
  EXPECT_CALL(manager_, IsConnected()).WillOnce(Return(false));

  Error error;
  std::vector<std::vector<std::string>> options;
  driver_->InitOptions(&options, &error);
  EXPECT_TRUE(error.IsSuccess());
  ExpectInFlags(options, {"auth", "MD5"});
  ExpectInFlags(options, {"cipher", "AES-192-CBC"});
  ExpectInFlags(options, {"compress", "lzo"});
  ExpectInFlags(options, {"key-direction", "1"});
  ExpectInFlags(options, {"tls-auth", driver_->tls_auth_file_.value()});
  std::string contents;
  EXPECT_TRUE(base::ReadFileToString(driver_->tls_auth_file_, &contents));
  EXPECT_EQ("SOME-RANDOM-CONTENTS\n", contents);
}

TEST_F(OpenVPNDriverTest, InitCAOptions) {
  Error error;
  std::vector<std::vector<std::string>> options;
  EXPECT_TRUE(driver_->InitCAOptions(&options, &error));
  EXPECT_TRUE(error.IsSuccess());
  ExpectInFlags(options, {"ca", OpenVPNDriver::kDefaultCACertificates});

  base::FilePath empty_cert;
  options.clear();
  SetArg(kProviderHostProperty, "");

  const std::vector<std::string> kCaCertPEM{"---PEM CONTENTS---"};
  static const char kPEMCertfile[] = "/tmp/pem-cert";
  base::FilePath pem_cert(kPEMCertfile);
  EXPECT_CALL(*certificate_file_, CreatePEMFromStrings(kCaCertPEM))
      .WillOnce(Return(empty_cert))
      .WillOnce(Return(pem_cert));
  SetArgArray(kOpenVPNCaCertPemProperty, kCaCertPEM);

  // |empty_cert| should fail.
  error.Reset();
  EXPECT_FALSE(driver_->InitCAOptions(&options, &error));
  EXPECT_EQ(Error::kInvalidArguments, error.type());
  EXPECT_EQ("Unable to extract PEM CA certificates.", error.message());

  // |pem_cert| should succeed.
  error.Reset();
  options.clear();
  EXPECT_TRUE(driver_->InitCAOptions(&options, &error));
  ExpectInFlags(options, {"ca", kPEMCertfile});
  EXPECT_TRUE(error.IsSuccess());
}

TEST_F(OpenVPNDriverTest, InitCertificateVerifyOptions) {
  {
    Error error;
    std::vector<std::vector<std::string>> options;
    // No options supplied.
    driver_->InitCertificateVerifyOptions(&options);
    EXPECT_TRUE(options.empty());
  }
  const char kName[] = "x509-name";
  {
    Error error;
    std::vector<std::vector<std::string>> options;
    // With Name property alone, we should have the 1-parameter version of the
    // "x509-verify-name" parameter provided.
    SetArg(kOpenVPNVerifyX509NameProperty, kName);
    driver_->InitCertificateVerifyOptions(&options);
    ExpectInFlags(options, {"verify-x509-name", kName});
  }
  const char kType[] = "x509-type";
  {
    Error error;
    std::vector<std::vector<std::string>> options;
    // With both Name property and Type property set, we should have the
    // 2-parameter version of the "x509-verify-name" parameter provided.
    SetArg(kOpenVPNVerifyX509TypeProperty, kType);
    driver_->InitCertificateVerifyOptions(&options);
    ExpectInFlags(options, {"verify-x509-name", kName, kType});
  }
  {
    Error error;
    std::vector<std::vector<std::string>> options;
    // We should ignore the Type parameter if no Name parameter is specified.
    SetArg(kOpenVPNVerifyX509NameProperty, "");
    driver_->InitCertificateVerifyOptions(&options);
    EXPECT_TRUE(options.empty());
  }
}

TEST_F(OpenVPNDriverTest, InitClientAuthOptions) {
  static const char kTestValue[] = "foo";
  std::vector<std::vector<std::string>> options;

  // Assume user/password authentication.
  driver_->InitClientAuthOptions(&options);
  ExpectInFlags(options, {"auth-user-pass"});

  // Empty PKCS11 certificate id, no user/password.
  options.clear();
  RemoveStringArg(kOpenVPNUserProperty);
  SetArg(kOpenVPNClientCertIdProperty, "");
  driver_->InitClientAuthOptions(&options);
  ExpectInFlags(options, {"auth-user-pass"});
  ExpectNotInFlags(options, "pkcs11-id");

  // Non-empty PKCS11 certificate id, no user/password.
  options.clear();
  SetArg(kOpenVPNClientCertIdProperty, kTestValue);
  driver_->InitClientAuthOptions(&options);
  ExpectNotInFlags(options, "auth-user-pass");
  // The "--pkcs11-id" option is added in InitPKCS11Options(), not here.
  ExpectNotInFlags(options, "pkcs11-id");

  // PKCS11 certificate id available, AuthUserPass set.
  options.clear();
  SetArg(kOpenVPNAuthUserPassProperty, kTestValue);
  driver_->InitClientAuthOptions(&options);
  ExpectInFlags(options, {"auth-user-pass"});

  // PKCS11 certificate id available, User set.
  options.clear();
  RemoveStringArg(kOpenVPNAuthUserPassProperty);
  SetArg(kOpenVPNUserProperty, "user");
  driver_->InitClientAuthOptions(&options);
  ExpectInFlags(options, {"auth-user-pass"});
}

TEST_F(OpenVPNDriverTest, InitExtraCertOptions) {
  {
    Error error;
    std::vector<std::vector<std::string>> options;
    // No ExtraCertOptions supplied.
    EXPECT_TRUE(driver_->InitExtraCertOptions(&options, &error));
    EXPECT_TRUE(error.IsSuccess());
    EXPECT_TRUE(options.empty());
  }
  {
    Error error;
    std::vector<std::vector<std::string>> options;
    SetArgArray(kOpenVPNExtraCertPemProperty, std::vector<std::string>());
    // Empty ExtraCertOptions supplied.
    EXPECT_TRUE(driver_->InitExtraCertOptions(&options, &error));
    EXPECT_TRUE(error.IsSuccess());
    EXPECT_TRUE(options.empty());
  }
  const std::vector<std::string> kExtraCerts{"---PEM CONTENTS---"};
  SetArgArray(kOpenVPNExtraCertPemProperty, kExtraCerts);
  static const char kPEMCertfile[] = "/tmp/pem-cert";
  base::FilePath pem_cert(kPEMCertfile);
  EXPECT_CALL(*extra_certificates_file_, CreatePEMFromStrings(kExtraCerts))
      .WillOnce(Return(base::FilePath()))
      .WillOnce(Return(pem_cert));
  // CreatePemFromStrings fails.
  {
    Error error;
    std::vector<std::vector<std::string>> options;
    EXPECT_FALSE(driver_->InitExtraCertOptions(&options, &error));
    EXPECT_EQ(Error::kInvalidArguments, error.type());
    EXPECT_TRUE(options.empty());
  }
  // CreatePemFromStrings succeeds.
  {
    Error error;
    std::vector<std::vector<std::string>> options;
    EXPECT_TRUE(driver_->InitExtraCertOptions(&options, &error));
    EXPECT_TRUE(error.IsSuccess());
    ExpectInFlags(options, {"extra-certs", kPEMCertfile});
  }
}

TEST_F(OpenVPNDriverTest, InitPKCS11Options) {
  std::vector<std::vector<std::string>> options;
  driver_->InitPKCS11Options(&options);
  EXPECT_TRUE(options.empty());

  static const char kID[] = "TestPKCS11ID";
  SetArg(kOpenVPNClientCertIdProperty, kID);
  driver_->InitPKCS11Options(&options);
  ExpectInFlags(options, {"pkcs11-id", kID});
  ExpectInFlags(options, {"pkcs11-providers", "libchaps.so"});
}

TEST_F(OpenVPNDriverTest, InitManagementChannelOptionsServerFail) {
  std::vector<std::vector<std::string>> options;
  EXPECT_CALL(*management_server_, Start(GetSockets(), &options))
      .WillOnce(Return(false));
  Error error;
  EXPECT_FALSE(InitManagementChannelOptions(&options, &error));
  EXPECT_EQ(Error::kInternalError, error.type());
  EXPECT_EQ("Unable to setup management channel.", error.message());
}

TEST_F(OpenVPNDriverTest, InitManagementChannelOptionsOnline) {
  std::vector<std::vector<std::string>> options;
  EXPECT_CALL(*management_server_, Start(GetSockets(), &options))
      .WillOnce(Return(true));
  EXPECT_CALL(manager_, IsConnected()).WillOnce(Return(true));
  EXPECT_CALL(*management_server_, ReleaseHold());
  Error error;
  EXPECT_TRUE(InitManagementChannelOptions(&options, &error));
  EXPECT_TRUE(error.IsSuccess());
}

TEST_F(OpenVPNDriverTest, InitManagementChannelOptionsOffline) {
  std::vector<std::vector<std::string>> options;
  EXPECT_CALL(*management_server_, Start(GetSockets(), &options))
      .WillOnce(Return(true));
  EXPECT_CALL(manager_, IsConnected()).WillOnce(Return(false));
  EXPECT_CALL(*management_server_, ReleaseHold()).Times(0);
  Error error;
  EXPECT_TRUE(InitManagementChannelOptions(&options, &error));
  EXPECT_TRUE(error.IsSuccess());
}

TEST_F(OpenVPNDriverTest, InitLoggingOptions) {
  std::vector<std::vector<std::string>> options;
  bool vpn_logging = SLOG_IS_ON(VPN, 0);
  int verbose_level = ScopeLogger::GetInstance()->verbose_level();
  ScopeLogger::GetInstance()->set_verbose_level(0);

  ScopeLogger::GetInstance()->EnableScopesByName("-vpn");
  driver_->InitLoggingOptions(&options);
  ASSERT_EQ(1, options.size());
  EXPECT_EQ(std::vector<std::string>{"syslog"}, options[0]);
  ScopeLogger::GetInstance()->EnableScopesByName("+vpn");
  options.clear();
  driver_->InitLoggingOptions(&options);
  ExpectInFlags(options, {"verb", "3"});
  ScopeLogger::GetInstance()->EnableScopesByName("-vpn");
  SetArg("OpenVPN.Verb", "2");
  options.clear();
  driver_->InitLoggingOptions(&options);
  ExpectInFlags(options, {"verb", "2"});
  ScopeLogger::GetInstance()->EnableScopesByName("+vpn");
  SetArg("OpenVPN.Verb", "1");
  options.clear();
  driver_->InitLoggingOptions(&options);
  ExpectInFlags(options, {"verb", "1"});

  if (!vpn_logging) {
    ScopeLogger::GetInstance()->EnableScopesByName("-vpn");
  }
  ScopeLogger::GetInstance()->set_verbose_level(verbose_level);
}

TEST_F(OpenVPNDriverTest, AppendRemoteOption) {
  std::vector<std::vector<std::string>> options;
  driver_->AppendRemoteOption("1.2.3.4:1234", &options);
  driver_->AppendRemoteOption("abc.com", &options);
  driver_->AppendRemoteOption("1.0.0.1:8080", &options);
  ASSERT_EQ(3, options.size());
  std::vector<std::string> expected_value0{"remote", "1.2.3.4", "1234"};
  std::vector<std::string> expected_value1{"remote", "abc.com"};
  std::vector<std::string> expected_value2{"remote", "1.0.0.1", "8080"};
  EXPECT_EQ(expected_value0, options[0]);
  EXPECT_EQ(expected_value1, options[1]);
  EXPECT_EQ(expected_value2, options[2]);
}

TEST_F(OpenVPNDriverTest, AppendValueOption) {
  std::vector<std::vector<std::string>> options;
  EXPECT_FALSE(
      driver_->AppendValueOption("OpenVPN.UnknownProperty", kOption, &options));
  EXPECT_TRUE(options.empty());

  SetArg(kProperty, "");
  EXPECT_FALSE(driver_->AppendValueOption(kProperty, kOption, &options));
  EXPECT_TRUE(options.empty());

  SetArg(kProperty, kValue);
  SetArg(kProperty2, kValue2);
  EXPECT_TRUE(driver_->AppendValueOption(kProperty, kOption, &options));
  EXPECT_TRUE(driver_->AppendValueOption(kProperty2, kOption2, &options));
  EXPECT_EQ(2, options.size());
  std::vector<std::string> expected_value{kOption, kValue};
  EXPECT_EQ(expected_value, options[0]);
  std::vector<std::string> expected_value2{kOption2, kValue2};
  EXPECT_EQ(expected_value2, options[1]);
}

TEST_F(OpenVPNDriverTest, AppendDelimitedValueOption) {
  std::vector<std::vector<std::string>> options;
  EXPECT_FALSE(driver_->AppendDelimitedValueOption("OpenVPN.UnknownProperty",
                                                   kOption, ' ', &options));
  EXPECT_TRUE(options.empty());

  SetArg(kProperty, "");
  EXPECT_FALSE(
      driver_->AppendDelimitedValueOption(kProperty, kOption, ' ', &options));
  EXPECT_TRUE(options.empty());

  std::string kConcatenatedValues(std::string(kValue) + " " +
                                  std::string(kValue2));
  SetArg(kProperty, kConcatenatedValues);
  SetArg(kProperty2, kConcatenatedValues);
  EXPECT_TRUE(
      driver_->AppendDelimitedValueOption(kProperty, kOption, ':', &options));
  EXPECT_TRUE(
      driver_->AppendDelimitedValueOption(kProperty2, kOption2, ' ', &options));
  EXPECT_EQ(2, options.size());
  std::vector<std::string> expected_value{kOption, kConcatenatedValues};
  EXPECT_EQ(expected_value, options[0]);
  std::vector<std::string> expected_value2{kOption2, kValue, kValue2};
  EXPECT_EQ(expected_value2, options[1]);
}

TEST_F(OpenVPNDriverTest, AppendFlag) {
  std::vector<std::vector<std::string>> options;
  EXPECT_FALSE(
      driver_->AppendFlag("OpenVPN.UnknownProperty", kOption, &options));
  EXPECT_TRUE(options.empty());

  SetArg(kProperty, "");
  SetArg(kProperty2, kValue2);
  EXPECT_TRUE(driver_->AppendFlag(kProperty, kOption, &options));
  EXPECT_TRUE(driver_->AppendFlag(kProperty2, kOption2, &options));
  EXPECT_EQ(2, options.size());
  EXPECT_EQ(std::vector<std::string>{kOption}, options[0]);
  EXPECT_EQ(std::vector<std::string>{kOption2}, options[1]);
}

TEST_F(OpenVPNDriverTest, FailService) {
  static const char kErrorDetails[] = "Bad password.";
  SetEventHandler(&event_handler_);
  EXPECT_CALL(event_handler_,
              OnDriverFailure(Service::kFailureConnect, Eq(kErrorDetails)));
  driver_->FailService(Service::kFailureConnect, kErrorDetails);
}

TEST_F(OpenVPNDriverTest, Cleanup) {
  // Ensure no crash.
  driver_->Cleanup();

  driver_->ipv4_properties_ = std::make_unique<IPConfig::Properties>();
  const int kPID = 123456;
  driver_->pid_ = kPID;
  driver_->rpc_task_.reset(new RpcTask(&control_, this));
  driver_->interface_name_ = kInterfaceName;
  driver_->ipv4_properties_->address = "1.2.3.4";
  base::FilePath tls_auth_file;
  EXPECT_TRUE(base::CreateTemporaryFile(&tls_auth_file));
  EXPECT_FALSE(tls_auth_file.empty());
  EXPECT_TRUE(base::PathExists(tls_auth_file));
  driver_->tls_auth_file_ = tls_auth_file;
  // Stop will be called twice -- once by Cleanup and once by the destructor.
  EXPECT_CALL(*management_server_, Stop()).Times(2);
  EXPECT_CALL(process_manager_, UpdateExitCallback(kPID, _));
  EXPECT_CALL(process_manager_, StopProcessAndBlock(kPID));
  driver_->Cleanup();
  EXPECT_EQ(0, driver_->pid_);
  EXPECT_EQ(nullptr, driver_->rpc_task_);
  EXPECT_TRUE(driver_->interface_name_.empty());
  EXPECT_FALSE(base::PathExists(tls_auth_file));
  EXPECT_TRUE(driver_->tls_auth_file_.empty());
  EXPECT_EQ(nullptr, driver_->ipv4_properties_);
}

TEST_F(OpenVPNDriverTest, SpawnOpenVPN) {
  SetupLSBRelease();

  EXPECT_FALSE(driver_->SpawnOpenVPN());

  static const char kHost[] = "192.168.2.254";
  SetArg(kProviderHostProperty, kHost);
  driver_->interface_name_ = "tun0";
  driver_->rpc_task_.reset(new RpcTask(&control_, this));
  EXPECT_CALL(*management_server_, Start(_, _))
      .Times(2)
      .WillRepeatedly(Return(true));
  EXPECT_CALL(manager_, IsConnected()).Times(2).WillRepeatedly(Return(false));

  const int kPID = 234678;
  EXPECT_CALL(process_manager_, StartProcessInMinijail)
      .WillOnce(Return(-1))
      .WillOnce(Return(kPID));
  EXPECT_FALSE(driver_->SpawnOpenVPN());
  EXPECT_TRUE(driver_->SpawnOpenVPN());
  EXPECT_EQ(kPID, driver_->pid_);
}

TEST_F(OpenVPNDriverTest, OnOpenVPNDied) {
  const int kPID = 99999;
  SetEventHandler(&event_handler_);
  driver_->pid_ = kPID;
  EXPECT_CALL(event_handler_, OnDriverFailure(_, _));
  EXPECT_CALL(process_manager_, StopProcess(_)).Times(0);
  driver_->OnOpenVPNDied(2);
  EXPECT_EQ(0, driver_->pid_);
}

TEST_F(OpenVPNDriverTest, Disconnect) {
  SetEventHandler(&event_handler_);
  driver_->Disconnect();
  EXPECT_FALSE(driver_->event_handler_);
}

TEST_F(OpenVPNDriverTest, OnConnectTimeout) {
  SetEventHandler(&event_handler_);
  EXPECT_CALL(event_handler_, OnDriverFailure(Service::kFailureConnect, _));
  driver_->OnConnectTimeout();
  EXPECT_FALSE(driver_->event_handler_);
}

TEST_F(OpenVPNDriverTest, OnConnectTimeoutResolve) {
  SetEventHandler(&event_handler_);
  SetClientState(OpenVPNManagementServer::kStateResolve);
  EXPECT_CALL(event_handler_, OnDriverFailure(Service::kFailureDNSLookup, _));
  driver_->OnConnectTimeout();
  EXPECT_FALSE(driver_->event_handler_);
}

TEST_F(OpenVPNDriverTest, OnReconnectingUnknown) {
  SetEventHandler(&event_handler_);
  EXPECT_CALL(event_handler_, OnDriverReconnecting(GetDefaultConnectTimeout()));
  driver_->OnReconnecting(OpenVPNDriver::kReconnectReasonUnknown);
}

TEST_F(OpenVPNDriverTest, OnReconnectingTLSError) {
  SetEventHandler(&event_handler_);

  EXPECT_CALL(event_handler_,
              OnDriverReconnecting(GetReconnectOfflineTimeout()));
  driver_->OnReconnecting(OpenVPNDriver::kReconnectReasonOffline);

  EXPECT_CALL(event_handler_,
              OnDriverReconnecting(GetReconnectTLSErrorTimeout()));
  driver_->OnReconnecting(OpenVPNDriver::kReconnectReasonTLSError);
}

TEST_F(OpenVPNDriverTest, InitPropertyStore) {
  // Quick test property store initialization.
  PropertyStore store;
  driver_->InitPropertyStore(&store);
  const std::string kUser = "joe";
  Error error;
  store.SetStringProperty(kOpenVPNUserProperty, kUser, &error);
  EXPECT_TRUE(error.IsSuccess());
  EXPECT_EQ(kUser, GetArgs()->Lookup<std::string>(kOpenVPNUserProperty, ""));
}

TEST_F(OpenVPNDriverTest, PassphraseRequired) {
  PropertyStore store;
  driver_->InitPropertyStore(&store);
  KeyValueStore props = GetProviderProperties(store);
  EXPECT_TRUE(props.Lookup<bool>(kPassphraseRequiredProperty, false));

  SetArg(kOpenVPNPasswordProperty, "random-password");
  props = GetProviderProperties(store);
  EXPECT_FALSE(props.Lookup<bool>(kPassphraseRequiredProperty, true));
  // This parameter should be write-only.
  EXPECT_FALSE(props.Contains<std::string>(kOpenVPNPasswordProperty));

  SetArg(kOpenVPNPasswordProperty, "");
  props = GetProviderProperties(store);
  EXPECT_TRUE(props.Lookup<bool>(kPassphraseRequiredProperty, false));

  SetArg(kOpenVPNTokenProperty, "random-token");
  props = GetProviderProperties(store);
  EXPECT_FALSE(props.Lookup<bool>(kPassphraseRequiredProperty, true));
  // This parameter should be write-only.
  EXPECT_FALSE(props.Contains<std::string>(kOpenVPNTokenProperty));
}

TEST_F(OpenVPNDriverTest, GetCommandLineArgs) {
  SetupLSBRelease();

  const std::vector<std::string> actual = driver_->GetCommandLineArgs();
  ASSERT_EQ("--config", actual[0]);
  // Config file path will be empty since SpawnOpenVPN() hasn't been called.
  ASSERT_EQ("", actual[1]);
  ASSERT_EQ("--setenv", actual[2]);
  ASSERT_EQ("UV_PLAT", actual[3]);
  ASSERT_EQ("Chromium OS", actual[4]);
  ASSERT_EQ("--setenv", actual[5]);
  ASSERT_EQ("UV_PLAT_REL", actual[6]);
  ASSERT_EQ("2202.0", actual[7]);

  EXPECT_EQ(0, base::WriteFile(lsb_release_file_, "", 0));
  // Still returns --config arg and path value.
  EXPECT_EQ(2, driver_->GetCommandLineArgs().size());
}

TEST_F(OpenVPNDriverTest, OnDefaultPhysicalServiceEvent) {
  SetEventHandler(&event_handler_);
  EXPECT_CALL(*management_server_, IsStarted()).WillRepeatedly(Return(true));

  // Switch from Online service -> no service.  VPN should be put on hold.
  EXPECT_CALL(*management_server_, IsStarted()).WillRepeatedly(Return(true));
  EXPECT_CALL(*management_server_, Hold());
  driver_->OnDefaultPhysicalServiceEvent(
      VPNDriver::kDefaultPhysicalServiceDown);
  Mock::VerifyAndClearExpectations(management_server_);

  // Switch from no service -> Online.  VPN should release the hold.
  EXPECT_CALL(*management_server_, IsStarted()).WillRepeatedly(Return(true));
  EXPECT_CALL(*management_server_, ReleaseHold());
  driver_->OnDefaultPhysicalServiceEvent(VPNDriver::kDefaultPhysicalServiceUp);
  Mock::VerifyAndClearExpectations(management_server_);

  // Switch from Online service -> another Online service.  VPN should restart
  // immediately.
  EXPECT_CALL(*management_server_, IsStarted()).WillRepeatedly(Return(true));
  EXPECT_CALL(*management_server_, Restart());
  driver_->OnDefaultPhysicalServiceEvent(
      VPNDriver::kDefaultPhysicalServiceChanged);

  // Do nothing when management server is not started.
  EXPECT_CALL(*management_server_, IsStarted()).WillRepeatedly(Return(false));
  driver_->OnDefaultPhysicalServiceEvent(
      VPNDriver::kDefaultPhysicalServiceDown);
  Mock::VerifyAndClearExpectations(management_server_);
}

TEST_F(OpenVPNDriverTest, GetReconnectTimeout) {
  EXPECT_EQ(GetDefaultConnectTimeout(),
            GetReconnectTimeout(OpenVPNDriver::kReconnectReasonUnknown));
  EXPECT_EQ(GetReconnectOfflineTimeout(),
            GetReconnectTimeout(OpenVPNDriver::kReconnectReasonOffline));
  EXPECT_EQ(GetReconnectTLSErrorTimeout(),
            GetReconnectTimeout(OpenVPNDriver::kReconnectReasonTLSError));
}

TEST_F(OpenVPNDriverTest, WriteConfigFile) {
  const char kOption0[] = "option0";
  const char kOption1[] = "option1";
  const char kOption1Argument0[] = "option1-argument0";
  const char kOption2[] = "option2";
  const char kOption2Argument0[] = "option2-argument0\n\t\"'\\";
  const char kOption2Argument0Transformed[] = "option2-argument0 \t\\\"'\\\\";
  const char kOption2Argument1[] = "option2-argument1 space";
  std::vector<std::vector<std::string>> options{
      {kOption0},
      {kOption1, kOption1Argument0},
      {kOption2, kOption2Argument0, kOption2Argument1}};
  base::FilePath config_directory(
      temporary_directory_.GetPath().Append(kOpenVPNConfigDirectory));
  base::FilePath config_file;
  EXPECT_FALSE(base::PathExists(config_directory));
  EXPECT_TRUE(driver_->WriteConfigFile(options, &config_file));
  EXPECT_TRUE(base::PathExists(config_directory));
  EXPECT_TRUE(base::PathExists(config_file));
  EXPECT_TRUE(config_directory.IsParent(config_file));

  std::string config_contents;
  EXPECT_TRUE(base::ReadFileToString(config_file, &config_contents));
  auto expected_config_contents = base::StringPrintf(
      "%s\n%s %s\n%s \"%s\" \"%s\"\n", kOption0, kOption1, kOption1Argument0,
      kOption2, kOption2Argument0Transformed, kOption2Argument1);
  EXPECT_EQ(expected_config_contents, config_contents);
}

}  // namespace shill
