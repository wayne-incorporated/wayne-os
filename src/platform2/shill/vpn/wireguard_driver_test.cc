// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/vpn/wireguard_driver.h"

#include <map>
#include <memory>
#include <set>
#include <utility>

#include <base/containers/flat_set.h>
#include <base/files/scoped_file.h>
#include <base/files/scoped_temp_dir.h>
#include <base/files/file_util.h>
#include <chromeos/dbus/service_constants.h>
#include <gtest/gtest.h>

#include "shill/metrics.h"
#include "shill/mock_control.h"
#include "shill/mock_device_info.h"
#include "shill/mock_manager.h"
#include "shill/mock_metrics.h"
#include "shill/net/mock_process_manager.h"
#include "shill/store/fake_store.h"
#include "shill/store/property_store.h"
#include "shill/test_event_dispatcher.h"
#include "shill/vpn/fake_vpn_util.h"
#include "shill/vpn/mock_vpn_driver.h"
#include "shill/vpn/vpn_provider.h"

namespace shill {

using testing::_;
using testing::AllOf;
using testing::DoAll;
using testing::HasSubstr;
using testing::Mock;
using testing::NiceMock;
using testing::Not;
using testing::Return;
using testing::WithArg;

// Expose necessary private members of WireGuardDriver for testing.
class WireGuardDriverTestPeer {
 public:
  explicit WireGuardDriverTestPeer(WireGuardDriver* driver) : driver_(driver) {
    driver->vpn_util_ = std::make_unique<FakeVPNUtil>();
  }

  const Stringmaps& peers() { return driver_->peers_; }

  const base::ScopedFD& config_fd() { return driver_->config_fd_; }

 private:
  std::unique_ptr<WireGuardDriver> driver_;
};

namespace {

constexpr pid_t kWireGuardToolsPid = 12346;
const char kIfName[] = "wg0";
constexpr int kIfIndex = 123;

// Randomly generated key for testing.
constexpr char kPrivateKey1[] = "gOL/kVF88Mdr7rVM2Fz91UgyAW4L8iYogU/M+9hlKmM=";
constexpr char kPrivateKey2[] = "wARBVZOPBWo7OoyHLfv2mDgFxYJ3S6uc9lIOpRiGqVI=";

// Consistent with the properties set in
// WireGuardDriverTest::InitializePropertyStore().
const char kExpectedConfigFileContents[] = R"([Interface]
PrivateKey=gOL/kVF88Mdr7rVM2Fz91UgyAW4L8iYogU/M+9hlKmM=
FwMark=0x4500

[Peer]
PublicKey=public-key-1
PresharedKey=preshared-key-1
Endpoint=10.0.1.1:12345
AllowedIPs=192.168.1.2/32,192.168.2.0/24
PersistentKeepalive=10

[Peer]
PublicKey=public-key-2
Endpoint=10.0.1.2:12345
AllowedIPs=192.168.1.2/32,fd00:0:0:0:1::/128

[Peer]
PublicKey=public-key-3
Endpoint=10.0.1.3:12345
AllowedIPs=fd00:0:0:0:1::/128,fd00:0:0:2::/64
)";

static constexpr char kIPv4Address[] = "10.12.14.2";
static constexpr char kIPv6Address1[] = "fd00:0:0:0:1::";
static constexpr char kIPv6Address2[] = "fd00:0:0:2::";
static constexpr char kWrongIPAddress[] = "10.12.14..2";

constexpr char kWireGuardIPAddress[] = "WireGuard.IPAddress";

class WireGuardDriverTest : public testing::Test {
 public:
  WireGuardDriverTest()
      : manager_(&control_, &dispatcher_, &metrics_), device_info_(&manager_) {
    ResetDriver();
    manager_.set_mock_device_info(&device_info_);
    SetFakeKeyGenerator();
  }

 protected:
  // Useful in storage-related tests.
  void ResetDriver() {
    driver_ = new WireGuardDriver(&manager_, &process_manager_);
    driver_test_peer_.reset(new WireGuardDriverTestPeer(driver_));
    property_store_.reset(new PropertyStore());
    driver_->InitPropertyStore(property_store_.get());
  }

  void InitializePropertyStore() {
    Error err;
    property_store_->SetStringProperty(kWireGuardPrivateKey, kPrivateKey1,
                                       &err);
    property_store_->SetStringsProperty(
        kWireGuardIPAddress,
        std::vector<std::string>{kIPv4Address, kIPv6Address1}, &err);
    property_store_->SetStringmapsProperty(
        kWireGuardPeers,
        {
            {{kWireGuardPeerPublicKey, "public-key-1"},
             {kWireGuardPeerPresharedKey, "preshared-key-1"},
             {kWireGuardPeerPersistentKeepalive, "10"},
             {kWireGuardPeerEndpoint, "10.0.1.1:12345"},
             {kWireGuardPeerAllowedIPs, "192.168.1.2/32,192.168.2.0/24"}},
            {{kWireGuardPeerPublicKey, "public-key-2"},
             {kWireGuardPeerEndpoint, "10.0.1.2:12345"},
             {kWireGuardPeerAllowedIPs, "192.168.1.2/32,fd00:0:0:0:1::/128"}},
            {{kWireGuardPeerPublicKey, "public-key-3"},
             {kWireGuardPeerEndpoint, "10.0.1.3:12345"},
             {kWireGuardPeerAllowedIPs, "fd00:0:0:0:1::/128,fd00:0:0:2::/64"}},
        },
        &err);
  }

  // Whenever the driver asks for calculating a public key, just echoes the
  // input back.
  // TODO(jiejiang): Consider returning a different key to avoid missing the
  // failure that keys are misused.
  void SetFakeKeyGenerator() {
    EXPECT_CALL(process_manager_,
                StartProcessInMinijailWithPipes(
                    _, base::FilePath("/usr/bin/wg"),
                    std::vector<std::string>{"pubkey"}, _,
                    AllOf(MinijailOptionsMatchUserGroup("vpn", "vpn"),
                          MinijailOptionsMatchCapMask(0u),
                          MinijailOptionsMatchInheritSupplementaryGroup(true)),
                    _, _))
        .WillRepeatedly([](const base::Location&, const base::FilePath&,
                           const std::vector<std::string>&,
                           const std::map<std::string, std::string>&,
                           const ProcessManager::MinijailOptions&,
                           base::OnceCallback<void(int)>,
                           struct std_file_descriptors std_fds) {
          CHECK(std_fds.stdin_fd);
          CHECK(std_fds.stdout_fd);
          int echo_pipe[2];
          CHECK_EQ(pipe(echo_pipe), 0);
          *std_fds.stdin_fd = echo_pipe[1];
          *std_fds.stdout_fd = echo_pipe[0];
          return 0;
        });
  }

  void InvokeConnectAsyncKernel() {
    driver_->ConnectAsync(&driver_event_handler_);
    EXPECT_CALL(device_info_, CreateWireGuardInterface(kIfName, _, _))
        .WillOnce([this](const std::string&,
                         DeviceInfo::LinkReadyCallback link_ready_cb,
                         base::OnceClosure failure_cb) {
          this->link_ready_callback_ = std::move(link_ready_cb);
          this->create_kernel_link_failed_callback_ = std::move(failure_cb);
          return true;
        });
    dispatcher_.DispatchPendingEvents();
  }

  void InvokeLinkReady() {
    // wireguard-tools should be invoked on interface ready.
    std::vector<std::string> args;
    base::flat_set<int> fds;
    constexpr uint64_t kExpectedCapMask = CAP_TO_MASK(CAP_NET_ADMIN);
    EXPECT_CALL(process_manager_,
                StartProcessInMinijail(
                    _, base::FilePath("/usr/bin/wg"), _, _,
                    AllOf(MinijailOptionsMatchUserGroup("vpn", "vpn"),
                          MinijailOptionsMatchCapMask(kExpectedCapMask),
                          MinijailOptionsMatchInheritSupplementaryGroup(true)),
                    _))
        .WillOnce(
            [this, &args, &fds](
                const base::Location&, const base::FilePath&,
                const std::vector<std::string>& arguments,
                const std::map<std::string, std::string>&,
                const MockProcessManager::MinijailOptions& minijail_options,
                base::OnceCallback<void(int)> exit_callback) {
              wireguard_tools_exit_callback_ = std::move(exit_callback);
              args = arguments;
              fds = minijail_options.preserved_nonstd_fds;
              return kWireGuardToolsPid;
            });
    std::move(link_ready_callback_).Run(kIfName, kIfIndex);

    EXPECT_EQ(args[0], "setconf");
    EXPECT_EQ(args[1], kIfName);
    EXPECT_EQ(fds.size(), 1);
    EXPECT_EQ(args[2], base::StringPrintf("/proc/self/fd/%d", *fds.begin()));
    config_file_path_ = base::FilePath(args[2]);
    EXPECT_TRUE(base::PathExists(config_file_path_));
  }

  void ExpectCallMetrics(Metrics::VpnWireGuardKeyPairSource key_pair_source,
                         int peers_num,
                         Metrics::VpnWireGuardAllowedIPsType allowed_ips_type) {
    EXPECT_CALL(metrics_, SendEnumToUMA(Metrics::kMetricVpnDriver,
                                        Metrics::kVpnDriverWireGuard));
    EXPECT_CALL(metrics_,
                SendEnumToUMA(Metrics::kMetricVpnWireGuardKeyPairSource,
                              key_pair_source));
    EXPECT_CALL(metrics_,
                SendToUMA(Metrics::kMetricVpnWireGuardPeersNum, peers_num));
    EXPECT_CALL(metrics_,
                SendEnumToUMA(Metrics::kMetricVpnWireGuardAllowedIPsType,
                              allowed_ips_type));
  }

  MockControl control_;
  EventDispatcherForTest dispatcher_;
  MockMetrics metrics_;
  MockProcessManager process_manager_;
  MockManager manager_;
  NiceMock<MockDeviceInfo> device_info_;
  FakeStore fake_store_;
  std::unique_ptr<PropertyStore> property_store_;
  MockVPNDriverEventHandler driver_event_handler_;
  WireGuardDriver* driver_;  // owned by driver_test_peer_
  std::unique_ptr<WireGuardDriverTestPeer> driver_test_peer_;

  base::OnceCallback<void(int)> wireguard_exit_callback_;
  base::OnceCallback<void(int)> wireguard_tools_exit_callback_;
  DeviceInfo::LinkReadyCallback link_ready_callback_;
  base::OnceClosure create_kernel_link_failed_callback_;
  base::FilePath config_file_path_;
};

TEST_F(WireGuardDriverTest, VPNType) {
  EXPECT_EQ(driver_->vpn_type(), VPNType::kWireGuard);
}

TEST_F(WireGuardDriverTest, ConnectFlowKernel) {
  InitializePropertyStore();
  InvokeConnectAsyncKernel();
  InvokeLinkReady();

  // Checks config file content.
  std::string contents;
  CHECK(base::ReadFileToString(config_file_path_, &contents));
  EXPECT_EQ(contents, kExpectedConfigFileContents);

  // Configuration done.
  EXPECT_CALL(driver_event_handler_, OnDriverConnected(kIfName, kIfIndex));
  std::move(wireguard_tools_exit_callback_).Run(0);

  // Checks that the config file has been deleted.
  EXPECT_FALSE(driver_test_peer_->config_fd().is_valid());

  // Checks IPProperties.
  const auto ipv4_properties = driver_->GetIPv4Properties();
  ASSERT_NE(ipv4_properties, nullptr);
  EXPECT_EQ(ipv4_properties->address_family, IPAddress::kFamilyIPv4);
  EXPECT_EQ(ipv4_properties->address, kIPv4Address);
  EXPECT_EQ(ipv4_properties->subnet_prefix, 32);
  EXPECT_THAT(ipv4_properties->inclusion_list,
              testing::UnorderedElementsAre(
                  // We do not dedup so this entry appears twice.
                  "192.168.1.2/32", "192.168.1.2/32", "192.168.2.0/24"));

  const auto ipv6_properties = driver_->GetIPv6Properties();
  ASSERT_NE(ipv6_properties, nullptr);
  EXPECT_EQ(ipv6_properties->address_family, IPAddress::kFamilyIPv6);
  EXPECT_EQ(ipv6_properties->subnet_prefix, 128);
  EXPECT_EQ(ipv6_properties->address, kIPv6Address1);
  EXPECT_THAT(
      ipv6_properties->inclusion_list,
      testing::UnorderedElementsAre(
          // We do not dedup so this entry appears twice.
          "fd00:0:0:0:1::/128", "fd00:0:0:0:1::/128", "fd00:0:0:2::/64"));

  // Disconnect.
  EXPECT_CALL(device_info_, DeleteInterface(kIfIndex));
  driver_->Disconnect();
}

TEST_F(WireGuardDriverTest, WireGuardToolsFailed) {
  InitializePropertyStore();
  InvokeConnectAsyncKernel();
  InvokeLinkReady();

  // Configuration failed.
  EXPECT_CALL(driver_event_handler_, OnDriverFailure(_, _));
  std::move(wireguard_tools_exit_callback_).Run(1);

  // Checks that the config file has been deleted.
  EXPECT_FALSE(driver_test_peer_->config_fd().is_valid());
}

TEST_F(WireGuardDriverTest, PropertyStoreAndConfigFile) {
  std::string contents;
  Error err;
  InitializePropertyStore();

  // Save & load should not lose any information.
  const std::string kStorageId = "wireguard-test";
  driver_->Save(&fake_store_, kStorageId, /*save_credentials=*/true);
  ResetDriver();
  driver_->Load(&fake_store_, kStorageId);
  InvokeConnectAsyncKernel();
  InvokeLinkReady();
  CHECK(base::ReadFileToString(config_file_path_, &contents));
  EXPECT_EQ(contents, kExpectedConfigFileContents);
  ExpectCallMetrics(Metrics::kVpnWireGuardKeyPairSourceUserInput, 3,
                    Metrics::kVpnWireGuardAllowedIPsTypeNoDefaultRoute);
  std::move(wireguard_tools_exit_callback_).Run(0);
  Mock::VerifyAndClearExpectations(&metrics_);
  driver_->Disconnect();

  // Checks reading properties. Private keys and preshared keys should not be
  // readable.
  KeyValueStore provider;
  EXPECT_TRUE(property_store_->GetKeyValueStoreProperty(kProviderProperty,
                                                        &provider, &err));
  EXPECT_FALSE(provider.Contains<std::string>(kWireGuardPrivateKey));
  EXPECT_TRUE(provider.Contains<std::string>(kWireGuardPublicKey));
  EXPECT_EQ(provider.Get<Strings>(kWireGuardIPAddress),
            (std::vector<std::string>{kIPv4Address, kIPv6Address1}));
  EXPECT_EQ(
      provider.Get<Stringmaps>(kWireGuardPeers),
      (Stringmaps{
          {{kWireGuardPeerPublicKey, "public-key-1"},
           {kWireGuardPeerPersistentKeepalive, "10"},
           {kWireGuardPeerEndpoint, "10.0.1.1:12345"},
           {kWireGuardPeerAllowedIPs, "192.168.1.2/32,192.168.2.0/24"}},
          {{kWireGuardPeerPublicKey, "public-key-2"},
           {kWireGuardPeerPersistentKeepalive, ""},
           {kWireGuardPeerEndpoint, "10.0.1.2:12345"},
           {kWireGuardPeerAllowedIPs, "192.168.1.2/32,fd00:0:0:0:1::/128"}},
          {{kWireGuardPeerPublicKey, "public-key-3"},
           {kWireGuardPeerPersistentKeepalive, ""},
           {kWireGuardPeerEndpoint, "10.0.1.3:12345"},
           {kWireGuardPeerAllowedIPs, "fd00:0:0:0:1::/128,fd00:0:0:2::/64"}},
      }));

  // Setting peers without touching PresharedKey property should leave it
  // unchanged.
  property_store_->SetStringmapsProperty(
      kWireGuardPeers,
      {
          {{kWireGuardPeerPublicKey, "public-key-1"},
           {kWireGuardPeerPersistentKeepalive, "10"},
           {kWireGuardPeerEndpoint, "10.0.1.1:12345"},
           {kWireGuardPeerAllowedIPs, "192.168.1.2/32,192.168.2.0/24"}},
          {{kWireGuardPeerPublicKey, "public-key-2"},
           {kWireGuardPeerEndpoint, "10.0.1.2:12345"},
           {kWireGuardPeerAllowedIPs, "192.168.1.2/32,fd00:0:0:0:1::/128"}},
          {{kWireGuardPeerPublicKey, "public-key-3"},
           {kWireGuardPeerEndpoint, "10.0.1.3:12345"},
           {kWireGuardPeerAllowedIPs, "fd00:0:0:0:1::/128,fd00:0:0:2::/64"}},
      },
      &err);
  InvokeConnectAsyncKernel();
  InvokeLinkReady();
  CHECK(base::ReadFileToString(config_file_path_, &contents));
  EXPECT_EQ(contents, kExpectedConfigFileContents);
  driver_->Disconnect();

  // Setting peers with an empty PublicKey property should be rejected and the
  // current peers will not be modified.
  property_store_->SetStringmapsProperty(
      kWireGuardPeers,
      {
          {{kWireGuardPeerPublicKey, "public-key-1"},
           {kWireGuardPeerPersistentKeepalive, "10"},
           {kWireGuardPeerEndpoint, "10.0.1.1:12345"},
           {kWireGuardPeerAllowedIPs, "192.168.1.2/32,192.168.2.0/24"}},
          {{kWireGuardPeerPublicKey, ""},
           {kWireGuardPeerEndpoint, "10.0.1.2:12345"},
           {kWireGuardPeerAllowedIPs, "192.168.1.2/32,fd00:0:0:0:1::/128"}},
      },
      &err);
  EXPECT_TRUE(err.IsFailure());
  InvokeConnectAsyncKernel();
  InvokeLinkReady();
  CHECK(base::ReadFileToString(config_file_path_, &contents));
  EXPECT_EQ(contents, kExpectedConfigFileContents);
  driver_->Disconnect();

  // Setting peers with a duplicated PublicKey property should be rejected and
  // the current peers will not be modified.
  property_store_->SetStringmapsProperty(
      kWireGuardPeers,
      {
          {{kWireGuardPeerPublicKey, "public-key-1"},
           {kWireGuardPeerPersistentKeepalive, "10"},
           {kWireGuardPeerEndpoint, "10.0.1.1:12345"},
           {kWireGuardPeerAllowedIPs, "192.168.1.2/32,192.168.2.0/24"}},
          {{kWireGuardPeerPublicKey, "public-key-1"},
           {kWireGuardPeerEndpoint, "10.0.1.2:12345"},
           {kWireGuardPeerAllowedIPs, "192.168.1.2/32,fd00:0:0:0:1::/128"}},
      },
      &err);
  EXPECT_TRUE(err.IsFailure());
  InvokeConnectAsyncKernel();
  InvokeLinkReady();
  CHECK(base::ReadFileToString(config_file_path_, &contents));
  EXPECT_EQ(contents, kExpectedConfigFileContents);
  driver_->Disconnect();

  // Setting peers with an empty PresharedKey property should clear the
  // PresharedKey of that peer.
  property_store_->SetStringmapsProperty(
      kWireGuardPeers,
      {
          {{kWireGuardPeerPublicKey, "public-key-1"},
           {kWireGuardPeerPresharedKey, ""},
           {kWireGuardPeerPersistentKeepalive, "10"},
           {kWireGuardPeerEndpoint, "10.0.1.1:12345"},
           {kWireGuardPeerAllowedIPs, "192.168.1.2/32,192.168.2.0/24"}},
          {{kWireGuardPeerPublicKey, "public-key-2"},
           {kWireGuardPeerEndpoint, "10.0.1.2:12345"},
           {kWireGuardPeerAllowedIPs, "192.168.1.2/32,fd00:0:0:0:1::/128"}},
      },
      &err);
  InvokeConnectAsyncKernel();
  InvokeLinkReady();
  CHECK(base::ReadFileToString(config_file_path_, &contents));
  EXPECT_THAT(contents, Not(HasSubstr("PresharedKey=")));

  // Clears the private key, changes the number of peers, and add 0.0.0.0/0 as
  // its allowed ips. The reported metrics should be changed.
  property_store_->SetStringProperty(kWireGuardPrivateKey, "", &err);
  property_store_->SetStringmapsProperty(
      kWireGuardPeers,
      {
          {{kWireGuardPeerPublicKey, "public-key-1"},
           {kWireGuardPeerPresharedKey, ""},
           {kWireGuardPeerPersistentKeepalive, "10"},
           {kWireGuardPeerEndpoint, "10.0.1.1:12345"},
           {kWireGuardPeerAllowedIPs, "0.0.0.0/0"}},
      },
      &err);
  driver_->Save(&fake_store_, kStorageId, /*save_credentials=*/true);
  InvokeConnectAsyncKernel();
  InvokeLinkReady();
  ExpectCallMetrics(Metrics::kVpnWireGuardKeyPairSourceSoftwareGenerated, 1,
                    Metrics::kVpnWireGuardAllowedIPsTypeHasDefaultRoute);
  std::move(wireguard_tools_exit_callback_).Run(0);
  Mock::VerifyAndClearExpectations(&metrics_);
}

TEST_F(WireGuardDriverTest, UnloadCredentials) {
  InitializePropertyStore();
  driver_->UnloadCredentials();
  const auto args = driver_->const_args();
  EXPECT_FALSE(args->Contains<std::string>(kWireGuardPrivateKey));
  EXPECT_EQ(
      driver_test_peer_->peers(),
      (Stringmaps{
          {{kWireGuardPeerPublicKey, "public-key-1"},
           {kWireGuardPeerPresharedKey, ""},
           {kWireGuardPeerPersistentKeepalive, "10"},
           {kWireGuardPeerEndpoint, "10.0.1.1:12345"},
           {kWireGuardPeerAllowedIPs, "192.168.1.2/32,192.168.2.0/24"}},
          {{kWireGuardPeerPublicKey, "public-key-2"},
           {kWireGuardPeerPresharedKey, ""},
           {kWireGuardPeerEndpoint, "10.0.1.2:12345"},
           {kWireGuardPeerAllowedIPs, "192.168.1.2/32,fd00:0:0:0:1::/128"}},
          {{kWireGuardPeerPublicKey, "public-key-3"},
           {kWireGuardPeerPresharedKey, ""},
           {kWireGuardPeerEndpoint, "10.0.1.3:12345"},
           {kWireGuardPeerAllowedIPs, "fd00:0:0:0:1::/128,fd00:0:0:2::/64"}},
      }));
}

TEST_F(WireGuardDriverTest, KeyPairGeneration) {
  Error err;
  const std::string kStorageId = "wireguard-test";

  auto assert_pubkey_is = [&](const std::string& key) {
    KeyValueStore provider;
    ASSERT_TRUE(property_store_->GetKeyValueStoreProperty(kProviderProperty,
                                                          &provider, &err));
    ASSERT_EQ(provider.Get<std::string>(kWireGuardPublicKey), key);
  };
  auto assert_pubkey_not_empty = [&]() {
    KeyValueStore provider;
    ASSERT_TRUE(property_store_->GetKeyValueStoreProperty(kProviderProperty,
                                                          &provider, &err));
    ASSERT_FALSE(provider.Get<std::string>(kWireGuardPublicKey).empty());
  };

  driver_->Save(&fake_store_, kStorageId, /*save_credentials=*/true);
  assert_pubkey_not_empty();

  ResetDriver();
  driver_->Load(&fake_store_, kStorageId);
  assert_pubkey_not_empty();

  property_store_->SetStringProperty(kWireGuardPrivateKey, kPrivateKey1, &err);
  driver_->Save(&fake_store_, kStorageId, /*save_credentials=*/true);
  assert_pubkey_is(kPrivateKey1);

  property_store_->SetStringProperty(kWireGuardPrivateKey, "", &err);
  driver_->Save(&fake_store_, kStorageId, /*save_credentials=*/true);
  assert_pubkey_not_empty();

  property_store_->SetStringProperty(kWireGuardPrivateKey, kPrivateKey2, &err);
  driver_->Save(&fake_store_, kStorageId, /*save_credentials=*/true);
  assert_pubkey_is(kPrivateKey2);
}

// Checks interface cleanup on timeout.
TEST_F(WireGuardDriverTest, OnConnectTimeout) {
  InitializePropertyStore();

  // Link is not created.
  InvokeConnectAsyncKernel();
  EXPECT_CALL(driver_event_handler_, OnDriverFailure(_, _));
  driver_->OnConnectTimeout();

  // Link is created by kernel.
  InvokeConnectAsyncKernel();
  InvokeLinkReady();
  EXPECT_CALL(driver_event_handler_, OnDriverFailure(_, _));
  EXPECT_CALL(device_info_, DeleteInterface(kIfIndex));
  driver_->OnConnectTimeout();
}

// Checks interface cleanup on disconnect before connected. Different with
// OnConnectTimeout, disconnect will not trigger an OnDriverFailure callback.
TEST_F(WireGuardDriverTest, DisconnectBeforeConnected) {
  InitializePropertyStore();

  // Link is not created.
  InvokeConnectAsyncKernel();
  driver_->Disconnect();

  // Link is created by kernel.
  InvokeConnectAsyncKernel();
  InvokeLinkReady();
  EXPECT_CALL(device_info_, DeleteInterface(kIfIndex));
  driver_->Disconnect();
}

TEST_F(WireGuardDriverTest, GetIPProperties) {
  Error err;
  auto create_kernel_link = [&]() {
    InvokeConnectAsyncKernel();
    InvokeLinkReady();
    std::move(wireguard_tools_exit_callback_).Run(0);
  };
  auto assert_ip_address_is = [&](const Strings& value) {
    KeyValueStore provider;
    ASSERT_TRUE(property_store_->GetKeyValueStoreProperty(kProviderProperty,
                                                          &provider, &err));
    ASSERT_EQ(provider.Get<Strings>(kWireGuardIPAddress), value);
  };

  // The case that the user configures only one IPv4 address.
  InitializePropertyStore();
  property_store_->SetStringsProperty(
      kWireGuardIPAddress, std::vector<std::string>{kIPv4Address}, &err);
  create_kernel_link();
  assert_ip_address_is(std::vector<std::string>{kIPv4Address});
  auto ipv4_properties = driver_->GetIPv4Properties();
  ASSERT_NE(ipv4_properties, nullptr);
  EXPECT_EQ(ipv4_properties->address_family, IPAddress::kFamilyIPv4);
  EXPECT_EQ(ipv4_properties->address, kIPv4Address);
  EXPECT_EQ(ipv4_properties->subnet_prefix, 32);
  auto ipv6_properties = driver_->GetIPv6Properties();
  ASSERT_EQ(ipv6_properties, nullptr);
  driver_->Disconnect();

  // The case that the user configures only one IPv6 address.
  InitializePropertyStore();
  property_store_->SetStringsProperty(
      kWireGuardIPAddress, std::vector<std::string>{kIPv6Address1}, &err);
  create_kernel_link();
  assert_ip_address_is(std::vector<std::string>{kIPv6Address1});
  ipv4_properties = driver_->GetIPv4Properties();
  ASSERT_EQ(ipv4_properties, nullptr);
  ipv6_properties = driver_->GetIPv6Properties();
  ASSERT_NE(ipv6_properties, nullptr);
  EXPECT_EQ(ipv6_properties->address_family, IPAddress::kFamilyIPv6);
  EXPECT_EQ(ipv6_properties->address, kIPv6Address1);
  EXPECT_EQ(ipv6_properties->subnet_prefix, 128);
  driver_->Disconnect();

  // The case that the user configures one IPv4 address and one IPv6 address.
  InitializePropertyStore();
  // kWireguardIPAddress that contains one IPv4 address and one IPv6 address
  // is set by default.
  create_kernel_link();
  assert_ip_address_is(std::vector<std::string>{kIPv4Address, kIPv6Address1});
  ipv4_properties = driver_->GetIPv4Properties();
  ASSERT_NE(ipv4_properties, nullptr);
  EXPECT_EQ(ipv4_properties->address_family, IPAddress::kFamilyIPv4);
  EXPECT_EQ(ipv4_properties->subnet_prefix, 32);
  EXPECT_EQ(ipv4_properties->address, kIPv4Address);
  ipv6_properties = driver_->GetIPv6Properties();
  ASSERT_NE(ipv6_properties, nullptr);
  EXPECT_EQ(ipv6_properties->address_family, IPAddress::kFamilyIPv6);
  EXPECT_EQ(ipv6_properties->subnet_prefix, 128);
  EXPECT_EQ(ipv6_properties->address, kIPv6Address1);
  driver_->Disconnect();

  // The case that the user configures two IPv6 addresses.
  InitializePropertyStore();
  property_store_->SetStringsProperty(
      kWireGuardIPAddress,
      std::vector<std::string>{kIPv6Address1, kIPv6Address2}, &err);
  create_kernel_link();
  assert_ip_address_is(std::vector<std::string>{kIPv6Address1, kIPv6Address2});
  ipv4_properties = driver_->GetIPv4Properties();
  ASSERT_EQ(ipv4_properties, nullptr);
  ipv6_properties = driver_->GetIPv6Properties();
  ASSERT_NE(ipv6_properties, nullptr);
  EXPECT_EQ(ipv6_properties->address_family, IPAddress::kFamilyIPv6);
  EXPECT_EQ(ipv6_properties->subnet_prefix, 128);
  EXPECT_EQ(ipv6_properties->address, kIPv6Address1);
  driver_->Disconnect();

  // The case that the user configures one wrong format address.
  InitializePropertyStore();
  property_store_->SetStringsProperty(
      kWireGuardIPAddress, std::vector<std::string>{kWrongIPAddress}, &err);
  EXPECT_CALL(driver_event_handler_, OnDriverFailure(_, _));
  create_kernel_link();
  assert_ip_address_is(std::vector<std::string>{kWrongIPAddress});
  ASSERT_EQ(driver_->GetIPv4Properties(), nullptr);
  ASSERT_EQ(driver_->GetIPv6Properties(), nullptr);
  driver_->Disconnect();
}
}  // namespace
}  // namespace shill
