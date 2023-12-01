// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/vpn/l2tp_ipsec_driver.h"

#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <chromeos/dbus/service_constants.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "shill/mock_control.h"
#include "shill/mock_manager.h"
#include "shill/mock_metrics.h"
#include "shill/net/mock_process_manager.h"
#include "shill/store/fake_store.h"
#include "shill/test_event_dispatcher.h"
#include "shill/vpn/fake_vpn_util.h"
#include "shill/vpn/ipsec_connection.h"
#include "shill/vpn/l2tp_connection.h"
#include "shill/vpn/mock_vpn_driver.h"
#include "shill/vpn/vpn_connection_under_test.h"
#include "shill/vpn/vpn_provider.h"

namespace shill {

class L2TPIPsecDriverUnderTest : public L2TPIPsecDriver {
 public:
  L2TPIPsecDriverUnderTest(Manager* manager, ProcessManager* process_manager)
      : L2TPIPsecDriver(manager, process_manager) {}

  L2TPIPsecDriverUnderTest(const L2TPIPsecDriverUnderTest&) = delete;
  L2TPIPsecDriverUnderTest& operator=(const L2TPIPsecDriverUnderTest&) = delete;

  VPNConnectionUnderTest* ipsec_connection() const {
    return dynamic_cast<VPNConnectionUnderTest*>(ipsec_connection_.get());
  }

  IPsecConnection::Config* ipsec_config() const { return ipsec_config_.get(); }
  L2TPConnection::Config* l2tp_config() const { return l2tp_config_.get(); }

 private:
  std::unique_ptr<VPNConnection> CreateIPsecConnection(
      std::unique_ptr<IPsecConnection::Config> config,
      std::unique_ptr<VPNConnection::Callbacks> callbacks,
      std::unique_ptr<VPNConnection> l2tp_connection,
      DeviceInfo* device_info,
      EventDispatcher* dispatcher,
      ProcessManager* process_manager) override {
    ipsec_config_ = std::move(config);
    auto ipsec_connection = std::make_unique<VPNConnectionUnderTest>(
        std::move(callbacks), dispatcher);
    EXPECT_CALL(*ipsec_connection, OnConnect());
    return ipsec_connection;
  }

  std::unique_ptr<VPNConnection> CreateL2TPConnection(
      std::unique_ptr<L2TPConnection::Config> config,
      ControlInterface* control_interface,
      DeviceInfo* device_info,
      EventDispatcher* dispatcher,
      ProcessManager* process_manager) override {
    l2tp_config_ = std::move(config);
    return std::make_unique<VPNConnectionUnderTest>(nullptr, dispatcher);
  }

  std::unique_ptr<IPsecConnection::Config> ipsec_config_;
  std::unique_ptr<L2TPConnection::Config> l2tp_config_;
};

namespace {

using testing::_;

class L2TPIPsecDriverTest : public testing::Test {
 public:
  L2TPIPsecDriverTest() : manager_(&control_, &dispatcher_, &metrics_) {
    ResetDriver();
  }

 protected:
  void ResetDriver() {
    driver_.reset(new L2TPIPsecDriverUnderTest(&manager_, &process_manager_));
    store_.reset(new PropertyStore());
    driver_->InitPropertyStore(store_.get());
    Error unused_error;
    // The ProviderHost property is needed in most of the tests.
    store_->SetStringProperty(kProviderHostProperty, "127.0.0.1",
                              &unused_error);
  }

  void InvokeAndVerifyConnectAsync() {
    const auto timeout = driver_->ConnectAsync(&event_handler_);
    EXPECT_NE(timeout, VPNDriver::kTimeoutNone);

    dispatcher_.task_environment().RunUntilIdle();
    EXPECT_NE(driver_->ipsec_connection(), nullptr);
    EXPECT_NE(driver_->ipsec_config(), nullptr);
    EXPECT_NE(driver_->l2tp_config(), nullptr);
  }

  void ExpectEndReasonMetricsReported(Service::ConnectFailure failure) {
    EXPECT_CALL(
        metrics_,
        SendEnumToUMA(Metrics::kMetricVpnL2tpIpsecSwanctlEndReason,
                      Metrics::ConnectFailureToServiceErrorEnum(failure)));
  }

  // Dependencies used by |driver_|.
  MockControl control_;
  EventDispatcherForTest dispatcher_;
  MockMetrics metrics_;
  MockManager manager_;
  MockProcessManager process_manager_;

  // Other objects used in the tests.
  FakeStore fake_store_;
  MockVPNDriverEventHandler event_handler_;
  std::unique_ptr<PropertyStore> store_;

  std::unique_ptr<L2TPIPsecDriverUnderTest> driver_;
};

TEST_F(L2TPIPsecDriverTest, VPNType) {
  EXPECT_EQ(driver_->vpn_type(), VPNType::kL2TPIPsec);
}

TEST_F(L2TPIPsecDriverTest, ConnectAndDisconnect) {
  // Sets psk and password to verify metrics.
  Error unused_error;
  store_->SetStringProperty(kL2TPIPsecPskProperty, "x", &unused_error);
  store_->SetStringProperty(kL2TPIPsecPasswordProperty, "y", &unused_error);
  store_->SetStringProperty(kL2TPIPsecTunnelGroupProperty, "z", &unused_error);
  InvokeAndVerifyConnectAsync();

  // Connected.
  const std::string kIfName = "ppp0";
  constexpr int kIfIndex = 123;
  driver_->ipsec_connection()->TriggerConnected(kIfName, kIfIndex, {}, {});
  EXPECT_CALL(event_handler_, OnDriverConnected(kIfName, kIfIndex));
  EXPECT_CALL(metrics_, SendEnumToUMA(Metrics::kMetricVpnDriver,
                                      Metrics::kVpnDriverL2tpIpsec));
  EXPECT_CALL(metrics_,
              SendEnumToUMA(Metrics::kMetricVpnRemoteAuthenticationType,
                            Metrics::kVpnRemoteAuthenticationTypeL2tpIpsecPsk));
  EXPECT_CALL(
      metrics_,
      SendEnumToUMA(
          Metrics::kMetricVpnUserAuthenticationType,
          Metrics::kVpnUserAuthenticationTypeL2tpIpsecUsernamePassword));
  EXPECT_CALL(metrics_,
              SendEnumToUMA(Metrics::kMetricVpnL2tpIpsecTunnelGroupUsage,
                            Metrics::kVpnL2tpIpsecTunnelGroupUsageYes));

  dispatcher_.DispatchPendingEvents();

  // Triggers disconnect.
  ExpectEndReasonMetricsReported(Service::kFailureDisconnect);
  driver_->Disconnect();
  EXPECT_CALL(*driver_->ipsec_connection(), OnDisconnect());
  dispatcher_.DispatchPendingEvents();

  // Stopped.
  driver_->ipsec_connection()->TriggerStopped();
  dispatcher_.DispatchPendingEvents();
  EXPECT_EQ(driver_->ipsec_connection(), nullptr);
}

TEST_F(L2TPIPsecDriverTest, ConnectTimeout) {
  InvokeAndVerifyConnectAsync();

  EXPECT_CALL(event_handler_, OnDriverFailure(Service::kFailureConnect, _));
  ExpectEndReasonMetricsReported(Service::kFailureConnect);
  EXPECT_CALL(*driver_->ipsec_connection(), OnDisconnect());
  driver_->OnConnectTimeout();
  dispatcher_.DispatchPendingEvents();

  driver_->ipsec_connection()->TriggerStopped();
  dispatcher_.DispatchPendingEvents();
  EXPECT_EQ(driver_->ipsec_connection(), nullptr);
}

TEST_F(L2TPIPsecDriverTest, ConnectingFailure) {
  InvokeAndVerifyConnectAsync();

  EXPECT_CALL(event_handler_, OnDriverFailure(Service::kFailureInternal, _));
  ExpectEndReasonMetricsReported(Service::kFailureInternal);
  driver_->ipsec_connection()->TriggerFailure(Service::kFailureInternal, "");
  dispatcher_.DispatchPendingEvents();

  driver_->ipsec_connection()->TriggerStopped();
  dispatcher_.DispatchPendingEvents();
  EXPECT_EQ(driver_->ipsec_connection(), nullptr);
}

TEST_F(L2TPIPsecDriverTest, ConnectedFailure) {
  InvokeAndVerifyConnectAsync();

  // Makes it connected.
  driver_->ipsec_connection()->TriggerConnected("ifname", 123, {}, {});
  dispatcher_.DispatchPendingEvents();

  EXPECT_CALL(event_handler_, OnDriverFailure(Service::kFailureInternal, _));
  ExpectEndReasonMetricsReported(Service::kFailureInternal);
  driver_->ipsec_connection()->TriggerFailure(Service::kFailureInternal, "");
  dispatcher_.DispatchPendingEvents();

  driver_->ipsec_connection()->TriggerStopped();
  dispatcher_.DispatchPendingEvents();
  EXPECT_EQ(driver_->ipsec_connection(), nullptr);
}

TEST_F(L2TPIPsecDriverTest, DisconnectOnSuspend) {
  InvokeAndVerifyConnectAsync();

  // Makes it connected.
  driver_->ipsec_connection()->TriggerConnected("ifname", 123, {}, {});
  dispatcher_.DispatchPendingEvents();

  EXPECT_CALL(event_handler_, OnDriverFailure(Service::kFailureDisconnect, _));
  ExpectEndReasonMetricsReported(Service::kFailureDisconnect);
  driver_->OnBeforeSuspend(base::DoNothing());
}

TEST_F(L2TPIPsecDriverTest, DisconnectOnDefaultPhysicalServiceDown) {
  InvokeAndVerifyConnectAsync();

  // Makes it connected.
  driver_->ipsec_connection()->TriggerConnected("ifname", 123, {}, {});
  dispatcher_.DispatchPendingEvents();

  EXPECT_CALL(event_handler_, OnDriverFailure(Service::kFailureDisconnect, _));
  ExpectEndReasonMetricsReported(Service::kFailureDisconnect);
  driver_->OnDefaultPhysicalServiceEvent(
      VPNDriver::kDefaultPhysicalServiceDown);
}

TEST_F(L2TPIPsecDriverTest, DisconnectOnDefaultPhysicalServiceChanged) {
  InvokeAndVerifyConnectAsync();

  // Makes it connected.
  driver_->ipsec_connection()->TriggerConnected("ifname", 123, {}, {});
  dispatcher_.DispatchPendingEvents();

  EXPECT_CALL(event_handler_, OnDriverFailure(Service::kFailureDisconnect, _));
  ExpectEndReasonMetricsReported(Service::kFailureDisconnect);
  driver_->OnDefaultPhysicalServiceEvent(
      VPNDriver::kDefaultPhysicalServiceChanged);
}

TEST_F(L2TPIPsecDriverTest, PropertyStoreAndConfig) {
  Error unused_error;
  const std::string kStorageId = "l2tp-ipsec-test";

  // Sets all the properties exposed in service-api.txt (dbus-constants.h).
  const std::string kHost = "127.0.0.1";
  const std::string kCertId = "cert-id";
  const std::string kCertSlot = "123";
  const std::string kCertPin = "1111";
  const std::string kPSK = "";
  const std::vector<std::string> kCACertPEM = {"aaa", "bbb", "ccc"};
  const std::string kTunnelGroup = "group";
  const std::string kXauthUser = "xauth-user";
  const std::string kXauthPassword = "xauth-password";
  const std::string kPPPUser = "ppp-user";
  const std::string kPPPPassword = "ppp-password";
  const std::string kUseLoginPassword = "true";
  store_->SetStringProperty(kProviderHostProperty, kHost, &unused_error);
  store_->SetStringProperty(kL2TPIPsecClientCertIdProperty, kCertId,
                            &unused_error);
  store_->SetStringProperty(kL2TPIPsecClientCertSlotProperty, kCertSlot,
                            &unused_error);
  store_->SetStringProperty(kL2TPIPsecPinProperty, kCertPin, &unused_error);
  store_->SetStringProperty(kL2TPIPsecPskProperty, kPSK, &unused_error);
  store_->SetStringsProperty(kL2TPIPsecCaCertPemProperty, kCACertPEM,
                             &unused_error);
  store_->SetStringProperty(kL2TPIPsecTunnelGroupProperty, kTunnelGroup,
                            &unused_error);
  store_->SetStringProperty(kL2TPIPsecXauthUserProperty, kXauthUser,
                            &unused_error);
  store_->SetStringProperty(kL2TPIPsecXauthPasswordProperty, kXauthPassword,
                            &unused_error);
  store_->SetStringProperty(kL2TPIPsecUserProperty, kPPPUser, &unused_error);
  store_->SetStringProperty(kL2TPIPsecPasswordProperty, kPPPPassword,
                            &unused_error);
  store_->SetStringProperty(kL2TPIPsecUseLoginPasswordProperty,
                            kUseLoginPassword, &unused_error);

  // Makes the driver save and reload the properties.
  driver_->Save(&fake_store_, kStorageId, /*save_credentials=*/true);
  ResetDriver();
  driver_->Load(&fake_store_, kStorageId);

  // Triggers ConnectAsync() and verifies the configs.
  InvokeAndVerifyConnectAsync();
  const auto* ipsec_config = driver_->ipsec_config();
  EXPECT_EQ(ipsec_config->remote, kHost);
  EXPECT_EQ(ipsec_config->ca_cert_pem_strings, kCACertPEM);
  EXPECT_EQ(ipsec_config->client_cert_id, kCertId);
  EXPECT_EQ(ipsec_config->client_cert_slot, kCertSlot);
  EXPECT_EQ(ipsec_config->psk, std::nullopt);
  EXPECT_EQ(ipsec_config->xauth_user, kXauthUser);
  EXPECT_EQ(ipsec_config->xauth_password, kXauthPassword);
  EXPECT_EQ(ipsec_config->tunnel_group, kTunnelGroup);
  EXPECT_EQ(ipsec_config->local_proto_port, "17/1701");
  EXPECT_EQ(ipsec_config->remote_proto_port, "17/1701");

  const auto* l2tp_config = driver_->l2tp_config();
  EXPECT_EQ(l2tp_config->remote_ip, kHost);
  EXPECT_EQ(l2tp_config->refuse_pap, false);
  EXPECT_EQ(l2tp_config->require_auth, true);
  EXPECT_EQ(l2tp_config->require_chap, true);
  EXPECT_EQ(l2tp_config->length_bit, true);
  EXPECT_EQ(l2tp_config->lcp_echo, true);
  EXPECT_EQ(l2tp_config->user, kPPPUser);
  EXPECT_EQ(l2tp_config->password, kPPPPassword);
  EXPECT_EQ(l2tp_config->use_login_password, true);
}

TEST_F(L2TPIPsecDriverTest, GetProvider) {
  Error unused_error;
  {
    KeyValueStore props;
    ResetDriver();
    store_->SetStringProperty(kL2TPIPsecClientCertIdProperty, "",
                              &unused_error);
    EXPECT_TRUE(store_->GetKeyValueStoreProperty(kProviderProperty, &props,
                                                 &unused_error));
    EXPECT_TRUE(props.Lookup<bool>(kPassphraseRequiredProperty, false));
    EXPECT_TRUE(props.Lookup<bool>(kL2TPIPsecPskRequiredProperty, false));
  }
  {
    KeyValueStore props;
    ResetDriver();
    store_->SetStringProperty(kL2TPIPsecClientCertIdProperty, "some-cert-id",
                              &unused_error);
    EXPECT_TRUE(store_->GetKeyValueStoreProperty(kProviderProperty, &props,
                                                 &unused_error));
    EXPECT_TRUE(props.Lookup<bool>(kPassphraseRequiredProperty, false));
    EXPECT_FALSE(props.Lookup<bool>(kL2TPIPsecPskRequiredProperty, true));
  }
  {
    KeyValueStore props;
    ResetDriver();
    store_->SetStringProperty(kL2TPIPsecPasswordProperty, "random-password",
                              &unused_error);
    store_->SetStringProperty(kL2TPIPsecPskProperty, "random-psk",
                              &unused_error);
    EXPECT_TRUE(store_->GetKeyValueStoreProperty(kProviderProperty, &props,
                                                 &unused_error));
    EXPECT_FALSE(props.Lookup<bool>(kPassphraseRequiredProperty, true));
    EXPECT_FALSE(props.Lookup<bool>(kL2TPIPsecPskRequiredProperty, true));
    EXPECT_FALSE(props.Contains<std::string>(kL2TPIPsecPasswordProperty));
  }
}

}  // namespace
}  // namespace shill
