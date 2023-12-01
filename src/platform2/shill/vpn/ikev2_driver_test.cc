// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/vpn/ikev2_driver.h"

#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "shill/mock_control.h"
#include "shill/mock_manager.h"
#include "shill/mock_metrics.h"
#include "shill/net/mock_process_manager.h"
#include "shill/store/fake_store.h"
#include "shill/test_event_dispatcher.h"

#include "shill/vpn/ipsec_connection.h"
#include "shill/vpn/mock_vpn_driver.h"
#include "shill/vpn/vpn_connection_under_test.h"
#include "shill/vpn/vpn_provider.h"

namespace shill {

class IKEv2DriverUnderTest : public IKEv2Driver {
 public:
  IKEv2DriverUnderTest(Manager* manager, ProcessManager* process_manager)
      : IKEv2Driver(manager, process_manager) {}

  IKEv2DriverUnderTest(const IKEv2DriverUnderTest&) = delete;
  IKEv2DriverUnderTest& operator=(const IKEv2DriverUnderTest&) = delete;

  VPNConnectionUnderTest* ipsec_connection() const {
    return dynamic_cast<VPNConnectionUnderTest*>(ipsec_connection_.get());
  }

  IPsecConnection::Config* ipsec_config() const { return ipsec_config_.get(); }

 private:
  std::unique_ptr<VPNConnection> CreateIPsecConnection(
      std::unique_ptr<IPsecConnection::Config> config,
      std::unique_ptr<VPNConnection::Callbacks> callbacks,
      DeviceInfo* device_info,
      EventDispatcher* dispatcher,
      ProcessManager* process_manager) override {
    ipsec_config_ = std::move(config);
    auto ipsec_connection = std::make_unique<VPNConnectionUnderTest>(
        std::move(callbacks), dispatcher);
    EXPECT_CALL(*ipsec_connection, OnConnect());
    return ipsec_connection;
  }

  std::unique_ptr<IPsecConnection::Config> ipsec_config_;
};

namespace {

using testing::_;

class IKEv2DriverTest : public testing::Test {
 public:
  IKEv2DriverTest() : manager_(&control_, &dispatcher_, &metrics_) {
    ResetDriver();
  }

 protected:
  void ResetDriver() {
    driver_.reset(new IKEv2DriverUnderTest(&manager_, &process_manager_));
    store_.reset(new PropertyStore());
    driver_->InitPropertyStore(store_.get());
    Error unused_error;
    // Set the PSK property by default.
    store_->SetStringProperty(kIKEv2AuthenticationTypeProperty,
                              kIKEv2AuthenticationTypePSK, &unused_error);
    store_->SetStringProperty(kIKEv2PskProperty, "psk", &unused_error);
  }

  void InvokeAndVerifyConnectAsync() {
    const auto timeout = driver_->ConnectAsync(&event_handler_);
    EXPECT_NE(timeout, VPNDriver::kTimeoutNone);

    dispatcher_.task_environment().RunUntilIdle();
    EXPECT_NE(driver_->ipsec_connection(), nullptr);
    EXPECT_NE(driver_->ipsec_config(), nullptr);
  }

  void ExpectEndReasonMetricsReported(Service::ConnectFailure failure) {
    EXPECT_CALL(
        metrics_,
        SendEnumToUMA(Metrics::kMetricVpnIkev2EndReason,
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

  std::unique_ptr<IKEv2DriverUnderTest> driver_;
};

TEST_F(IKEv2DriverTest, VPNType) {
  EXPECT_EQ(driver_->vpn_type(), VPNType::kIKEv2);
}

TEST_F(IKEv2DriverTest, ConnectAndDisconnect) {
  Error unused_error;
  store_->SetStringProperty(kIKEv2AuthenticationTypeProperty,
                            kIKEv2AuthenticationTypePSK, &unused_error);
  InvokeAndVerifyConnectAsync();

  // Connected.
  const std::string kIfName = "xfrm0";
  constexpr int kIfIndex = 123;
  driver_->ipsec_connection()->TriggerConnected(kIfName, kIfIndex, {}, {});
  EXPECT_CALL(event_handler_, OnDriverConnected(kIfName, kIfIndex));
  EXPECT_CALL(metrics_, SendEnumToUMA(Metrics::kMetricVpnDriver,
                                      Metrics::kVpnDriverIKEv2));
  EXPECT_CALL(metrics_,
              SendEnumToUMA(Metrics::kMetricVpnIkev2AuthenticationType,
                            Metrics::kVpnIpsecAuthenticationTypePsk));
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

TEST_F(IKEv2DriverTest, ConnectTimeout) {
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

TEST_F(IKEv2DriverTest, ConnectingFailure) {
  InvokeAndVerifyConnectAsync();

  EXPECT_CALL(event_handler_, OnDriverFailure(Service::kFailureInternal, _));
  ExpectEndReasonMetricsReported(Service::kFailureInternal);
  driver_->ipsec_connection()->TriggerFailure(Service::kFailureInternal, "");
  dispatcher_.DispatchPendingEvents();

  driver_->ipsec_connection()->TriggerStopped();
  dispatcher_.DispatchPendingEvents();
  EXPECT_EQ(driver_->ipsec_connection(), nullptr);
}

TEST_F(IKEv2DriverTest, ConnectedFailure) {
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

// TODO(b/210064468): Add tests for default service change and suspend events.

TEST_F(IKEv2DriverTest, PropertyStoreAndConfig) {
  Error unused_error;
  const std::string kStorageId = "ikev2-test";

  const std::string kHost = "127.0.0.1";
  const std::string kCertId = "cert-id";
  const std::string kCertSlot = "123";
  const std::string kPSK = "preshared-key";
  const std::vector<std::string> kCACertPEM = {"aaa", "bbb", "ccc"};
  const std::string kEAPIdentity = "eap-identity";
  const std::string kEAPPassword = "eap-password";
  const std::string kLocalId = "local-id";
  const std::string kRemoteId = "remote-id";

  // Set to PSK auth, save and load, and then check the generated config file.
  {
    store_->SetStringProperty(kProviderHostProperty, kHost, &unused_error);
    store_->SetStringProperty(kIKEv2AuthenticationTypeProperty,
                              kIKEv2AuthenticationTypePSK, &unused_error);
    store_->SetStringProperty(kIKEv2PskProperty, kPSK, &unused_error);
    store_->SetStringProperty(kIKEv2LocalIdentityProperty, kLocalId,
                              &unused_error);
    store_->SetStringProperty(kIKEv2RemoteIdentityProperty, kRemoteId,
                              &unused_error);

    driver_->Save(&fake_store_, kStorageId, /*save_credentials=*/true);
    ResetDriver();
    driver_->Load(&fake_store_, kStorageId);

    InvokeAndVerifyConnectAsync();
    const auto* ipsec_config = driver_->ipsec_config();
    EXPECT_EQ(ipsec_config->remote, kHost);
    EXPECT_EQ(ipsec_config->ike_version,
              IPsecConnection::Config::IKEVersion::kV2);
    EXPECT_EQ(ipsec_config->ca_cert_pem_strings, std::nullopt);
    EXPECT_EQ(ipsec_config->client_cert_id, std::nullopt);
    EXPECT_EQ(ipsec_config->client_cert_slot, std::nullopt);
    EXPECT_EQ(ipsec_config->psk, kPSK);
    EXPECT_EQ(ipsec_config->xauth_user, std::nullopt);
    EXPECT_EQ(ipsec_config->xauth_password, std::nullopt);
    EXPECT_EQ(ipsec_config->local_id, kLocalId);
    EXPECT_EQ(ipsec_config->remote_id, kRemoteId);
  }

  // Set to cert auth.
  {
    store_->SetStringProperty(kProviderHostProperty, kHost, &unused_error);
    store_->SetStringProperty(kIKEv2AuthenticationTypeProperty,
                              kIKEv2AuthenticationTypeCert, &unused_error);
    store_->SetStringProperty(kIKEv2ClientCertIdProperty, kCertId,
                              &unused_error);
    store_->SetStringProperty(kIKEv2ClientCertSlotProperty, kCertSlot,
                              &unused_error);
    store_->SetStringsProperty(kIKEv2CaCertPemProperty, kCACertPEM,
                               &unused_error);

    driver_->Save(&fake_store_, kStorageId, /*save_credentials=*/true);
    ResetDriver();
    driver_->Load(&fake_store_, kStorageId);

    InvokeAndVerifyConnectAsync();
    const auto* ipsec_config = driver_->ipsec_config();
    EXPECT_EQ(ipsec_config->remote, kHost);
    EXPECT_EQ(ipsec_config->ike_version,
              IPsecConnection::Config::IKEVersion::kV2);
    EXPECT_EQ(ipsec_config->ca_cert_pem_strings, kCACertPEM);
    EXPECT_EQ(ipsec_config->client_cert_id, kCertId);
    EXPECT_EQ(ipsec_config->client_cert_slot, kCertSlot);
    EXPECT_EQ(ipsec_config->psk, std::nullopt);
    EXPECT_EQ(ipsec_config->xauth_user, std::nullopt);
    EXPECT_EQ(ipsec_config->xauth_password, std::nullopt);
    EXPECT_EQ(ipsec_config->local_id, kLocalId);
    EXPECT_EQ(ipsec_config->remote_id, kRemoteId);
  }

  // Set to EAP auth.
  {
    store_->SetStringProperty(kProviderHostProperty, kHost, &unused_error);
    store_->SetStringProperty(kIKEv2AuthenticationTypeProperty,
                              kIKEv2AuthenticationTypeEAP, &unused_error);
    store_->SetStringProperty(kEapMethodProperty, kEapMethodMSCHAPV2,
                              &unused_error);
    store_->SetStringProperty(kEapIdentityProperty, kEAPIdentity,
                              &unused_error);
    store_->SetStringProperty(kEapPasswordProperty, kEAPPassword,
                              &unused_error);

    driver_->Save(&fake_store_, kStorageId, /*save_credentials=*/true);
    ResetDriver();
    driver_->Load(&fake_store_, kStorageId);

    InvokeAndVerifyConnectAsync();
    const auto* ipsec_config = driver_->ipsec_config();
    EXPECT_EQ(ipsec_config->remote, kHost);
    EXPECT_EQ(ipsec_config->ike_version,
              IPsecConnection::Config::IKEVersion::kV2);
    EXPECT_EQ(ipsec_config->ca_cert_pem_strings, kCACertPEM);
    EXPECT_EQ(ipsec_config->client_cert_id, std::nullopt);
    EXPECT_EQ(ipsec_config->client_cert_slot, std::nullopt);
    EXPECT_EQ(ipsec_config->psk, std::nullopt);
    EXPECT_EQ(ipsec_config->xauth_user, kEAPIdentity);
    EXPECT_EQ(ipsec_config->xauth_password, kEAPPassword);
    EXPECT_EQ(ipsec_config->local_id, kLocalId);
    EXPECT_EQ(ipsec_config->remote_id, kRemoteId);
  }
}

// Verifies whether kPassphraseRequiredProperty is properly set in the Provider
// property.
TEST_F(IKEv2DriverTest, GetProvider) {
  Error unused_error;

  const std::string kPSK = "preshared-key";
  const std::string kEAPIdentity = "eap-identity";
  const std::string kEAPPassword = "eap-password";

  store_->SetStringProperty(kIKEv2AuthenticationTypeProperty,
                            kIKEv2AuthenticationTypePSK, &unused_error);
  {
    KeyValueStore props;
    store_->SetStringProperty(kIKEv2PskProperty, "", &unused_error);
    EXPECT_TRUE(store_->GetKeyValueStoreProperty(kProviderProperty, &props,
                                                 &unused_error));
    EXPECT_TRUE(props.Get<bool>(kPassphraseRequiredProperty));
  }
  {
    KeyValueStore props;
    store_->SetStringProperty(kIKEv2PskProperty, kPSK, &unused_error);
    EXPECT_TRUE(store_->GetKeyValueStoreProperty(kProviderProperty, &props,
                                                 &unused_error));
    EXPECT_FALSE(props.Get<bool>(kPassphraseRequiredProperty));
  }

  store_->SetStringProperty(kIKEv2AuthenticationTypeProperty,
                            kIKEv2AuthenticationTypeEAP, &unused_error);
  store_->SetStringProperty(kEapMethodProperty, kEapMethodMSCHAPV2,
                            &unused_error);
  store_->SetStringProperty(kEapIdentityProperty, kEAPIdentity, &unused_error);
  {
    KeyValueStore props;
    store_->SetStringProperty(kEapPasswordProperty, "", &unused_error);
    EXPECT_TRUE(store_->GetKeyValueStoreProperty(kProviderProperty, &props,
                                                 &unused_error));
    EXPECT_TRUE(props.Get<bool>(kPassphraseRequiredProperty));
  }
  {
    KeyValueStore props;
    store_->SetStringProperty(kEapPasswordProperty, kEAPPassword,
                              &unused_error);
    EXPECT_TRUE(store_->GetKeyValueStoreProperty(kProviderProperty, &props,
                                                 &unused_error));
    EXPECT_FALSE(props.Get<bool>(kPassphraseRequiredProperty));
  }

  // PassphraseRequired should always be false if the authentication type is
  // cert.
  store_->SetStringProperty(kIKEv2AuthenticationTypeProperty,
                            kIKEv2AuthenticationTypeCert, &unused_error);
  {
    KeyValueStore props;
    EXPECT_TRUE(store_->GetKeyValueStoreProperty(kProviderProperty, &props,
                                                 &unused_error));
    EXPECT_FALSE(props.Get<bool>(kPassphraseRequiredProperty));
  }
}

}  // namespace
}  // namespace shill
