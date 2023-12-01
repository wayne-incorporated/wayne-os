// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <string>
#include <vector>

#include <brillo/dbus/mock_dbus_method_response.h>
#include <brillo/errors/error_codes.h>
#include <brillo/message_loops/fake_message_loop.h>
#include <dbus/shill/dbus-constants.h>
#include <gtest/gtest.h>

#include "minios/minios.h"
#include "minios/mock_network_manager.h"
#include "minios/mock_shill_proxy.h"
#include "minios/network_manager.h"

using ::testing::_;
using ::testing::ElementsAre;
using ::testing::IsNull;
using ::testing::NotNull;
using ::testing::StrictMock;

namespace minios {

class NetworkManagerTest : public ::testing::Test {
 public:
  void SetUp() override {
    loop_.SetAsCurrent();

    auto mock_shill_proxy_ptr = std::make_unique<MockShillProxy>();
    mock_shill_proxy_ptr_ = mock_shill_proxy_ptr.get();
    network_manager_ =
        std::make_unique<NetworkManager>(std::move(mock_shill_proxy_ptr));
    network_manager_->AddObserver(&mock_network_manager_observer_);
  }

 protected:
  MockShillProxy* mock_shill_proxy_ptr_;
  StrictMock<MockNetworkManagerObserver> mock_network_manager_observer_;
  std::unique_ptr<NetworkManager> network_manager_;

  base::SimpleTestClock clock_;
  brillo::FakeMessageLoop loop_{&clock_};
};

TEST_F(NetworkManagerTest, Connect) {
  EXPECT_CALL(*mock_shill_proxy_ptr_,
              ManagerRequestScan(shill::kTypeWifi, _, _));
  network_manager_->Connect("ssid-foo", "passphrase");

  // It's okay to request the same SSID for connection, a no-op.
  network_manager_->Connect("ssid-foo", "passphrase");

  // Passphrase changes for same SSID will be ignored, a no-op.
  network_manager_->Connect("ssid-foo", "passphrase-other");

  // Connecting to a different SSID should be successful.
  EXPECT_CALL(*mock_shill_proxy_ptr_,
              ManagerRequestScan(shill::kTypeWifi, _, _));
  network_manager_->Connect("ssid-bar", "passphrase");
}

TEST_F(NetworkManagerTest, Connect_RequestScanSuccess_NoPassphrase) {
  network_manager_->connect_map_["ssid"] = NetworkManager::ConnectField();
  auto iter_no_passphrase = network_manager_->connect_map_.begin();
  const brillo::VariantDictionary properties = {
      {shill::kModeProperty, brillo::Any(std::string(shill::kModeManaged))},
      {shill::kNameProperty, brillo::Any(iter_no_passphrase->first)},
      {shill::kSecurityClassProperty,
       brillo::Any(std::string(shill::kSecurityClassNone))},
      {shill::kTypeProperty, brillo::Any(std::string(shill::kTypeWifi))},
  };
  EXPECT_CALL(*mock_shill_proxy_ptr_,
              ManagerFindMatchingService(properties, _, _));
  network_manager_->RequestScanSuccess(iter_no_passphrase);
}

TEST_F(NetworkManagerTest, Connect_RequestScanSuccess_Passphrase) {
  network_manager_->connect_map_["ssid"] =
      NetworkManager::ConnectField{.passphrase = "passphrase"};
  auto iter_passphrase = network_manager_->connect_map_.begin();
  const brillo::VariantDictionary properties = {
      {shill::kModeProperty, brillo::Any(std::string(shill::kModeManaged))},
      {shill::kNameProperty, brillo::Any(iter_passphrase->first)},
      {shill::kSecurityClassProperty,
       brillo::Any(std::string(shill::kSecurityClassPsk))},
      {shill::kTypeProperty, brillo::Any(std::string(shill::kTypeWifi))},
  };
  EXPECT_CALL(*mock_shill_proxy_ptr_,
              ManagerFindMatchingService(properties, _, _));
  network_manager_->RequestScanSuccess(iter_passphrase);
}

TEST_F(NetworkManagerTest, Connect_GetServiceSuccess_GoodStrength) {
  network_manager_->connect_map_["ssid"] =
      NetworkManager::ConnectField{.passphrase = "passphrase"};
  auto iter = network_manager_->connect_map_.begin();
  const brillo::VariantDictionary input_properties = {
      {shill::kSignalStrengthProperty, brillo::Any(uint8_t(1))},
  };
  const brillo::VariantDictionary expected_properties = {
      {shill::kAutoConnectProperty, brillo::Any(true)},
      {shill::kPassphraseProperty, brillo::Any(iter->second.passphrase)},
  };
  EXPECT_CALL(*mock_shill_proxy_ptr_,
              ServiceSetProperties(_, expected_properties, _, _));
  network_manager_->GetServiceSuccess(iter, input_properties);
}

TEST_F(NetworkManagerTest, Connect_GetServiceSuccess_NoPassphrase) {
  // Empty password does not send `kPassphraseProperty`.
  network_manager_->connect_map_["ssid"] =
      NetworkManager::ConnectField{.passphrase = ""};
  auto iter = network_manager_->connect_map_.begin();
  const brillo::VariantDictionary input_properties = {
      {shill::kSignalStrengthProperty, brillo::Any(uint8_t(1))},
  };
  const brillo::VariantDictionary expected_properties = {
      {shill::kAutoConnectProperty, brillo::Any(true)},
  };
  EXPECT_CALL(*mock_shill_proxy_ptr_,
              ServiceSetProperties(_, expected_properties, _, _));
  network_manager_->GetServiceSuccess(iter, input_properties);
}

TEST_F(NetworkManagerTest, Connect_GetServiceSuccess_BadStrength) {
  network_manager_->connect_map_["ssid"] =
      NetworkManager::ConnectField{.passphrase = "passphrase"};
  auto iter = network_manager_->connect_map_.begin();
  const brillo::VariantDictionary input_properties = {
      {shill::kSignalStrengthProperty, brillo::Any(uint8_t(0))},
  };
  EXPECT_CALL(mock_network_manager_observer_, OnConnect("ssid", NotNull()));
  network_manager_->GetServiceSuccess(iter, input_properties);
}

TEST_F(NetworkManagerTest, Connect_GetServiceSuccess_MissingStrength) {
  network_manager_->connect_map_["ssid"] =
      NetworkManager::ConnectField{.passphrase = "passphrase"};
  auto iter = network_manager_->connect_map_.begin();
  EXPECT_CALL(mock_network_manager_observer_, OnConnect("ssid", NotNull()));
  network_manager_->GetServiceSuccess(iter, {});
}

TEST_F(NetworkManagerTest,
       Connect_ConnectToNetworkError_InProgressRetriesConnection) {
  auto error_ptr =
      brillo::Error::Create(FROM_HERE, brillo::errors::dbus::kDomain,
                            shill::kErrorResultInProgress, "");
  network_manager_->connect_map_["ssid"] = NetworkManager::ConnectField{
      .service_path = dbus::ObjectPath("some-service-path")};
  auto iter = network_manager_->connect_map_.begin();
  network_manager_->ConnectToNetworkError(iter, error_ptr.get());

  EXPECT_CALL(*mock_shill_proxy_ptr_,
              ServiceConnect(iter->second.service_path, _, _));
  clock_.Advance(base::Seconds(1));
  loop_.RunOnce(false);
}

TEST_F(NetworkManagerTest, Connect_ConnectToNetworkError_AlreadyConnected) {
  auto error_ptr =
      brillo::Error::Create(FROM_HERE, brillo::errors::dbus::kDomain,
                            shill::kErrorResultAlreadyConnected, "");
  network_manager_->connect_map_["ssid"] = NetworkManager::ConnectField{
      .service_path = dbus::ObjectPath("some-service-path")};
  auto iter = network_manager_->connect_map_.begin();
  EXPECT_CALL(mock_network_manager_observer_, OnConnect("ssid", IsNull()));
  network_manager_->ConnectToNetworkError(iter, error_ptr.get());
}

TEST_F(NetworkManagerTest,
       Connect_ConnectToNetworkError_OtherErrorResponsesFromShill) {
  auto error_ptr = brillo::Error::Create(
      FROM_HERE, brillo::errors::dbus::kDomain, DBUS_ERROR_FAILED, "");
  network_manager_->connect_map_["ssid"] = NetworkManager::ConnectField();
  auto iter = network_manager_->connect_map_.begin();
  EXPECT_CALL(mock_network_manager_observer_, OnConnect("ssid", NotNull()));
  network_manager_->ConnectToNetworkError(iter, error_ptr.get());
}

TEST_F(NetworkManagerTest,
       Connect_GetServiceCheckConnectionSuccess_FailureState) {
  const brillo::VariantDictionary input_properties = {
      {shill::kStateProperty, brillo::Any(std::string(shill::kStateFailure))},
  };
  network_manager_->connect_map_["ssid"] = NetworkManager::ConnectField{
      .service_path = dbus::ObjectPath("some-service-path")};
  auto iter = network_manager_->connect_map_.begin();
  EXPECT_CALL(mock_network_manager_observer_, OnConnect("ssid", NotNull()));
  network_manager_->GetServiceCheckConnectionSuccess(iter, input_properties);
}

TEST_F(NetworkManagerTest,
       Connect_GetServiceCheckConnectionSuccess_OnlineState) {
  const brillo::VariantDictionary input_properties = {
      {shill::kStateProperty, brillo::Any(std::string(shill::kStateOnline))},
  };
  network_manager_->connect_map_["ssid"] = NetworkManager::ConnectField{
      .service_path = dbus::ObjectPath("some-service-path")};
  auto iter = network_manager_->connect_map_.begin();
  EXPECT_CALL(mock_network_manager_observer_, OnConnect("ssid", IsNull()));
  network_manager_->GetServiceCheckConnectionSuccess(iter, input_properties);
}

TEST_F(NetworkManagerTest,
       Connect_GetServiceCheckConnectionSuccess_MissingState) {
  network_manager_->connect_map_["ssid"] = NetworkManager::ConnectField{
      .service_path = dbus::ObjectPath("some-service-path")};
  auto iter = network_manager_->connect_map_.begin();
  EXPECT_CALL(mock_network_manager_observer_, OnConnect("ssid", NotNull()));
  network_manager_->GetServiceCheckConnectionSuccess(iter, {});
}

TEST_F(NetworkManagerTest,
       Connect_GetServiceCheckConnectionSuccess_IntermediateState) {
  const brillo::VariantDictionary input_properties = {
      {shill::kStateProperty, brillo::Any(std::string(shill::kStateReady))},
  };
  network_manager_->connect_map_["ssid"] = NetworkManager::ConnectField{
      .service_path = dbus::ObjectPath("some-service-path")};
  auto iter = network_manager_->connect_map_.begin();
  network_manager_->GetServiceCheckConnectionSuccess(iter, input_properties);

  EXPECT_CALL(*mock_shill_proxy_ptr_,
              ServiceGetProperties(iter->second.service_path, _, _));
  clock_.Advance(
      base::Seconds(NetworkManager::kCheckConnectionRetryMsDelay * 2));
  loop_.RunOnce(false);
}

TEST_F(NetworkManagerTest, GetNetworks) {
  EXPECT_TRUE(network_manager_->get_networks_list_.empty());
  EXPECT_CALL(*mock_shill_proxy_ptr_,
              ManagerRequestScan(shill::kTypeWifi, _, _));
  network_manager_->GetNetworks();
  EXPECT_EQ(network_manager_->get_networks_list_.size(), 1);

  // Subsequent `GetNetworks()` should be bundled.
  network_manager_->GetNetworks();
  EXPECT_EQ(network_manager_->get_networks_list_.size(), 1);
}

TEST_F(NetworkManagerTest, GetGlobalPropertiesSuccess_MultipleServices) {
  auto iter = network_manager_->get_networks_list_.insert(
      network_manager_->get_networks_list_.begin(),
      NetworkManager::GetNetworksField());

  dbus::ObjectPath object_path("some-service-path");
  dbus::ObjectPath other_object_path("other-some-service-path");
  std::vector<dbus::ObjectPath> object_paths = {other_object_path, object_path};
  const brillo::VariantDictionary input_properties = {
      {shill::kServicesProperty, brillo::Any(object_paths)},
  };

  EXPECT_CALL(*mock_shill_proxy_ptr_, ServiceGetProperties(object_path, _, _));
  network_manager_->GetGlobalPropertiesSuccess(iter, input_properties);
  // Should still hold `other_object_path` to iterate over and get the Service
  // name from as `object_path` was binded into `ServiceGetProperties()`.
  EXPECT_EQ(iter->service_paths.size(), 1);
}

TEST_F(NetworkManagerTest,
       GetGlobalPropertiesSuccess_EmptyServices_DoneRetries) {
  auto iter = network_manager_->get_networks_list_.insert(
      network_manager_->get_networks_list_.begin(),
      NetworkManager::GetNetworksField());
  network_manager_->num_scan_retries_ = 0;
  EXPECT_CALL(mock_network_manager_observer_,
              OnGetNetworks(testing::_, NotNull()));
  network_manager_->GetGlobalPropertiesSuccess(iter, {});
}

TEST_F(NetworkManagerTest, GetGlobalPropertiesSuccess_EmptyServices_Retry) {
  auto iter = network_manager_->get_networks_list_.insert(
      network_manager_->get_networks_list_.begin(),
      NetworkManager::GetNetworksField());
  network_manager_->num_scan_retries_ = 1;
  EXPECT_CALL(*mock_shill_proxy_ptr_,
              ManagerRequestScan(shill::kTypeWifi, _, _));
  network_manager_->GetGlobalPropertiesSuccess(iter, {});
  clock_.Advance(NetworkManager::kScanRetryMsDelay * 2);
  loop_.RunOnce(false);
  EXPECT_EQ(network_manager_->num_scan_retries_, 0);
}

TEST_F(NetworkManagerTest, IterateOverServicePropertiesSuccess_EmptyServices) {
  // Explicitly empty the `service_paths`.
  auto iter = network_manager_->get_networks_list_.insert(
      network_manager_->get_networks_list_.begin(),
      NetworkManager::GetNetworksField{.service_paths = {}});
  EXPECT_CALL(mock_network_manager_observer_,
              OnGetNetworks(testing::_, IsNull()));
  network_manager_->IterateOverServicePropertiesSuccess(iter, {});
}

TEST_F(NetworkManagerTest, IterateOverServicePropertiesSuccess_OneService) {
  // Explicitly empty the `service_paths`.
  auto iter = network_manager_->get_networks_list_.insert(
      network_manager_->get_networks_list_.begin(),
      NetworkManager::GetNetworksField{.service_paths = {}});

  const std::string kSsid = "some-ssid-name";
  const brillo::VariantDictionary input_properties = {
      {shill::kNameProperty, brillo::Any(kSsid)},
  };
  EXPECT_CALL(mock_network_manager_observer_,
              OnGetNetworks(testing::_, IsNull()));
  network_manager_->IterateOverServicePropertiesSuccess(iter, input_properties);
}

TEST_F(NetworkManagerTest,
       IterateOverServicePropertiesSuccess_MoreServicesToIterate) {
  dbus::ObjectPath object_path("some-service-path");
  auto iter = network_manager_->get_networks_list_.insert(
      network_manager_->get_networks_list_.begin(),
      NetworkManager::GetNetworksField{.service_paths = {object_path}});

  const std::string kSsid = "some-ssid-name";
  const brillo::VariantDictionary input_properties = {
      {shill::kNameProperty, brillo::Any(kSsid)},
  };

  EXPECT_TRUE(iter->networks.empty());
  EXPECT_CALL(*mock_shill_proxy_ptr_, ServiceGetProperties(object_path, _, _));
  network_manager_->IterateOverServicePropertiesSuccess(iter, input_properties);
  EXPECT_THAT(iter->networks[0].ssid, kSsid);
  EXPECT_TRUE(iter->service_paths.empty());
}

TEST_F(NetworkManagerTest,
       IterateOverServicePropertiesError_MoreServicesToIterate) {
  dbus::ObjectPath object_path("some-service-path");
  auto iter = network_manager_->get_networks_list_.insert(
      network_manager_->get_networks_list_.begin(),
      NetworkManager::GetNetworksField{.service_paths = {object_path}});

  EXPECT_CALL(*mock_shill_proxy_ptr_, ServiceGetProperties(object_path, _, _));
  network_manager_->IterateOverServicePropertiesError(iter, nullptr);
  EXPECT_TRUE(iter->service_paths.empty());
}

TEST_F(NetworkManagerTest,
       IterateOverServicePropertiesError_AlwaysReturnOnEnd) {
  const std::string kSsid = "some-ssid-name";
  // Explicitly empty the `service_paths`.
  // Put `kSsid` into the already parsed `networks` list.
  auto iter = network_manager_->get_networks_list_.insert(
      network_manager_->get_networks_list_.begin(),
      NetworkManager::GetNetworksField{.service_paths = {},
                                       .networks = {{.ssid = kSsid}}});

  EXPECT_CALL(mock_network_manager_observer_,
              OnGetNetworks(testing::_, IsNull()));
  network_manager_->IterateOverServicePropertiesError(iter, nullptr);
}

}  // namespace minios
