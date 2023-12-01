// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/ethernet/ethernet_service.h"

#include <base/memory/weak_ptr.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "shill/ethernet/mock_ethernet.h"
#include "shill/ethernet/mock_ethernet_provider.h"
#include "shill/mock_adaptors.h"
#include "shill/mock_manager.h"
#include "shill/mock_profile.h"
#include "shill/network/mock_network.h"
#include "shill/refptr_types.h"
#include "shill/service_property_change_test.h"
#include "shill/store/fake_store.h"
#include "shill/store/property_store_test.h"
#include "shill/technology.h"

using ::testing::_;
using ::testing::NiceMock;
using ::testing::Return;
using ::testing::ReturnRef;

namespace shill {

class EthernetServiceTest : public PropertyStoreTest {
 public:
  EthernetServiceTest()
      : mock_manager_(control_interface(), dispatcher(), metrics()) {
    Service::SetNextSerialNumberForTesting(0);
    ethernet_ =
        new NiceMock<MockEthernet>(&mock_manager_, "ethernet", fake_mac, 0);
    service_ = new EthernetService(
        &mock_manager_,
        EthernetService::Properties(ethernet_->weak_ptr_factory_.GetWeakPtr()));
  }
  ~EthernetServiceTest() override {}

 protected:
  static const char fake_mac[];

  bool GetAutoConnect() { return service_->GetAutoConnect(nullptr); }

  bool SetAutoConnect(const bool connect, Error* error) {
    return service_->SetAutoConnectFull(connect, error);
  }

  ServiceMockAdaptor* GetAdaptor() {
    return static_cast<ServiceMockAdaptor*>(service_->adaptor());
  }

  MockManager mock_manager_;
  scoped_refptr<MockEthernet> ethernet_;
  EthernetServiceRefPtr service_;
};

// static
const char EthernetServiceTest::fake_mac[] = "AaBBcCDDeeFF";

TEST_F(EthernetServiceTest, LogName) {
  EXPECT_EQ("ethernet_0", service_->log_name());
}

TEST_F(EthernetServiceTest, AutoConnect) {
  EXPECT_TRUE(service_->IsAutoConnectByDefault());
  EXPECT_TRUE(GetAutoConnect());
  {
    Error error;
    SetAutoConnect(false, &error);
    EXPECT_FALSE(error.IsSuccess());
  }
  EXPECT_TRUE(GetAutoConnect());
  {
    Error error;
    SetAutoConnect(true, &error);
    EXPECT_TRUE(error.IsSuccess());
  }
  EXPECT_TRUE(GetAutoConnect());
}

TEST_F(EthernetServiceTest, ConnectDisconnectDelegation) {
  EXPECT_CALL(*ethernet_, link_up()).WillRepeatedly(Return(true));
  EXPECT_CALL(*ethernet_, ConnectTo(service_.get()));
  service_->AutoConnect();
  service_->SetState(Service::kStateConnected);
  EXPECT_CALL(*ethernet_, DisconnectFrom(service_.get()));
  Error error;
  service_->Disconnect(&error, "in test");
}

TEST_F(EthernetServiceTest, PropertyChanges) {
  TestCommonPropertyChanges(service_, GetAdaptor());
}

// Custom property setters should return false, and make no changes, if
// the new value is the same as the old value.
TEST_F(EthernetServiceTest, CustomSetterNoopChange) {
  TestCustomSetterNoopChange(service_, &mock_manager_);
}

TEST_F(EthernetServiceTest, LoadAutoConnect) {
  // Make sure when we try to load an Ethernet service, it sets AutoConnect
  // to be true even if the property is not found.
  FakeStore store;
  scoped_refptr<MockProfile> mock_profile = new MockProfile(&mock_manager_, "");
  ProfileRefPtr profile = mock_profile.get();
  store.SetString(service_->GetStorageIdentifier(), Service::kStorageType,
                  kTypeEthernet);
  EXPECT_TRUE(service_->Load(&store));
  EXPECT_TRUE(GetAutoConnect());
}

TEST_F(EthernetServiceTest, GetTethering) {
  EXPECT_EQ(nullptr, service_->attached_network());
  EXPECT_EQ(Service::TetheringState::kNotDetected, service_->GetTethering());

  MockNetwork network(1, "eth0", Technology::kEthernet);
  service_->SetAttachedNetwork(network.AsWeakPtr());
  EXPECT_CALL(network, IsConnectedViaTether())
      .WillOnce(Return(true))
      .WillOnce(Return(false));
  EXPECT_NE(nullptr, service_->attached_network());
  EXPECT_EQ(Service::TetheringState::kConfirmed, service_->GetTethering());
  EXPECT_EQ(Service::TetheringState::kNotDetected, service_->GetTethering());
}

TEST_F(EthernetServiceTest, IsVisible) {
  EXPECT_CALL(*ethernet_, link_up())
      .WillOnce(Return(false))
      .WillOnce(Return(true));
  EXPECT_FALSE(service_->IsVisible());
  EXPECT_TRUE(service_->IsVisible());
}

TEST_F(EthernetServiceTest, IsAutoConnectable) {
  EXPECT_CALL(*ethernet_, link_up())
      .WillOnce(Return(false))
      .WillOnce(Return(true));
  const char* reason;
  EXPECT_FALSE(service_->IsAutoConnectable(&reason));
  EXPECT_STREQ("connection medium unavailable", reason);
  EXPECT_TRUE(service_->IsAutoConnectable(nullptr));
}

}  // namespace shill
