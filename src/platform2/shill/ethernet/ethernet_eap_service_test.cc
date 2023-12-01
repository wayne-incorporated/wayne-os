// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/ethernet/ethernet_eap_service.h"

#include <base/functional/bind.h>
#include <chromeos/dbus/service_constants.h>
#include <gtest/gtest.h>

#include "shill/ethernet/mock_ethernet_eap_provider.h"
#include "shill/mock_adaptors.h"
#include "shill/mock_control.h"
#include "shill/mock_manager.h"
#include "shill/mock_metrics.h"
#include "shill/service_property_change_test.h"
#include "shill/technology.h"
#include "shill/test_event_dispatcher.h"

using testing::Return;

namespace shill {

class EthernetEapServiceTest : public testing::Test {
 public:
  EthernetEapServiceTest() : manager_(&control_, &dispatcher_, &metrics_) {
    Service::SetNextSerialNumberForTesting(0);
    service_ = new EthernetEapService(&manager_);
  }
  ~EthernetEapServiceTest() override = default;

 protected:
  ServiceMockAdaptor* GetAdaptor() {
    return static_cast<ServiceMockAdaptor*>(service_->adaptor());
  }

  MockControl control_;
  EventDispatcherForTest dispatcher_;
  MockMetrics metrics_;
  MockManager manager_;
  MockEthernetEapProvider provider_;
  scoped_refptr<EthernetEapService> service_;
};

TEST_F(EthernetEapServiceTest, MethodOverrides) {
  EXPECT_EQ(RpcIdentifier("/"), service_->GetDeviceRpcId(nullptr));
  EXPECT_EQ("etherneteap_all", service_->GetStorageIdentifier());
  EXPECT_EQ(Technology::kEthernetEap, service_->technology());
  EXPECT_TRUE(service_->Is8021x());
  EXPECT_FALSE(service_->IsVisible());
}

TEST_F(EthernetEapServiceTest, LogName) {
  EXPECT_EQ("etherneteap_0", service_->log_name());
}

TEST_F(EthernetEapServiceTest, OnEapCredentialsChanged) {
  service_->has_ever_connected_ = true;
  EXPECT_TRUE(service_->has_ever_connected());
  EXPECT_CALL(manager_, ethernet_eap_provider()).WillOnce(Return(&provider_));
  EXPECT_CALL(provider_, OnCredentialsChanged());
  service_->OnEapCredentialsChanged(Service::kReasonPropertyUpdate);
  EXPECT_FALSE(service_->has_ever_connected());
}

TEST_F(EthernetEapServiceTest, OnEapCredentialPropertyChanged) {
  EXPECT_CALL(manager_, ethernet_eap_provider()).WillOnce(Return(&provider_));
  EXPECT_CALL(provider_, OnCredentialsChanged());
  service_->OnPropertyChanged(kEapPasswordProperty);
}

TEST_F(EthernetEapServiceTest, Unload) {
  EXPECT_CALL(manager_, ethernet_eap_provider()).WillOnce(Return(&provider_));
  EXPECT_CALL(provider_, OnCredentialsChanged());
  EXPECT_FALSE(service_->Unload());
}

TEST_F(EthernetEapServiceTest, PropertyChanges) {
  TestCommonPropertyChanges(service_, GetAdaptor());
}

// Custom property setters should return false, and make no changes, if
// the new value is the same as the old value.
TEST_F(EthernetEapServiceTest, CustomSetterNoopChange) {
  TestCustomSetterNoopChange(service_, &manager_);
}

}  // namespace shill
