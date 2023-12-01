// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/ethernet/ethernet_provider.h"

#include <base/functional/bind.h>
#include <base/memory/ref_counted.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "shill/ethernet/mock_ethernet.h"
#include "shill/mock_control.h"
#include "shill/mock_manager.h"
#include "shill/mock_metrics.h"
#include "shill/mock_profile.h"
#include "shill/store/key_value_store.h"
#include "shill/test_event_dispatcher.h"

using testing::_;
using testing::DoAll;
using testing::Mock;
using testing::NiceMock;
using testing::Return;
using testing::ReturnRef;
using testing::SaveArg;

namespace shill {

class EthernetProviderTest : public testing::Test {
 public:
  EthernetProviderTest()
      : manager_(&control_, &dispatcher_, &metrics_),
        profile_(new MockProfile(&manager_, "")),
        provider_(&manager_),
        eth0_(new NiceMock<MockEthernet>(&manager_, "ethernet", fake_mac0, 0)),
        eth1_(new NiceMock<MockEthernet>(&manager_, "ethernet", fake_mac1, 0)) {
  }
  ~EthernetProviderTest() override = default;

 protected:
  using MockProfileRefPtr = scoped_refptr<MockProfile>;

  static const char fake_mac0[];
  static const char fake_mac1[];

  MockControl control_;
  EventDispatcherForTest dispatcher_;
  MockMetrics metrics_;
  MockManager manager_;
  MockProfileRefPtr profile_;
  EthernetProvider provider_;
  scoped_refptr<MockEthernet> eth0_;
  scoped_refptr<MockEthernet> eth1_;
};

// static
const char EthernetProviderTest::fake_mac0[] = "AaBBcCDDeeFF";
const char EthernetProviderTest::fake_mac1[] = "FfEEDdccBbaA";

TEST_F(EthernetProviderTest, Construct) {
  EXPECT_EQ(ServiceRefPtr(), provider_.service());
}

TEST_F(EthernetProviderTest, StartAndStop) {
  provider_.Start();
  ServiceRefPtr service = provider_.service();
  EXPECT_NE(ServiceRefPtr(), provider_.service());

  provider_.Stop();
  EXPECT_EQ(service, provider_.service());

  // Provider re-uses the same service on restart.
  provider_.Start();
  Mock::VerifyAndClearExpectations(&manager_);
}

TEST_F(EthernetProviderTest, ServiceConstructors) {
  provider_.Start();
  ServiceRefPtr service = provider_.service();
  KeyValueStore args;
  args.Set<std::string>(kTypeProperty, kTypeEthernet);
  {
    Error error;
    EXPECT_EQ(service, provider_.GetService(args, &error));
    EXPECT_TRUE(error.IsSuccess());
  }
  {
    Error error;
    EXPECT_EQ(service, provider_.FindSimilarService(args, &error));
    EXPECT_TRUE(error.IsSuccess());
  }
  {
    Error error;
    Mock::VerifyAndClearExpectations(&manager_);
    EXPECT_CALL(manager_, RegisterService(_)).Times(0);
    ServiceRefPtr temp_service = provider_.CreateTemporaryService(args, &error);
    EXPECT_TRUE(error.IsSuccess());
    // Returned service should be non-NULL but not the provider's own service.
    EXPECT_NE(ServiceRefPtr(), temp_service);
    EXPECT_NE(service, temp_service);
  }
}

TEST_F(EthernetProviderTest, GenericServiceCreation) {
  provider_.Start();
  ServiceRefPtr service = provider_.service();
  EXPECT_NE(ServiceRefPtr(), provider_.service());
  EXPECT_EQ(provider_.service()->GetStorageIdentifier(), "ethernet_any");

  provider_.Stop();
  EXPECT_EQ(service, provider_.service());
}

TEST_F(EthernetProviderTest, MultipleServices) {
  provider_.Start();
  EthernetServiceRefPtr ethernet_any_service = provider_.service();
  EXPECT_NE(ServiceRefPtr(), provider_.service());
  EXPECT_EQ(ethernet_any_service->GetStorageIdentifier(), "ethernet_any");
  EXPECT_FALSE(ethernet_any_service->HasEthernet());

  EthernetServiceRefPtr ethernet_service0 =
      provider_.CreateService(eth0_->weak_ptr_factory_.GetWeakPtr());
  ServiceRefPtr service0 = ethernet_service0;
  EXPECT_TRUE(ethernet_any_service->HasEthernet());
  EXPECT_EQ(ethernet_service0, ethernet_any_service);
  EXPECT_EQ(ethernet_service0->GetStorageIdentifier(), "ethernet_any");
  EXPECT_CALL(manager_, RegisterService(_)).Times(0);
  EXPECT_CALL(manager_, GetFirstEthernetService())
      .WillOnce(Return(ethernet_service0));
  EXPECT_CALL(manager_, MatchProfileWithService(_)).Times(0);
  provider_.RegisterService(ethernet_service0);
  provider_.RefreshGenericEthernetService();
  EXPECT_EQ(provider_.services_.size(), 1);
  EXPECT_EQ(ethernet_service0, provider_.service());

  EthernetServiceRefPtr ethernet_service1 =
      provider_.CreateService(eth1_->weak_ptr_factory_.GetWeakPtr());
  ServiceRefPtr service1 = ethernet_service1;
  EXPECT_NE(ethernet_service0, ethernet_service1);
  EXPECT_EQ(ethernet_service1->GetStorageIdentifier(), "ethernet_ffeeddccbbaa");
  EXPECT_CALL(manager_, RegisterService(_)).Times(1);
  EXPECT_CALL(manager_, GetFirstEthernetService())
      .WillOnce(Return(ethernet_service1));
  EXPECT_CALL(manager_, MatchProfileWithService(service0));
  EXPECT_CALL(manager_, MatchProfileWithService(service1));
  provider_.RegisterService(ethernet_service1);
  provider_.RefreshGenericEthernetService();
  EXPECT_EQ(provider_.services_.size(), 2);
  EXPECT_EQ(ethernet_service1, provider_.service());
  EXPECT_EQ(ethernet_service1->GetStorageIdentifier(), "ethernet_any");
  EXPECT_EQ(ethernet_service0->GetStorageIdentifier(), "ethernet_aabbccddeeff");

  EXPECT_CALL(manager_, GetFirstEthernetService())
      .WillOnce(Return(ethernet_service0));
  EXPECT_CALL(manager_, MatchProfileWithService(service0));
  EXPECT_CALL(manager_, MatchProfileWithService(service1));
  provider_.RefreshGenericEthernetService();
  EXPECT_EQ(ethernet_service1->GetStorageIdentifier(), "ethernet_ffeeddccbbaa");
  EXPECT_EQ(ethernet_service0->GetStorageIdentifier(), "ethernet_any");

  EXPECT_CALL(manager_, DeregisterService(_)).Times(1);
  EXPECT_CALL(manager_, GetFirstEthernetService())
      .WillOnce(Return(ethernet_service1));
  EXPECT_CALL(manager_, MatchProfileWithService(service1));
  EXPECT_CALL(manager_, MatchProfileWithService(service0)).Times(0);
  provider_.DeregisterService(ethernet_service0);
  provider_.RefreshGenericEthernetService();
  EXPECT_EQ(provider_.services_.size(), 1);
  EXPECT_EQ(ethernet_service1, provider_.service());
  EXPECT_EQ(ethernet_service1->GetStorageIdentifier(), "ethernet_any");

  EXPECT_CALL(manager_, DeregisterService(_)).Times(1);
  provider_.Stop();
  EXPECT_EQ(provider_.services_.size(), 0);
  EXPECT_EQ(ethernet_service1, provider_.service());
  EXPECT_FALSE(ethernet_service1->HasEthernet());
}

}  // namespace shill
