// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/cellular/cellular_service.h"

#include <chromeos/dbus/service_constants.h>
#include <gtest/gtest.h>

#include "base/containers/contains.h"
#include "dbus/shill/dbus-constants.h"
#include "shill/cellular/cellular_capability_3gpp.h"
#include "shill/cellular/cellular_service_provider.h"
#include "shill/cellular/mock_cellular.h"
#include "shill/cellular/mock_mobile_operator_info.h"
#include "shill/cellular/mock_modem_info.h"
#include "shill/mock_adaptors.h"
#include "shill/mock_control.h"
#include "shill/mock_manager.h"
#include "shill/mock_metrics.h"
#include "shill/mock_profile.h"
#include "shill/service_property_change_test.h"
#include "shill/store/fake_store.h"

using testing::_;
using testing::AnyNumber;
using testing::Mock;
using testing::NiceMock;
using testing::Return;

namespace shill {

namespace {
const char kImsi[] = "111222123456789";
const char kIccid[] = "1234567890000";
}  // namespace

class CellularServiceTest : public testing::Test {
 public:
  CellularServiceTest()
      : manager_(&control_, &dispatcher_, &metrics_),
        modem_info_(&control_, &manager_),
        profile_(new NiceMock<MockProfile>(&manager_)) {
    cellular_service_provider_.set_profile_for_testing(profile_);
    Service::SetNextSerialNumberForTesting(0);
  }
  ~CellularServiceTest() override { adaptor_ = nullptr; }

  void SetUp() override {
    // Many tests set service properties which call Manager.UpdateService().
    EXPECT_CALL(manager_, UpdateService(_)).Times(AnyNumber());
    EXPECT_CALL(manager_, modem_info()).WillRepeatedly(Return(&modem_info_));
    EXPECT_CALL(manager_, cellular_service_provider())
        .WillRepeatedly(Return(&cellular_service_provider_));

    device_ =
        new MockCellular(&manager_, "usb0", kAddress, 3, "", RpcIdentifier(""));

    // CellularService expects an IMSI and SIM ID be set in the Device.
    Cellular::SimProperties sim_properties;
    sim_properties.iccid = kIccid;
    sim_properties.imsi = kImsi;
    device_->SetPrimarySimProperties(sim_properties);
    service_ =
        new CellularService(&manager_, kImsi, kIccid, device_->GetSimCardId());
    service_->SetDevice(device_.get());
    adaptor_ = static_cast<ServiceMockAdaptor*>(service_->adaptor());

    storage_id_ = service_->GetStorageIdentifier();
    storage_.SetString(storage_id_, CellularService::kStorageType,
                       kTypeCellular);
    storage_.SetString(storage_id_, CellularService::kStorageIccid, kIccid);
    storage_.SetString(storage_id_, CellularService::kStorageImsi, kImsi);
  }

 protected:
  static const char kAddress[];

  std::string GetFriendlyName() const { return service_->friendly_name(); }
  bool IsAutoConnectable(const char** reason) const {
    return service_->IsAutoConnectable(reason);
  }
  bool SetAutoConnectFull(bool connect) {
    return service_->SetAutoConnectFull(connect, /*error=*/nullptr);
  }

  EventDispatcher dispatcher_;
  NiceMock<MockControl> control_;
  MockMetrics metrics_;
  NiceMock<MockManager> manager_;
  MockModemInfo modem_info_;
  scoped_refptr<MockCellular> device_;
  CellularServiceProvider cellular_service_provider_{&manager_};
  CellularServiceRefPtr service_;
  ServiceMockAdaptor* adaptor_ = nullptr;  // Owned by |service_|.
  std::string storage_id_;
  FakeStore storage_;
  scoped_refptr<NiceMock<MockProfile>> profile_;
};

const char CellularServiceTest::kAddress[] = "000102030405";

TEST_F(CellularServiceTest, Constructor) {
  EXPECT_TRUE(service_->connectable());
}

TEST_F(CellularServiceTest, SetNetworkTechnology) {
  EXPECT_CALL(*adaptor_, EmitStringChanged(kNetworkTechnologyProperty,
                                           kNetworkTechnologyUmts));
  EXPECT_TRUE(service_->network_technology().empty());
  service_->SetNetworkTechnology(kNetworkTechnologyUmts);
  EXPECT_EQ(kNetworkTechnologyUmts, service_->network_technology());
  service_->SetNetworkTechnology(kNetworkTechnologyUmts);
}

TEST_F(CellularServiceTest, LogName) {
  EXPECT_EQ("cellular_0", service_->log_name());
  service_->SetNetworkTechnology(kNetworkTechnologyUmts);
  EXPECT_EQ("cellular_UMTS_0", service_->log_name());
  service_->SetNetworkTechnology(kNetworkTechnologyGsm);
  EXPECT_EQ("cellular_GSM_0", service_->log_name());
  service_->SetNetworkTechnology(kNetworkTechnologyLte);
  EXPECT_EQ("cellular_LTE_0", service_->log_name());
}

TEST_F(CellularServiceTest, SetServingOperator) {
  static const char kCode[] = "123456";
  static const char kName[] = "Some Cellular Operator";
  Stringmap test_operator;
  service_->SetServingOperator(test_operator);
  test_operator[kOperatorCodeKey] = kCode;
  test_operator[kOperatorNameKey] = kName;
  EXPECT_CALL(*adaptor_, EmitStringmapChanged(kServingOperatorProperty, _));
  service_->SetServingOperator(test_operator);
  const Stringmap& serving_operator = service_->serving_operator();
  ASSERT_NE(serving_operator.end(), serving_operator.find(kOperatorCodeKey));
  ASSERT_NE(serving_operator.end(), serving_operator.find(kOperatorNameKey));
  EXPECT_EQ(kCode, serving_operator.find(kOperatorCodeKey)->second);
  EXPECT_EQ(kName, serving_operator.find(kOperatorNameKey)->second);
  Mock::VerifyAndClearExpectations(adaptor_);
  EXPECT_CALL(*adaptor_, EmitStringmapChanged(kServingOperatorProperty, _))
      .Times(0);
  service_->SetServingOperator(serving_operator);
}

TEST_F(CellularServiceTest, SetOLP) {
  const char kMethod[] = "GET";
  const char kURL[] = "payment.url";
  const char kPostData[] = "post_man";
  Stringmap olp;

  service_->SetOLP("", "", "");
  olp = service_->olp();  // Copy to simplify assertions below.
  EXPECT_EQ("", olp[kPaymentPortalURL]);
  EXPECT_EQ("", olp[kPaymentPortalMethod]);
  EXPECT_EQ("", olp[kPaymentPortalPostData]);

  EXPECT_CALL(*adaptor_, EmitStringmapChanged(kPaymentPortalProperty, _));
  service_->SetOLP(kURL, kMethod, kPostData);
  olp = service_->olp();  // Copy to simplify assertions below.
  EXPECT_EQ(kURL, olp[kPaymentPortalURL]);
  EXPECT_EQ(kMethod, olp[kPaymentPortalMethod]);
  EXPECT_EQ(kPostData, olp[kPaymentPortalPostData]);
}

TEST_F(CellularServiceTest, SetUsageURL) {
  static const char kUsageURL[] = "usage.url";
  EXPECT_CALL(*adaptor_, EmitStringChanged(kUsageURLProperty, kUsageURL));
  EXPECT_TRUE(service_->usage_url().empty());
  service_->SetUsageURL(kUsageURL);
  EXPECT_EQ(kUsageURL, service_->usage_url());
  service_->SetUsageURL(kUsageURL);
}

TEST_F(CellularServiceTest, SetApn) {
  static const char kApn[] = "TheAPN";
  static const char kUsername[] = "commander.data";
  service_->set_profile(profile_);
  Error error;
  Stringmap testapn;
  testapn[kApnProperty] = kApn;
  testapn[kApnUsernameProperty] = kUsername;
  EXPECT_CALL(*adaptor_, EmitStringmapChanged(kCellularApnProperty, _));
  service_->SetApn(testapn, &error);
  EXPECT_TRUE(error.IsSuccess());
  Stringmap resultapn = service_->GetApn(&error);
  EXPECT_TRUE(error.IsSuccess());
  Stringmap::const_iterator it = resultapn.find(kApnProperty);
  EXPECT_TRUE(it != resultapn.end() && it->second == kApn);
  it = resultapn.find(kApnUsernameProperty);
  EXPECT_TRUE(it != resultapn.end() && it->second == kUsername);
  EXPECT_NE(nullptr, service_->GetUserSpecifiedApn());
}

TEST_F(CellularServiceTest, SetAttachApn) {
  static const char kApn[] = "AttachInternetAPN";
  static const char kUsername[] = "commander.data";
  ProfileRefPtr profile(new NiceMock<MockProfile>(&manager_));
  service_->set_profile(profile);
  Error error;
  Stringmap testapn;
  testapn[kApnProperty] = kApn;
  testapn[kApnUsernameProperty] = kUsername;
  testapn[kApnAttachProperty] = kApnAttachProperty;
  EXPECT_CALL(*adaptor_, EmitStringmapChanged(kCellularApnProperty, _));
  service_->SetApn(testapn, &error);
  EXPECT_TRUE(error.IsSuccess());
  Stringmap resultapn = service_->GetApn(&error);
  EXPECT_TRUE(error.IsSuccess());
  Stringmap::const_iterator it = resultapn.find(kApnProperty);
  EXPECT_TRUE(it != resultapn.end() && it->second == kApn);
  it = resultapn.find(kApnTypesProperty);
  ASSERT_TRUE(it != resultapn.end());
  EXPECT_STREQ(it->second.c_str(), "DEFAULT,IA");
  EXPECT_NE(nullptr, service_->GetUserSpecifiedApn());
}

TEST_F(CellularServiceTest, ClearApn) {
  static const char kApn[] = "TheAPN";
  static const char kUsername[] = "commander.data";
  service_->set_profile(profile_);
  Error error;
  // Set up an APN to make sure that it later gets cleared.
  Stringmap testapn;
  testapn[kApnProperty] = kApn;
  testapn[kApnUsernameProperty] = kUsername;
  EXPECT_CALL(*adaptor_, EmitStringmapChanged(kCellularApnProperty, _));
  service_->SetApn(testapn, &error);
  Stringmap resultapn = service_->GetApn(&error);
  ASSERT_TRUE(error.IsSuccess());

  Stringmap emptyapn;
  EXPECT_CALL(*adaptor_, EmitStringmapChanged(kCellularLastGoodApnProperty, _))
      .Times(0);
  EXPECT_CALL(*adaptor_, EmitStringmapChanged(kCellularApnProperty, _))
      .Times(1);
  service_->SetApn(emptyapn, &error);
  EXPECT_TRUE(error.IsSuccess());
  resultapn = service_->GetApn(&error);
  EXPECT_TRUE(resultapn.empty());
  EXPECT_EQ(nullptr, service_->GetUserSpecifiedApn());
}

TEST_F(CellularServiceTest, LastGoodApn) {
  static const char kApn[] = "TheAPN";
  static const char kUsername[] = "commander.data";
  service_->set_profile(profile_);
  Stringmap testapn;
  testapn[kApnProperty] = kApn;
  testapn[kApnUsernameProperty] = kUsername;
  EXPECT_CALL(*adaptor_, EmitStringmapChanged(kCellularLastGoodApnProperty, _));
  EXPECT_CALL(*adaptor_, EmitStringmapChanged(
                             kCellularLastConnectedDefaultApnProperty, _));
  service_->SetLastGoodApn(testapn);
  Stringmap* resultapn = service_->GetLastGoodApn();
  ASSERT_NE(nullptr, resultapn);
  EXPECT_EQ(kApn, (*resultapn)[kApnProperty]);
  EXPECT_EQ(kUsername, (*resultapn)[kApnUsernameProperty]);
  resultapn = service_->GetLastConnectedDefaultApn();
  ASSERT_NE(nullptr, resultapn);
  EXPECT_EQ(kApn, (*resultapn)[kApnProperty]);
  EXPECT_EQ(kUsername, (*resultapn)[kApnUsernameProperty]);

  // Now set the user-specified APN, and check that LastGoodApn is preserved.
  Stringmap userapn;
  userapn[kApnProperty] = kApn;
  userapn[kApnUsernameProperty] = kUsername;
  EXPECT_CALL(*adaptor_, EmitStringmapChanged(kCellularApnProperty, _));
  Error error;
  service_->SetApn(userapn, &error);

  ASSERT_NE(nullptr, service_->GetLastGoodApn());
  EXPECT_EQ(kApn, (*resultapn)[kApnProperty]);
  EXPECT_EQ(kUsername, (*resultapn)[kApnUsernameProperty]);
}

TEST_F(CellularServiceTest, LastConnectedAttachApn) {
  static const char kApn[] = "TheAPN";
  static const char kUsername[] = "commander.data";
  service_->set_profile(profile_);
  Stringmap testapn;
  testapn[kApnProperty] = kApn;
  testapn[kApnUsernameProperty] = kUsername;
  EXPECT_CALL(*adaptor_,
              EmitStringmapChanged(kCellularLastConnectedAttachApnProperty, _));
  service_->SetLastConnectedAttachApn(testapn);
  Stringmap* resultapn = service_->GetLastConnectedAttachApn();
  ASSERT_NE(nullptr, resultapn);
  EXPECT_EQ(kApn, (*resultapn)[kApnProperty]);
  EXPECT_EQ(kUsername, (*resultapn)[kApnUsernameProperty]);
  ASSERT_TRUE(service_->Save(&storage_));

  // Clear the LastConnectedAttachAPN.
  EXPECT_CALL(*adaptor_,
              EmitStringmapChanged(kCellularLastConnectedAttachApnProperty, _));
  service_->ClearLastConnectedAttachApn();
  ASSERT_EQ(nullptr, service_->GetLastConnectedAttachApn());

  // Load the LastConnectedAttachAPN.
  ASSERT_TRUE(service_->Load(&storage_));
  resultapn = service_->GetLastConnectedAttachApn();
  ASSERT_NE(nullptr, resultapn);
  EXPECT_EQ(kApn, (*resultapn)[kApnProperty]);
  EXPECT_EQ(kUsername, (*resultapn)[kApnUsernameProperty]);

  // Clear the LastConnectedAttachAPN again and save.
  EXPECT_CALL(*adaptor_,
              EmitStringmapChanged(kCellularLastConnectedAttachApnProperty, _));
  service_->ClearLastConnectedAttachApn();
  ASSERT_EQ(nullptr, service_->GetLastConnectedAttachApn());
  ASSERT_TRUE(service_->Save(&storage_));

  // Load the LastConnectedAttachAPN.
  ASSERT_EQ(nullptr, service_->GetLastConnectedAttachApn());
}

TEST_F(CellularServiceTest, IsAutoConnectable) {
  // This test assumes AutoConnect is not disabled by policy.
  EXPECT_CALL(manager_, IsTechnologyAutoConnectDisabled(_))
      .WillRepeatedly(Return(false));

  const char* reason = nullptr;

  // Auto-connect should be suppressed if the device is not enabled.
  device_->enabled_ = false;
  EXPECT_FALSE(IsAutoConnectable(&reason));
  EXPECT_STREQ(CellularService::kAutoConnDeviceDisabled, reason);
  device_->enabled_ = true;

  // Auto-connect should be suppressed if the device is not registered.
  device_->set_state_for_testing(Cellular::State::kDisabled);
  EXPECT_FALSE(IsAutoConnectable(&reason));
  EXPECT_STREQ(CellularService::kAutoConnNotRegistered, reason);
  device_->set_state_for_testing(Cellular::State::kRegistered);

  // Auto-connect should be suppressed if we're out of credits.
  service_->NotifySubscriptionStateChanged(SubscriptionState::kOutOfCredits);
  EXPECT_FALSE(IsAutoConnectable(&reason));
  EXPECT_STREQ(CellularService::kAutoConnOutOfCredits, reason);
  service_->NotifySubscriptionStateChanged(SubscriptionState::kProvisioned);

  // A PPP authentication failure means the Service is not auto-connectable.
  service_->SetFailure(Service::kFailurePPPAuth);
  EXPECT_FALSE(IsAutoConnectable(&reason));
  EXPECT_STREQ(CellularService::kAutoConnBadPPPCredentials, reason);

  // Reset failure state, to make the Service auto-connectable again.
  service_->SetState(Service::kStateIdle);
  EXPECT_TRUE(IsAutoConnectable(&reason));

  // The following test cases are copied from ServiceTest.IsAutoConnectable

  service_->SetConnectable(true);
  EXPECT_TRUE(IsAutoConnectable(&reason));

  // We should not auto-connect to a Service that a user has
  // deliberately disconnected.
  Error error;
  service_->UserInitiatedDisconnect("RPC", &error);
  EXPECT_FALSE(IsAutoConnectable(&reason));
  EXPECT_STREQ(Service::kAutoConnExplicitDisconnect, reason);

  // If the Service is reloaded, it is eligible for auto-connect again.
  EXPECT_TRUE(service_->Load(&storage_));
  EXPECT_TRUE(IsAutoConnectable(&reason));

  // A non-user initiated Disconnect doesn't change anything.
  service_->Disconnect(&error, "in test");
  EXPECT_TRUE(IsAutoConnectable(&reason));

  // A resume also re-enables auto-connect.
  service_->UserInitiatedDisconnect("RPC", &error);
  EXPECT_FALSE(IsAutoConnectable(&reason));
  service_->OnAfterResume();
  EXPECT_TRUE(IsAutoConnectable(&reason));

  service_->SetState(Service::kStateConnected);
  EXPECT_FALSE(IsAutoConnectable(&reason));
  EXPECT_STREQ(Service::kAutoConnConnected, reason);

  service_->SetState(Service::kStateAssociating);
  EXPECT_FALSE(IsAutoConnectable(&reason));
  EXPECT_STREQ(Service::kAutoConnConnecting, reason);
}

TEST_F(CellularServiceTest, LoadResetsPPPAuthFailure) {
  const std::string kDefaultUser;
  const std::string kDefaultPass;
  const std::string kNewUser("new-username");
  const std::string kNewPass("new-password");
  for (const auto change_username : {false, true}) {
    for (const auto change_password : {false, true}) {
      service_->ppp_username_ = kDefaultUser;
      service_->ppp_password_ = kDefaultPass;
      service_->SetFailure(Service::kFailurePPPAuth);
      EXPECT_TRUE(service_->IsFailed());
      EXPECT_EQ(Service::kFailurePPPAuth, service_->failure());
      if (change_username) {
        storage_.SetString(storage_id_, CellularService::kStoragePPPUsername,
                           kNewUser);
      }
      if (change_password) {
        storage_.SetString(storage_id_, CellularService::kStoragePPPPassword,
                           kNewPass);
      }
      EXPECT_TRUE(service_->Load(&storage_));
      if (change_username || change_password) {
        EXPECT_NE(Service::kFailurePPPAuth, service_->failure());
      } else {
        EXPECT_EQ(Service::kFailurePPPAuth, service_->failure());
      }
    }
  }
}

// The default |storage_id_| will be {kCellular}_{kIccid}, however older
// profile/storage entries may use a different identifier. This sets up an entry
// with a matching ICCID but an arbitrary storage id and ensures that the older
// |storage_id_| value is set.
TEST_F(CellularServiceTest, LoadFromProfileMatchingIccid) {
  std::string initial_storage_id = storage_id_;
  std::string matching_storage_id = "another-storage-id";
  storage_.DeleteGroup(initial_storage_id);
  storage_.SetString(matching_storage_id, CellularService::kStorageType,
                     kTypeCellular);
  storage_.SetString(matching_storage_id, CellularService::kStorageIccid,
                     kIccid);
  storage_.SetString(matching_storage_id, CellularService::kStorageImsi, kImsi);

  EXPECT_TRUE(service_->IsLoadableFrom(storage_));
  EXPECT_TRUE(service_->Load(&storage_));
  EXPECT_EQ(matching_storage_id, service_->GetStorageIdentifier());
}

TEST_F(CellularServiceTest, LoadFromFirstOfMultipleMatchingProfiles) {
  std::string initial_storage_id = storage_id_;
  std::string matching_storage_ids[] = {
      "another-storage-id1", "another-storage-id2", "another-storage-id3"};
  storage_.DeleteGroup(initial_storage_id);
  for (auto& matching_storage_id : matching_storage_ids) {
    storage_.SetString(matching_storage_id, CellularService::kStorageType,
                       kTypeCellular);
    storage_.SetString(matching_storage_id, CellularService::kStorageIccid,
                       kIccid);
    storage_.SetString(matching_storage_id, CellularService::kStorageImsi,
                       kImsi);
  }
  EXPECT_TRUE(service_->IsLoadableFrom(storage_));
  EXPECT_TRUE(service_->Load(&storage_));
  EXPECT_EQ(matching_storage_ids[0], service_->GetStorageIdentifier());
}

TEST_F(CellularServiceTest, Save) {
  EXPECT_TRUE(service_->Save(&storage_));
  std::string iccid;
  EXPECT_TRUE(
      storage_.GetString(storage_id_, CellularService::kStorageIccid, &iccid));
  EXPECT_EQ(iccid, device_->iccid());
}

TEST_F(CellularServiceTest, SaveAndLoadApn) {
  static const char kApn[] = "petal.net";
  static const char kUsername[] = "orekid";
  static const char kPassword[] = "arlet";
  static const char kAuthentication[] = "chap";

  std::string attach;
  const std::string attach_key =
      std::string(CellularService::kStorageAPN) + "." + kApnAttachProperty;
  Error error;
  Stringmap testapn;
  testapn[kApnProperty] = kApn;
  testapn[kApnUsernameProperty] = kUsername;
  testapn[kApnPasswordProperty] = kPassword;
  testapn[kApnAuthenticationProperty] = kAuthentication;
  testapn[kApnAttachProperty] = kApnAttachProperty;
  service_->SetApn(testapn, &error);
  ASSERT_TRUE(error.IsSuccess());
  EXPECT_TRUE(service_->Save(&storage_));
  // kApnAttachProperty will be converted into kApnTypesProperty
  EXPECT_FALSE(storage_.GetString(storage_id_, attach_key, &attach));
  EXPECT_TRUE(storage_.GetString(
      storage_id_,
      std::string(CellularService::kStorageAPN) + "." + kApnTypesProperty,
      &attach));

  // Clear the APN, and then load it from storage again.
  Stringmap emptyapn;
  service_->SetApn(emptyapn, &error);
  ASSERT_TRUE(error.IsSuccess());

  EXPECT_TRUE(service_->Load(&storage_));

  Stringmap resultapn = service_->GetApn(&error);
  EXPECT_TRUE(error.IsSuccess());
  EXPECT_EQ(kApn, resultapn[kApnProperty]);
  EXPECT_EQ(kUsername, resultapn[kApnUsernameProperty]);
  EXPECT_EQ(kPassword, resultapn[kApnPasswordProperty]);
  EXPECT_EQ(kAuthentication, resultapn[kApnAuthenticationProperty]);
  EXPECT_TRUE(base::Contains(resultapn, kApnAttachProperty));
  EXPECT_EQ("DEFAULT,IA", resultapn[kApnTypesProperty]);

  // Force storing kApnAttachProperty and reset kApnTypesProperty to verify the
  // value is migrated on Load.
  EXPECT_TRUE(storage_.SetString(storage_id_, attach_key, kApnAttachProperty));
  EXPECT_TRUE(storage_.DeleteKey(storage_id_, kApnTypesProperty));
  EXPECT_TRUE(service_->Save(&storage_));
  EXPECT_TRUE(service_->Load(&storage_));
  resultapn = service_->GetApn(&error);
  EXPECT_TRUE(base::Contains(resultapn, kApnAttachProperty));
  EXPECT_EQ("DEFAULT,IA", resultapn[kApnTypesProperty]);
}

TEST_F(CellularServiceTest, IgnoreUnversionedLastGoodApn) {
  static const char kApn[] = "petal.net";
  static const char kUsername[] = "orekid";
  Stringmap testapn;
  testapn[kApnProperty] = kApn;
  testapn[kApnUsernameProperty] = kUsername;
  EXPECT_CALL(*adaptor_, EmitStringmapChanged(kCellularLastGoodApnProperty, _));
  EXPECT_CALL(*adaptor_, EmitStringmapChanged(
                             kCellularLastConnectedDefaultApnProperty, _));
  service_->SetLastGoodApn(testapn);
  ASSERT_TRUE(service_->Save(&storage_));
  EXPECT_NE(nullptr, service_->GetLastGoodApn());
  EXPECT_NE(nullptr, service_->GetLastConnectedDefaultApn());

  // Clear the LastGoodAPN. The LastConnectedDefaultAPN should be unaffected.
  EXPECT_CALL(*adaptor_, EmitStringmapChanged(kCellularLastGoodApnProperty, _));
  EXPECT_CALL(*adaptor_,
              EmitStringmapChanged(kCellularLastConnectedDefaultApnProperty, _))
      .Times(0);
  service_->ClearLastGoodApn();
  EXPECT_EQ(nullptr, service_->GetLastGoodApn());
  EXPECT_NE(nullptr, service_->GetLastConnectedDefaultApn());

  // Force the LastConnectedDefaultAPN to be cleared.
  service_->GetLastConnectedDefaultApn()->clear();

  // Load the LastGoodAPN and LastConnectedDefaultAPN. The LastGoodAPN should be
  // ignored.
  ASSERT_TRUE(service_->Load(&storage_));
  EXPECT_EQ(nullptr, service_->GetLastGoodApn());
  Stringmap* resultapn = service_->GetLastConnectedDefaultApn();
  EXPECT_NE(nullptr, resultapn);
  EXPECT_EQ(kApn, (*resultapn)[kApnProperty]);
  EXPECT_EQ(kUsername, (*resultapn)[kApnUsernameProperty]);
}

TEST_F(CellularServiceTest, MergeDetailsFromApnList) {
  static const char kApn[] = "petal.net";
  static const char kUsername[] = "orekid";
  static const char kPassword[] = "arlet";
  static const char kAuthentication[] = "chap";
  Stringmap fullapn;
  fullapn[kApnProperty] = kApn;
  fullapn[kApnUsernameProperty] = kUsername;
  fullapn[kApnPasswordProperty] = kPassword;
  fullapn[kApnAuthenticationProperty] = kAuthentication;
  Stringmaps apn_list{fullapn};
  device_->SetApnList(apn_list);

  // Just set an APN with only the name. Check that we are using
  // the rest of the details.
  Error error;
  Stringmap testapn;
  testapn[kApnProperty] = kApn;
  service_->SetApn(testapn, &error);

  Stringmap resultapn = service_->GetApn(&error);
  EXPECT_TRUE(error.IsSuccess());
  EXPECT_EQ(kApn, resultapn[kApnProperty]);
  EXPECT_EQ(kUsername, resultapn[kApnUsernameProperty]);
  EXPECT_EQ(kPassword, resultapn[kApnPasswordProperty]);
  EXPECT_EQ(kAuthentication, resultapn[kApnAuthenticationProperty]);
}

// Some of these tests duplicate signals tested above. However, it's
// convenient to have all the property change notifications documented
// (and tested) in one place.
TEST_F(CellularServiceTest, PropertyChanges) {
  TestCommonPropertyChanges(service_, adaptor_);
  TestAutoConnectPropertyChange(service_, adaptor_);

  EXPECT_CALL(*adaptor_, EmitStringChanged(kActivationTypeProperty, _));
  service_->SetActivationType(CellularService::kActivationTypeOTA);
  Mock::VerifyAndClearExpectations(adaptor_);

  EXPECT_NE(kActivationStateNotActivated, service_->activation_state());
  EXPECT_CALL(*adaptor_, EmitStringChanged(kActivationStateProperty, _));
  service_->SetActivationState(kActivationStateNotActivated);
  Mock::VerifyAndClearExpectations(adaptor_);

  std::string network_technology = service_->network_technology();
  EXPECT_CALL(*adaptor_, EmitStringChanged(kNetworkTechnologyProperty, _));
  service_->SetNetworkTechnology(network_technology + "and some new stuff");
  Mock::VerifyAndClearExpectations(adaptor_);

  EXPECT_CALL(*adaptor_, EmitBoolChanged(kOutOfCreditsProperty, true));
  service_->NotifySubscriptionStateChanged(SubscriptionState::kOutOfCredits);
  Mock::VerifyAndClearExpectations(adaptor_);
  EXPECT_CALL(*adaptor_, EmitBoolChanged(kOutOfCreditsProperty, false));
  service_->NotifySubscriptionStateChanged(SubscriptionState::kProvisioned);
  Mock::VerifyAndClearExpectations(adaptor_);

  std::string roaming_state = service_->roaming_state();
  EXPECT_CALL(*adaptor_, EmitStringChanged(kRoamingStateProperty, _));
  service_->SetRoamingState(roaming_state + "and some new stuff");
  Mock::VerifyAndClearExpectations(adaptor_);
}

// Overriding the APN value with the same value should not result in a failure.
TEST_F(CellularServiceTest, CustomSetterNoopChange) {
  // Test that we didn't break any setters provided by the base class.
  TestCustomSetterNoopChange(service_, &manager_);

  // Test the new setter we added.
  // First set up our environment...
  static const char kApn[] = "TheAPN";
  static const char kUsername[] = "commander.data";
  Error error;
  Stringmap testapn;
  service_->set_profile(profile_);
  testapn[kApnProperty] = kApn;
  testapn[kApnUsernameProperty] = kUsername;
  // ... then set to a known value ...
  EXPECT_TRUE(service_->SetApn(testapn, &error));
  EXPECT_TRUE(error.IsSuccess());
  // ... then set to same value.
  EXPECT_TRUE(service_->SetApn(testapn, &error));
  EXPECT_TRUE(error.IsSuccess());
}

TEST_F(CellularServiceTest, IsMeteredByDefault) {
  // These services should be metered by default.
  EXPECT_TRUE(service_->IsMetered());
}

TEST_F(CellularServiceTest, SetActivationState) {
  // SetActivationState should emit a change.
  EXPECT_CALL(*adaptor_, EmitStringChanged(kActivationStateProperty,
                                           kActivationStateNotActivated));
  service_->SetActivationState(kActivationStateNotActivated);
  EXPECT_EQ(service_->activation_state(), kActivationStateNotActivated);
  EXPECT_CALL(*adaptor_, EmitStringChanged(kActivationStateProperty, _))
      .Times(AnyNumber());

  // Setting the activation state to activated should also set AutoConnect.
  EXPECT_FALSE(service_->auto_connect());
  service_->SetActivationState(kActivationStateActivated);
  EXPECT_EQ(service_->activation_state(), kActivationStateActivated);
  EXPECT_TRUE(service_->auto_connect());

  // After a client sets AutoConnect to false, setting the activation state to
  // activated should not set AutoConnect.
  SetAutoConnectFull(false);
  EXPECT_FALSE(service_->auto_connect());
  service_->SetActivationState(kActivationStateNotActivated);
  EXPECT_EQ(service_->activation_state(), kActivationStateNotActivated);
  EXPECT_FALSE(service_->auto_connect());
  service_->SetActivationState(kActivationStateActivated);
  EXPECT_EQ(service_->activation_state(), kActivationStateActivated);
  EXPECT_FALSE(service_->auto_connect());
}

TEST_F(CellularServiceTest, SetAllowRoaming) {
  Error error;
  service_->SetRoamingState(kRoamingStateRoaming);
  service_->SetAllowRoaming(true, &error);

  // Check that disallowing roaming while on a roaming network leads to a
  // disconnect
  EXPECT_CALL(*adaptor_, EmitBoolChanged(kCellularAllowRoamingProperty, _))
      .Times(2);
  EXPECT_CALL(*device_, Disconnect(_, _)).Times(1);
  service_->SetAllowRoaming(false, &error);
  EXPECT_EQ(error.IsSuccess(), true);

  // Check that Disconnect isn't called if roaming is allowed
  EXPECT_CALL(*device_, Disconnect(_, _)).Times(0);
  service_->SetAllowRoaming(true, &error);
  EXPECT_EQ(error.IsSuccess(), true);
}

TEST_F(CellularServiceTest, SetRoamingState) {
  // Check that a change in roaming state is advertised on dbus
  EXPECT_CALL(*adaptor_,
              EmitStringChanged(kRoamingStateProperty, kRoamingStateHome));
  EXPECT_TRUE(service_->roaming_state().empty());
  service_->SetRoamingState(kRoamingStateHome);
  EXPECT_EQ(kRoamingStateHome, service_->roaming_state());

  // Check that a disconnect occurs if we begin roaming when it isn't allowed.
  service_->set_allow_roaming(false);
  EXPECT_CALL(*device_, Disconnect(_, _)).Times(1);
  EXPECT_CALL(*adaptor_,
              EmitStringChanged(kRoamingStateProperty, kRoamingStateRoaming));
  service_->SetRoamingState(kRoamingStateRoaming);
}

}  // namespace shill
