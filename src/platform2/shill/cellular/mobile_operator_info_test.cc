// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/cellular/mobile_operator_info.h"

#include <map>
#include <memory>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <base/check_op.h>
#include <base/files/file_path.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "shill/cellular/mobile_operator_mapper.h"
#include "shill/cellular/mock_mobile_operator_mapper.h"
#include "shill/test_event_dispatcher.h"

using testing::_;
using testing::Mock;
using testing::Return;
using testing::ReturnRef;
using testing::Test;
using testing::Values;
using testing::WithParamInterface;
namespace shill {
class MockMobileOperatorInfoObserver : public MobileOperatorInfo::Observer {
 public:
  MockMobileOperatorInfoObserver() = default;

  MOCK_METHOD(void, OnOperatorChanged, (), (override));
};

class MobileOperatorInfoTestHelper : public MobileOperatorInfo {
 public:
  explicit MobileOperatorInfoTestHelper(EventDispatcher* dispatcher,
                                        const std::string& info_owner,
                                        MobileOperatorMapper* home,
                                        MobileOperatorMapper* serving)
      : MobileOperatorInfo(dispatcher, info_owner, home, serving) {}
  using MobileOperatorInfo::kDefaultDatabasePath;
  using MobileOperatorInfo::kExclusiveOverrideDatabasePath;
};

class MobileOperatorInfoTest : public Test {
 public:
  MobileOperatorInfoTest()
      : kModbName("placeholder_modb.textproto"),
        kModbPath(base::FilePath(kModbName)),
        home_(new testing::StrictMock<MockMobileOperatorMapper>(&dispatcher_,
                                                                "home")),
        serving_(new testing::StrictMock<MockMobileOperatorMapper>(&dispatcher_,
                                                                   "serving")) {
    // The default modb is added in the constructor
    EXPECT_CALL(*home_,
                AddDatabasePath(base::FilePath(
                    MobileOperatorInfoTestHelper::kDefaultDatabasePath)));
    EXPECT_CALL(*serving_,
                AddDatabasePath(base::FilePath(
                    MobileOperatorInfoTestHelper::kDefaultDatabasePath)));
    operator_info_ = std::make_unique<MobileOperatorInfoTestHelper>(
        &dispatcher_, "Operator", home_, serving_);
    Mock::VerifyAndClearExpectations(&home_);
    Mock::VerifyAndClearExpectations(&serving_);
  }
  MobileOperatorInfoTest(const MobileOperatorInfoTest&) = delete;
  MobileOperatorInfoTest& operator=(const MobileOperatorInfoTest&) = delete;

  void SetUp() override {}

  bool SetUpDatabase(const std::vector<std::string>& files) {
    EXPECT_CALL(*home_, ClearDatabasePaths());
    EXPECT_CALL(*serving_, ClearDatabasePaths());
    operator_info_->ClearDatabasePaths();
    for (const auto& file : files) {
      const auto path = base::FilePath(file);
      EXPECT_CALL(*home_, AddDatabasePath(path));
      EXPECT_CALL(*serving_, AddDatabasePath(path));
      operator_info_->AddDatabasePath(path);
      Mock::VerifyAndClearExpectations(&home_);
      Mock::VerifyAndClearExpectations(&serving_);
    }
    EXPECT_CALL(*home_, Init(_)).WillOnce(Return(true));
    EXPECT_CALL(*serving_, Init(_)).WillOnce(Return(true));
    return operator_info_->Init();
  }

 protected:
  const std::string kModbName;
  const base::FilePath kModbPath;

  EventDispatcherForTest dispatcher_;
  std::unique_ptr<MobileOperatorInfoTestHelper> operator_info_;
  MockMobileOperatorMapper* home_;
  MockMobileOperatorMapper* serving_;
};

TEST_F(MobileOperatorInfoTest, AddDatabasePath) {
  EXPECT_CALL(*home_, AddDatabasePath(kModbPath));
  EXPECT_CALL(*serving_, AddDatabasePath(kModbPath));
  operator_info_->AddDatabasePath(kModbPath);
  std::cerr << "TODO(remove)\n\n";
  Mock::VerifyAndClearExpectations(&home_);
  Mock::VerifyAndClearExpectations(&serving_);
}

TEST_F(MobileOperatorInfoTest, ClearDatabasePaths) {
  EXPECT_CALL(*home_, ClearDatabasePaths());
  EXPECT_CALL(*serving_, ClearDatabasePaths());
  operator_info_->ClearDatabasePaths();
}

TEST_F(MobileOperatorInfoTest, Init) {
  EXPECT_CALL(*home_, Init(_)).WillOnce(Return(true));
  EXPECT_CALL(*serving_, Init(_)).WillOnce(Return(true));
  EXPECT_TRUE(operator_info_->Init());
}

TEST_F(MobileOperatorInfoTest, InitHomeFail) {
  EXPECT_CALL(*home_, Init(_)).WillOnce(Return(false));
  EXPECT_CALL(*serving_, Init(_)).WillOnce(Return(true));
  EXPECT_FALSE(operator_info_->Init());
}

TEST_F(MobileOperatorInfoTest, InitServingFail) {
  EXPECT_CALL(*home_, Init(_)).WillOnce(Return(true));
  EXPECT_CALL(*serving_, Init(_)).WillOnce(Return(false));
  EXPECT_FALSE(operator_info_->Init());
}

TEST_F(MobileOperatorInfoTest, InitWithObserver) {
  MockMobileOperatorInfoObserver observer;
  EXPECT_TRUE(SetUpDatabase({kModbName}));
  operator_info_->AddObserver(&observer);
  EXPECT_CALL(*home_, Init(_)).WillOnce(Return(true));
  EXPECT_CALL(*serving_, Init(_)).WillOnce(Return(true));
  EXPECT_TRUE(operator_info_->Init());
}

class MobileOperatorInfoMainTest : public MobileOperatorInfoTest {
 public:
  MobileOperatorInfoMainTest() {}
  MobileOperatorInfoMainTest(const MobileOperatorInfoMainTest&) = delete;
  MobileOperatorInfoMainTest& operator=(const MobileOperatorInfoMainTest&) =
      delete;

  void SetUp() override {
    operator_info_->AddObserver(&observer_);
    EXPECT_TRUE(SetUpDatabase({kModbName}));
    Mock::VerifyAndClearExpectations(&home_);
    Mock::VerifyAndClearExpectations(&serving_);
  }

  // ///////////////////////////////////////////////////////////////////////////
  // Data.
  MockMobileOperatorInfoObserver observer_;
};

TEST_F(MobileOperatorInfoMainTest, IsMobileNetworkOperatorKnown) {
  EXPECT_CALL(*home_, IsMobileNetworkOperatorKnown()).WillOnce(Return(true));
  EXPECT_TRUE(operator_info_->IsMobileNetworkOperatorKnown());

  EXPECT_CALL(*home_, IsMobileNetworkOperatorKnown()).WillOnce(Return(false));
  EXPECT_FALSE(operator_info_->IsMobileNetworkOperatorKnown());
}

TEST_F(MobileOperatorInfoMainTest, IsServingMobileNetworkOperatorKnown) {
  EXPECT_CALL(*serving_, IsMobileNetworkOperatorKnown()).WillOnce(Return(true));
  EXPECT_TRUE(operator_info_->IsServingMobileNetworkOperatorKnown());

  EXPECT_CALL(*serving_, IsMobileNetworkOperatorKnown())
      .WillOnce(Return(false));
  EXPECT_FALSE(operator_info_->IsServingMobileNetworkOperatorKnown());
}

TEST_F(MobileOperatorInfoMainTest, uuid) {
  const std::string uuid = "uuid";
  EXPECT_CALL(*home_, uuid()).WillOnce(ReturnRef(uuid));
  EXPECT_EQ(operator_info_->uuid(), uuid);
}

TEST_F(MobileOperatorInfoMainTest, operator_name) {
  const std::string operator_name = "operator_name";
  EXPECT_CALL(*home_, operator_name()).WillOnce(ReturnRef(operator_name));
  EXPECT_EQ(operator_info_->operator_name(), operator_name);
}

TEST_F(MobileOperatorInfoMainTest, country) {
  const std::string country = "country";
  EXPECT_CALL(*home_, country()).WillOnce(ReturnRef(country));
  EXPECT_EQ(operator_info_->country(), country);
}

TEST_F(MobileOperatorInfoMainTest, mccmnc) {
  const std::string mccmnc = "mccmnc";
  EXPECT_CALL(*home_, mccmnc()).WillOnce(ReturnRef(mccmnc));
  EXPECT_EQ(operator_info_->mccmnc(), mccmnc);
}

TEST_F(MobileOperatorInfoMainTest, gid1) {
  const std::string gid1 = "gid1";
  EXPECT_CALL(*home_, gid1()).WillOnce(ReturnRef(gid1));
  EXPECT_EQ(operator_info_->gid1(), gid1);
}

TEST_F(MobileOperatorInfoMainTest, serving_uuid) {
  const std::string uuid = "serving_uuid";
  EXPECT_CALL(*serving_, uuid()).WillOnce(ReturnRef(uuid));
  EXPECT_EQ(operator_info_->serving_uuid(), uuid);
}

TEST_F(MobileOperatorInfoMainTest, serving_operator_name) {
  const std::string operator_name = "operator_name";
  EXPECT_CALL(*serving_, operator_name()).WillOnce(ReturnRef(operator_name));
  EXPECT_EQ(operator_info_->serving_operator_name(), operator_name);
}

TEST_F(MobileOperatorInfoMainTest, serving_country) {
  const std::string country = "country";
  EXPECT_CALL(*serving_, country()).WillOnce(ReturnRef(country));
  EXPECT_EQ(operator_info_->serving_country(), country);
}

TEST_F(MobileOperatorInfoMainTest, serving_mccmnc) {
  const std::string mccmnc = "mccmnc";
  EXPECT_CALL(*serving_, mccmnc()).WillOnce(ReturnRef(mccmnc));
  EXPECT_EQ(operator_info_->serving_mccmnc(), mccmnc);
}

TEST_F(MobileOperatorInfoMainTest, FriendlyOperatorNameKnownOperatorName) {
  const std::string serving_name = "serving";
  const std::string home_name = "home";
  const std::string serving_mccmnc = "001001";
  const std::string home_mccmnc = "002002";
  EXPECT_CALL(*serving_, operator_name())
      .WillRepeatedly(ReturnRef(serving_name));
  EXPECT_CALL(*serving_, mccmnc()).WillRepeatedly(ReturnRef(serving_mccmnc));
  EXPECT_CALL(*home_, operator_name()).WillRepeatedly(ReturnRef(home_name));
  EXPECT_CALL(*home_, mccmnc()).WillRepeatedly(ReturnRef(home_mccmnc));

  // Serving mobile network operator known
  // Roaming
  EXPECT_CALL(*serving_, IsMobileNetworkOperatorKnown()).WillOnce(Return(true));
  EXPECT_EQ(operator_info_->friendly_operator_name(true), "home | serving");
  // Not roaming
  EXPECT_CALL(*serving_, IsMobileNetworkOperatorKnown()).WillOnce(Return(true));
  EXPECT_EQ(operator_info_->friendly_operator_name(false), "serving");

  // Serving mobile network operator not known
  // Roaming
  EXPECT_CALL(*serving_, IsMobileNetworkOperatorKnown())
      .WillOnce(Return(false));
  EXPECT_CALL(*home_, IsMobileNetworkOperatorKnown()).WillOnce(Return(true));
  EXPECT_EQ(operator_info_->friendly_operator_name(true), "home");
  // Not roaming
  EXPECT_CALL(*serving_, IsMobileNetworkOperatorKnown())
      .WillOnce(Return(false));
  EXPECT_CALL(*home_, IsMobileNetworkOperatorKnown()).WillOnce(Return(true));
  EXPECT_EQ(operator_info_->friendly_operator_name(false), "home");
}

TEST_F(MobileOperatorInfoMainTest, FriendlyOperatorNameUnknownOperatorName) {
  const std::string serving_name = "";
  const std::string home_name = "";
  const std::string serving_mccmnc = "001001";
  const std::string home_mccmnc = "002002";
  EXPECT_CALL(*serving_, operator_name())
      .WillRepeatedly(ReturnRef(serving_name));
  EXPECT_CALL(*serving_, mccmnc()).WillRepeatedly(ReturnRef(serving_mccmnc));
  EXPECT_CALL(*home_, operator_name()).WillRepeatedly(ReturnRef(home_name));
  EXPECT_CALL(*home_, mccmnc()).WillRepeatedly(ReturnRef(home_mccmnc));

  // Serving mobile network operator known
  // Roaming
  EXPECT_CALL(*serving_, IsMobileNetworkOperatorKnown()).WillOnce(Return(true));
  EXPECT_EQ(operator_info_->friendly_operator_name(true), "cellular_001001");
  // Not roaming
  EXPECT_CALL(*serving_, IsMobileNetworkOperatorKnown()).WillOnce(Return(true));
  EXPECT_EQ(operator_info_->friendly_operator_name(false), "cellular_001001");

  // Serving mobile network operator not known
  // Roaming
  EXPECT_CALL(*serving_, IsMobileNetworkOperatorKnown())
      .WillOnce(Return(false));
  EXPECT_CALL(*home_, IsMobileNetworkOperatorKnown()).WillOnce(Return(true));
  EXPECT_EQ(operator_info_->friendly_operator_name(true), "cellular_002002");
  // Not roaming
  EXPECT_CALL(*serving_, IsMobileNetworkOperatorKnown())
      .WillOnce(Return(false));
  EXPECT_CALL(*home_, IsMobileNetworkOperatorKnown()).WillOnce(Return(true));
  EXPECT_EQ(operator_info_->friendly_operator_name(false), "cellular_002002");
}

TEST_F(MobileOperatorInfoMainTest, apn_list) {
  MobileOperatorMapper::MobileAPN apn1;
  apn1.apn = "apn1";
  MobileOperatorMapper::MobileAPN apn2;
  apn2.apn = "apn1";
  std::vector<MobileOperatorMapper::MobileAPN> apns = {apn1, apn2};
  EXPECT_CALL(*home_, apn_list()).WillOnce(ReturnRef(apns));
  EXPECT_EQ(operator_info_->apn_list(), apns);
}

TEST_F(MobileOperatorInfoMainTest, olp_list) {
  MobileOperatorMapper::OnlinePortal olp1;
  olp1.url = "url1";
  MobileOperatorMapper::OnlinePortal olp2;
  olp2.url = "url2";
  std::vector<MobileOperatorMapper::OnlinePortal> olps = {olp1, olp2};
  EXPECT_CALL(*home_, olp_list()).WillOnce(ReturnRef(olps));
  EXPECT_EQ(operator_info_->olp_list(), olps);
}

TEST_F(MobileOperatorInfoMainTest, requires_roaming_set_on_home) {
  EXPECT_CALL(*home_, IsMobileNetworkOperatorKnown()).WillOnce(Return(true));
  EXPECT_CALL(*home_, requires_roaming()).WillOnce(Return(true));
  EXPECT_TRUE(operator_info_->requires_roaming());
}

TEST_F(MobileOperatorInfoMainTest, tethering_allowed) {
  EXPECT_CALL(*home_, tethering_allowed()).WillOnce(Return(true));
  EXPECT_TRUE(operator_info_->tethering_allowed());
  EXPECT_CALL(*home_, tethering_allowed()).WillOnce(Return(false));
  EXPECT_FALSE(operator_info_->tethering_allowed());
}

TEST_F(MobileOperatorInfoMainTest, use_dun_apn_as_default) {
  EXPECT_CALL(*home_, use_dun_apn_as_default()).WillOnce(Return(true));
  EXPECT_TRUE(operator_info_->use_dun_apn_as_default());
  EXPECT_CALL(*home_, use_dun_apn_as_default()).WillOnce(Return(false));
  EXPECT_FALSE(operator_info_->use_dun_apn_as_default());
}

TEST_F(MobileOperatorInfoMainTest, entitlement_config) {
  MobileOperatorMapper::EntitlementConfig config;
  std::string imsi = "12345";
  config.url = "url.com";
  config.params = {{"imsi", imsi}};
  config.method = "POST";
  EXPECT_CALL(*home_, entitlement_config())
      .Times(3)
      .WillRepeatedly(ReturnRef(config));

  EXPECT_EQ(operator_info_->entitlement_config().url, config.url);
  EXPECT_EQ(operator_info_->entitlement_config().params, config.params);
  EXPECT_EQ(operator_info_->entitlement_config().method, config.method);
}

}  // namespace shill
