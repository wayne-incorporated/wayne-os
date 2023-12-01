// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "attestation/common/tpm_utility_common.h"

#include <utility>
#include <vector>

#include <base/logging.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <libhwsec-foundation/tpm/tpm_version.h>
#include <tpm_manager-client/tpm_manager/dbus-constants.h>
#include <tpm_manager/client/mock_tpm_manager_utility.h>

#if USE_TPM2
#include <trunks/trunks_factory_for_test.h>

#include "attestation/common/tpm_utility_v2.h"
#endif

#if USE_TPM1
#include "attestation/common/tpm_utility_v1.h"
#endif

namespace {

using ::testing::_;
using ::testing::DoAll;
using ::testing::NiceMock;
using ::testing::NotNull;
using ::testing::Return;
using ::testing::SetArgPointee;
using ::testing::Types;
}  // namespace

namespace attestation {

class TpmUtilityCommonTest : public ::testing::Test {
 public:
  ~TpmUtilityCommonTest() override = default;
  void SetUp() override {
    SET_DEFAULT_TPM_FOR_TESTING;

    TPM_SELECT_BEGIN;
    TPM1_SECTION({
      tpm_utility_ = std::make_unique<TpmUtilityV1>(&mock_tpm_manager_utility_);
    });
    TPM2_SECTION({
      tpm_utility_ = std::make_unique<TpmUtilityV2>(&mock_tpm_manager_utility_,
                                                    &trunks_factory_for_test_);
    });
    OTHER_TPM_SECTION();
    TPM_SELECT_END;
  }

 protected:
  void OnOwnershipTakenSignal() { tpm_utility_->OnOwnershipTakenSignal(); }
  // Checks if GetTpmStatus sets up the private data member.
  void VerifyAgainstExpectedLocalData(const tpm_manager::LocalData local_data) {
    EXPECT_EQ(tpm_utility_->owner_password_, local_data.owner_password());
    EXPECT_EQ(tpm_utility_->endorsement_password_,
              local_data.endorsement_password());
    EXPECT_EQ(tpm_utility_->delegate_blob_, local_data.owner_delegate().blob());
    EXPECT_EQ(tpm_utility_->delegate_secret_,
              local_data.owner_delegate().secret());
  }

  NiceMock<tpm_manager::MockTpmManagerUtility> mock_tpm_manager_utility_;
  std::unique_ptr<TpmUtilityCommon> tpm_utility_;

#if USE_TPM2
  trunks::TrunksFactoryForTest trunks_factory_for_test_;
#endif
};

TEST_F(TpmUtilityCommonTest, IsTpmReadySuccess) {
  EXPECT_CALL(this->mock_tpm_manager_utility_, GetTpmStatus(_, _, _))
      .WillOnce(
          DoAll(SetArgPointee<0>(true), SetArgPointee<1>(true), Return(true)));
  EXPECT_TRUE(this->tpm_utility_->IsTpmReady());
}

TEST_F(TpmUtilityCommonTest, IsTpmReadyNotOwned) {
  EXPECT_CALL(this->mock_tpm_manager_utility_, GetTpmStatus(_, _, _))
      .WillOnce(
          DoAll(SetArgPointee<0>(true), SetArgPointee<1>(false), Return(true)));
  EXPECT_FALSE(this->tpm_utility_->IsTpmReady());
}

TEST_F(TpmUtilityCommonTest, IsTpmReadyWithOwnershipTakenSignal) {
  EXPECT_CALL(this->mock_tpm_manager_utility_, GetTpmStatus(_, _, _))
      .WillOnce(Return(false));
  EXPECT_FALSE(this->tpm_utility_->IsTpmReady());
  EXPECT_FALSE(this->tpm_utility_->IsTpmReady());

  this->OnOwnershipTakenSignal();
  EXPECT_TRUE(this->tpm_utility_->IsTpmReady());
}

TEST_F(TpmUtilityCommonTest, IsTpmReadyCallsCacheTpmState) {
  tpm_manager::LocalData expected_local_data;
  expected_local_data.set_owner_password("Uvuvwevwevwe");
  expected_local_data.set_endorsement_password("Onyetenyevwe");
  expected_local_data.mutable_owner_delegate()->set_blob("Ugwemuhwem");
  expected_local_data.mutable_owner_delegate()->set_secret("Osas");
  EXPECT_CALL(this->mock_tpm_manager_utility_, GetTpmStatus(_, _, _))
      .WillOnce(DoAll(SetArgPointee<2>(expected_local_data), Return(true)));
  this->tpm_utility_->IsTpmReady();
  this->VerifyAgainstExpectedLocalData(expected_local_data);
}

TEST_F(TpmUtilityCommonTest, RemoveOwnerDependency) {
  EXPECT_CALL(
      this->mock_tpm_manager_utility_,
      RemoveOwnerDependency(tpm_manager::kTpmOwnerDependency_Attestation))
      .WillOnce(Return(false))
      .WillOnce(Return(true));
  EXPECT_FALSE(this->tpm_utility_->RemoveOwnerDependency());
  EXPECT_TRUE(this->tpm_utility_->RemoveOwnerDependency());
}

}  // namespace attestation
