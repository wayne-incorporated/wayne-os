// Copyright 2015 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "tpm_manager/server/tpm2_status_impl.h"

#include <memory>

#include <base/functional/bind.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <trunks/cr50_headers/ap_ro_status.h>
#include <trunks/mock_tpm_state.h>
#include <trunks/mock_tpm_utility.h>
#include <trunks/tpm_constants.h>
#include <trunks/trunks_factory_for_test.h>

#include "tpm_manager/common/typedefs.h"

using testing::_;
using testing::Invoke;
using testing::NiceMock;
using testing::Return;
using testing::SetArgPointee;
using trunks::TPM_RC_FAILURE;
using trunks::TPM_RC_SUCCESS;

namespace tpm_manager {

class Tpm2StatusTest : public testing::Test {
 public:
  Tpm2StatusTest() = default;
  ~Tpm2StatusTest() override = default;

  void SetUp() override {
    factory_.set_tpm_state(&mock_tpm_state_);
    factory_.set_tpm_utility(&mock_tpm_utility_);
    tpm_status_.reset(new Tpm2StatusImpl(factory_));
  }

 protected:
  NiceMock<trunks::MockTpmState> mock_tpm_state_;
  NiceMock<trunks::MockTpmUtility> mock_tpm_utility_;
  trunks::TrunksFactoryForTest factory_;
  std::unique_ptr<TpmStatus> tpm_status_;
};

TEST_F(Tpm2StatusTest, IsEnabledAlwaysSuccess) {
  EXPECT_CALL(mock_tpm_state_, Initialize()).Times(0);
  EXPECT_TRUE(tpm_status_->IsTpmEnabled());
}

TEST_F(Tpm2StatusTest, IsOwnedSuccess) {
  EXPECT_CALL(mock_tpm_state_, Initialize())
      .WillRepeatedly(Return(TPM_RC_SUCCESS));
  EXPECT_CALL(mock_tpm_state_, IsOwned()).WillRepeatedly(Return(true));
  EXPECT_CALL(mock_tpm_state_, IsOwnerPasswordSet())
      .WillRepeatedly(Return(true));

  EXPECT_CALL(mock_tpm_utility_, GetKeyPublicArea(trunks::kStorageRootKey, _))
      .WillRepeatedly(
          Invoke([](trunks::TPM_HANDLE, trunks::TPMT_PUBLIC* public_area) {
            memset(public_area, 0, sizeof(trunks::TPMT_PUBLIC));
            public_area->object_attributes =
                trunks::kSensitiveDataOrigin | trunks::kUserWithAuth |
                trunks::kNoDA | trunks::kRestricted | trunks::kDecrypt;
            return TPM_RC_SUCCESS;
          }));

  TpmStatus::TpmOwnershipStatus status;
  EXPECT_TRUE(tpm_status_->GetTpmOwned(&status));
  EXPECT_EQ(TpmStatus::kTpmOwned, status);
}

TEST_F(Tpm2StatusTest, IsOwnedWrongAttributes) {
  EXPECT_CALL(mock_tpm_state_, Initialize())
      .WillRepeatedly(Return(TPM_RC_SUCCESS));
  EXPECT_CALL(mock_tpm_state_, IsOwned()).WillRepeatedly(Return(true));
  EXPECT_CALL(mock_tpm_state_, IsOwnerPasswordSet())
      .WillRepeatedly(Return(true));

  EXPECT_CALL(mock_tpm_utility_, GetKeyPublicArea(trunks::kStorageRootKey, _))
      .WillRepeatedly(
          Invoke([](trunks::TPM_HANDLE, trunks::TPMT_PUBLIC* public_area) {
            memset(public_area, 0, sizeof(trunks::TPMT_PUBLIC));
            return TPM_RC_SUCCESS;
          }));
  TpmStatus::TpmOwnershipStatus status;
  EXPECT_TRUE(tpm_status_->GetTpmOwned(&status));
  EXPECT_EQ(TpmStatus::kTpmPreOwned, status);
}

TEST_F(Tpm2StatusTest, IsOwnedNoSrk) {
  EXPECT_CALL(mock_tpm_state_, Initialize())
      .WillRepeatedly(Return(TPM_RC_SUCCESS));
  EXPECT_CALL(mock_tpm_state_, IsOwned()).WillRepeatedly(Return(true));
  EXPECT_CALL(mock_tpm_state_, IsOwnerPasswordSet())
      .WillRepeatedly(Return(true));
  EXPECT_CALL(mock_tpm_utility_, GetKeyPublicArea(trunks::kStorageRootKey, _))
      .WillRepeatedly(Return(TPM_RC_FAILURE));

  TpmStatus::TpmOwnershipStatus status;
  EXPECT_TRUE(tpm_status_->GetTpmOwned(&status));
  EXPECT_EQ(TpmStatus::kTpmPreOwned, status);
}

TEST_F(Tpm2StatusTest, IsOwnedFailure) {
  EXPECT_CALL(mock_tpm_state_, IsOwned()).WillRepeatedly(Return(false));
  EXPECT_CALL(mock_tpm_state_, IsOwnerPasswordSet())
      .WillRepeatedly(Return(false));

  TpmStatus::TpmOwnershipStatus status;
  EXPECT_TRUE(tpm_status_->GetTpmOwned(&status));
  EXPECT_EQ(TpmStatus::kTpmUnowned, status);
}

TEST_F(Tpm2StatusTest, IsOwnedRepeatedInitializationOnFalse) {
  EXPECT_CALL(mock_tpm_state_, Initialize())
      .Times(2)
      .WillRepeatedly(Return(TPM_RC_SUCCESS));
  EXPECT_CALL(mock_tpm_state_, IsOwned()).WillOnce(Return(false));
  EXPECT_CALL(mock_tpm_state_, IsOwnerPasswordSet())
      .WillRepeatedly(Return(false));
  EXPECT_CALL(mock_tpm_utility_, GetKeyPublicArea(trunks::kStorageRootKey, _))
      .WillRepeatedly(Return(TPM_RC_FAILURE));

  TpmStatus::TpmOwnershipStatus status;
  EXPECT_TRUE(tpm_status_->GetTpmOwned(&status));
  EXPECT_EQ(TpmStatus::kTpmUnowned, status);

  EXPECT_CALL(mock_tpm_state_, IsOwned()).WillRepeatedly(Return(true));
  EXPECT_CALL(mock_tpm_utility_, GetKeyPublicArea(trunks::kStorageRootKey, _))
      .WillRepeatedly(
          Invoke([](trunks::TPM_HANDLE, trunks::TPMT_PUBLIC* public_area) {
            memset(public_area, 0, sizeof(trunks::TPMT_PUBLIC));
            public_area->object_attributes =
                trunks::kSensitiveDataOrigin | trunks::kUserWithAuth |
                trunks::kNoDA | trunks::kRestricted | trunks::kDecrypt;
            return TPM_RC_SUCCESS;
          }));

  EXPECT_TRUE(tpm_status_->GetTpmOwned(&status));
  EXPECT_EQ(TpmStatus::kTpmOwned, status);
}

TEST_F(Tpm2StatusTest, IsOwnedNoRepeatedInitializationOnTrue) {
  EXPECT_CALL(mock_tpm_state_, Initialize()).WillOnce(Return(TPM_RC_SUCCESS));
  EXPECT_CALL(mock_tpm_state_, IsOwned()).WillRepeatedly(Return(true));
  EXPECT_CALL(mock_tpm_state_, IsOwnerPasswordSet())
      .WillRepeatedly(Return(true));
  EXPECT_CALL(mock_tpm_utility_, GetKeyPublicArea(trunks::kStorageRootKey, _))
      .WillRepeatedly(
          Invoke([](trunks::TPM_HANDLE, trunks::TPMT_PUBLIC* public_area) {
            memset(public_area, 0, sizeof(trunks::TPMT_PUBLIC));
            public_area->object_attributes =
                trunks::kSensitiveDataOrigin | trunks::kUserWithAuth |
                trunks::kNoDA | trunks::kRestricted | trunks::kDecrypt;
            return TPM_RC_SUCCESS;
          }));

  TpmStatus::TpmOwnershipStatus status;
  EXPECT_TRUE(tpm_status_->GetTpmOwned(&status));
  EXPECT_EQ(TpmStatus::kTpmOwned, status);
  EXPECT_TRUE(tpm_status_->GetTpmOwned(&status));
  EXPECT_EQ(TpmStatus::kTpmOwned, status);
}

TEST_F(Tpm2StatusTest, IsOwnedInitializeFailure) {
  EXPECT_CALL(mock_tpm_state_, Initialize())
      .WillRepeatedly(Return(TPM_RC_FAILURE));
  EXPECT_CALL(mock_tpm_state_, IsOwned()).Times(0);
  EXPECT_CALL(mock_tpm_state_, IsOwnerPasswordSet()).Times(0);

  TpmStatus::TpmOwnershipStatus status;
  EXPECT_FALSE(tpm_status_->GetTpmOwned(&status));
}

TEST_F(Tpm2StatusTest, IsPreOwned) {
  EXPECT_CALL(mock_tpm_state_, Initialize())
      .WillRepeatedly(Return(TPM_RC_SUCCESS));
  EXPECT_CALL(mock_tpm_state_, IsOwned()).WillRepeatedly(Return(false));
  EXPECT_CALL(mock_tpm_state_, IsOwnerPasswordSet())
      .WillRepeatedly(Return(true));

  TpmStatus::TpmOwnershipStatus status;
  EXPECT_TRUE(tpm_status_->GetTpmOwned(&status));
  EXPECT_EQ(TpmStatus::kTpmPreOwned, status);
}

TEST_F(Tpm2StatusTest, GetDictionaryAttackInfoInitializeFailure) {
  EXPECT_CALL(mock_tpm_state_, Initialize())
      .WillRepeatedly(Return(TPM_RC_FAILURE));
  uint32_t count;
  uint32_t threshold;
  bool lockout;
  uint32_t seconds_remaining;
  EXPECT_FALSE(tpm_status_->GetDictionaryAttackInfo(
      &count, &threshold, &lockout, &seconds_remaining));
}

TEST_F(Tpm2StatusTest, GetDictionaryAttackInfoForwarding) {
  uint32_t lockout_count = 3;
  uint32_t lockout_threshold = 16;
  bool is_locked = true;
  uint32_t lockout_interval = 3600;
  EXPECT_CALL(mock_tpm_state_, GetLockoutCounter())
      .WillRepeatedly(Return(lockout_count));
  EXPECT_CALL(mock_tpm_state_, GetLockoutThreshold())
      .WillRepeatedly(Return(lockout_threshold));
  EXPECT_CALL(mock_tpm_state_, IsInLockout()).WillRepeatedly(Return(is_locked));
  EXPECT_CALL(mock_tpm_state_, GetLockoutInterval())
      .WillRepeatedly(Return(lockout_interval));
  uint32_t count;
  uint32_t threshold;
  bool lockout;
  uint32_t seconds_remaining;
  EXPECT_TRUE(tpm_status_->GetDictionaryAttackInfo(&count, &threshold, &lockout,
                                                   &seconds_remaining));
  EXPECT_EQ(count, lockout_count);
  EXPECT_EQ(threshold, lockout_threshold);
  EXPECT_EQ(lockout, is_locked);
  EXPECT_EQ(seconds_remaining, lockout_count * lockout_interval);
}

TEST_F(Tpm2StatusTest, GetDictionaryAttackInfoAlwaysRefresh) {
  EXPECT_CALL(mock_tpm_state_, Initialize())
      .WillRepeatedly(Return(TPM_RC_SUCCESS));
  uint32_t count;
  uint32_t threshold;
  bool lockout;
  uint32_t seconds_remaining;
  EXPECT_TRUE(tpm_status_->GetDictionaryAttackInfo(&count, &threshold, &lockout,
                                                   &seconds_remaining));
}

TEST_F(Tpm2StatusTest, IsDictionaryAttackMitigationEnabledInitializeFailure) {
  EXPECT_CALL(mock_tpm_state_, Initialize())
      .WillRepeatedly(Return(TPM_RC_FAILURE));
  bool is_enabled;
  EXPECT_FALSE(tpm_status_->IsDictionaryAttackMitigationEnabled(&is_enabled));
}

TEST_F(Tpm2StatusTest, IsDictionaryAttackMitigationEnabledSuccess) {
  EXPECT_CALL(mock_tpm_state_, Initialize())
      .WillRepeatedly(Return(TPM_RC_SUCCESS));

  // Either lockout interval or lockout recovery indicates a positive test.
  EXPECT_CALL(mock_tpm_state_, GetLockoutInterval())
      .WillRepeatedly(Return(2000));
  EXPECT_CALL(mock_tpm_state_, GetLockoutRecovery()).WillRepeatedly(Return(0));
  bool is_enabled = false;
  EXPECT_TRUE(tpm_status_->IsDictionaryAttackMitigationEnabled(&is_enabled));
  EXPECT_TRUE(is_enabled);

  EXPECT_CALL(mock_tpm_state_, GetLockoutInterval()).WillRepeatedly(Return(0));
  EXPECT_CALL(mock_tpm_state_, GetLockoutRecovery())
      .WillRepeatedly(Return(2000));
  is_enabled = false;
  EXPECT_TRUE(tpm_status_->IsDictionaryAttackMitigationEnabled(&is_enabled));
  EXPECT_TRUE(is_enabled);

  // Otherwise both values being 0 indicates a negative test.
  EXPECT_CALL(mock_tpm_state_, GetLockoutInterval()).WillRepeatedly(Return(0));
  EXPECT_CALL(mock_tpm_state_, GetLockoutRecovery()).WillRepeatedly(Return(0));
  is_enabled = true;
  EXPECT_TRUE(tpm_status_->IsDictionaryAttackMitigationEnabled(&is_enabled));
  EXPECT_FALSE(is_enabled);
}

TEST_F(Tpm2StatusTest, Cr50SupportsU2f) {
  EXPECT_CALL(mock_tpm_utility_, IsGsc).WillRepeatedly(Return(true));

  EXPECT_TRUE(tpm_status_->SupportU2f());
}

TEST_F(Tpm2StatusTest, NonCr50SupportsU2f) {
  EXPECT_CALL(mock_tpm_utility_, IsGsc).WillRepeatedly(Return(false));

  EXPECT_TRUE(tpm_status_->SupportU2f());
}

TEST_F(Tpm2StatusTest, SupportPinweaver) {
  EXPECT_CALL(mock_tpm_utility_, PinWeaverIsSupported(0, _))
      .WillRepeatedly(Return(TPM_RC_SUCCESS));

  EXPECT_TRUE(tpm_status_->SupportPinweaver());
}

TEST_F(Tpm2StatusTest, NotSupportPinweaver) {
  EXPECT_CALL(mock_tpm_utility_, PinWeaverIsSupported(0, _))
      .WillRepeatedly(Return(TPM_RC_FAILURE));

  EXPECT_FALSE(tpm_status_->SupportPinweaver());
}

TEST_F(Tpm2StatusTest, GetGscVersion) {
  // Running this command should not crash.
  tpm_status_->GetGscVersion();
}

TEST_F(Tpm2StatusTest, GetRoVerificationStatusSuccess) {
  EXPECT_CALL(mock_tpm_utility_, GetRoVerificationStatus(_))
      .WillRepeatedly(Invoke([](ap_ro_status* status) {
        *status = AP_RO_PASS;
        return TPM_RC_SUCCESS;
      }));
  tpm_manager::RoVerificationStatus status;
  EXPECT_TRUE(tpm_status_->GetRoVerificationStatus(&status));
  EXPECT_EQ(status, RO_STATUS_PASS);
}

TEST_F(Tpm2StatusTest, GetRoVerificationStatusFailure) {
  EXPECT_CALL(mock_tpm_utility_, GetRoVerificationStatus(_))
      .WillRepeatedly(Return(TPM_RC_FAILURE));
  tpm_manager::RoVerificationStatus status;
  EXPECT_FALSE(tpm_status_->GetRoVerificationStatus(&status));
}

TEST_F(Tpm2StatusTest, GetAlertsDataSuccess) {
  EXPECT_CALL(mock_tpm_utility_, GetAlertsData(_))
      .WillOnce([](trunks::TpmAlertsData* alerts) {
        *alerts = trunks::TpmAlertsData{
            .chip_family = trunks::kFamilyH1,
            .alerts_num = 2,
            .counters = {5, 9},
        };
        return TPM_RC_SUCCESS;
      });
  TpmStatus::AlertsData alerts;
  EXPECT_TRUE(tpm_status_->GetAlertsData(&alerts));
  EXPECT_EQ(alerts.counters[1], 5);
  EXPECT_EQ(alerts.counters[2], 9);
}

TEST_F(Tpm2StatusTest, GetAlertsDataWrongFamily) {
  EXPECT_CALL(mock_tpm_utility_, GetAlertsData(_))
      .WillOnce([](trunks::TpmAlertsData* alerts) {
        *alerts = trunks::TpmAlertsData{
            .chip_family = 0x42,
            .alerts_num = 2,
            .counters = {5, 9},
        };
        return TPM_RC_SUCCESS;
      });
  TpmStatus::AlertsData alerts;
  EXPECT_FALSE(tpm_status_->GetAlertsData(&alerts));
}

TEST_F(Tpm2StatusTest, GetAlertsDataNoSuchCommand) {
  EXPECT_CALL(mock_tpm_utility_, GetAlertsData(_))
      .WillRepeatedly(Return(trunks::TPM_RC_NO_SUCH_COMMAND));
  TpmStatus::AlertsData alerts;
  EXPECT_FALSE(tpm_status_->GetAlertsData(&alerts));
}

TEST_F(Tpm2StatusTest, GetAlertsDataFailure) {
  EXPECT_CALL(mock_tpm_utility_, GetAlertsData(_))
      .WillRepeatedly(Return(trunks::TPM_RC_FAILURE));
  TpmStatus::AlertsData alerts;
  EXPECT_TRUE(tpm_status_->GetAlertsData(&alerts));
  EXPECT_EQ(alerts.counters[1], 0);
}

TEST_F(Tpm2StatusTest, GetTi50StatsSuccess) {
  EXPECT_CALL(mock_tpm_utility_, GetTi50Stats(_, _, _, _))
      .WillOnce([](uint32_t* fs_time, uint32_t* fs_size, uint32_t* aprov_time,
                   uint32_t* aprov_status) {
        *fs_time = 1234;
        *fs_size = 5678;
        *aprov_time = 9012;
        *aprov_status = 3456;
        return TPM_RC_SUCCESS;
      });
  uint32_t fs_time = 0;
  uint32_t fs_size = 0;
  uint32_t aprov_time = 0;
  uint32_t aprov_status = 0;
  EXPECT_TRUE(tpm_status_->GetTi50Stats(&fs_time, &fs_size, &aprov_time,
                                        &aprov_status));
  EXPECT_EQ(fs_time, 1234);
  EXPECT_EQ(fs_size, 5678);
  EXPECT_EQ(aprov_time, 9012);
  EXPECT_EQ(aprov_status, 3456);
}

TEST_F(Tpm2StatusTest, GetTi50StatsFailure) {
  EXPECT_CALL(mock_tpm_utility_, GetTi50Stats(_, _, _, _))
      .WillRepeatedly(Return(trunks::TPM_RC_FAILURE));
  uint32_t fs_time = 0;
  uint32_t fs_size = 0;
  uint32_t aprov_time = 0;
  uint32_t aprov_status = 0;
  EXPECT_FALSE(tpm_status_->GetTi50Stats(&fs_time, &fs_size, &aprov_time,
                                         &aprov_status));
  EXPECT_EQ(fs_time, 0);
  EXPECT_EQ(fs_size, 0);
  EXPECT_EQ(aprov_time, 0);
  EXPECT_EQ(aprov_status, 0);
}

TEST_F(Tpm2StatusTest, GetTi50StatsNoSuchCommand) {
  EXPECT_CALL(mock_tpm_utility_, GetTi50Stats(_, _, _, _))
      .WillRepeatedly(Return(trunks::TPM_RC_NO_SUCH_COMMAND));
  uint32_t fs_time = 0;
  uint32_t fs_size = 0;
  uint32_t aprov_time = 0;
  uint32_t aprov_status = 0;
  EXPECT_FALSE(tpm_status_->GetTi50Stats(&fs_time, &fs_size, &aprov_time,
                                         &aprov_status));
  EXPECT_EQ(fs_time, 0);
  EXPECT_EQ(fs_size, 0);
  EXPECT_EQ(aprov_time, 0);
  EXPECT_EQ(aprov_status, 0);
}
}  // namespace tpm_manager
