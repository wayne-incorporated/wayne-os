// Copyright 2015 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "tpm_manager/server/tpm2_initializer_impl.h"

#include <memory>

#include <base/functional/bind.h>
#include <base/strings/string_number_conversions.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <tpm_manager-client/tpm_manager/dbus-constants.h>
#include <trunks/mock_tpm_state.h>
#include <trunks/mock_tpm_utility.h>
#include <trunks/trunks_factory_for_test.h>

#include "tpm_manager/common/typedefs.h"
#include "tpm_manager/server/mock_local_data_store.h"
#include "tpm_manager/server/mock_openssl_crypto_util.h"
#include "tpm_manager/server/mock_tpm_status.h"
#include "tpm_manager/server/tpm_status.h"

using testing::_;
using testing::AtLeast;
using testing::DoAll;
using testing::Invoke;
using testing::NiceMock;
using testing::Return;
using testing::SaveArg;
using testing::SetArgPointee;

namespace tpm_manager {

class Tpm2InitializerTest : public testing::Test {
 public:
  Tpm2InitializerTest() = default;
  ~Tpm2InitializerTest() override = default;

  void SetUp() override {
    EXPECT_CALL(mock_data_store_, Read(_))
        .WillRepeatedly(Invoke([this](LocalData* arg) {
          *arg = fake_local_data_;
          return true;
        }));
    EXPECT_CALL(mock_data_store_, Write(_))
        .WillRepeatedly(Invoke([this](const LocalData& arg) {
          fake_local_data_ = arg;
          return true;
        }));
    factory_.set_tpm_state(&mock_trunks_tpm_state_);
    factory_.set_tpm_utility(&mock_tpm_utility_);

    tpm_initializer_.reset(new Tpm2InitializerImpl(
        factory_, &mock_openssl_util_, &mock_data_store_, &mock_tpm_status_));
  }

 protected:
  LocalData fake_local_data_;
  NiceMock<MockOpensslCryptoUtil> mock_openssl_util_;
  NiceMock<MockLocalDataStore> mock_data_store_;
  NiceMock<MockTpmStatus> mock_tpm_status_;
  NiceMock<trunks::MockTpmState> mock_trunks_tpm_state_;
  NiceMock<trunks::MockTpmUtility> mock_tpm_utility_;
  trunks::TrunksFactoryForTest factory_;
  std::unique_ptr<TpmInitializer> tpm_initializer_;
};

TEST_F(Tpm2InitializerTest, InitializeTpmNoSeedTpm) {
  EXPECT_CALL(mock_tpm_utility_, StirRandom(_, _))
      .WillRepeatedly(Return(trunks::TPM_RC_FAILURE));
  bool already_owned;
  EXPECT_FALSE(tpm_initializer_->InitializeTpm(&already_owned));
}

TEST_F(Tpm2InitializerTest, InitializeTpmAlreadyOwned) {
  EXPECT_CALL(mock_tpm_utility_, TakeOwnership(_, _, _)).Times(0);
  bool already_owned = false;
  EXPECT_TRUE(tpm_initializer_->InitializeTpm(&already_owned));
  EXPECT_TRUE(already_owned);
}

TEST_F(Tpm2InitializerTest, InitializeTpmOwnershipStatusError) {
  EXPECT_CALL(mock_tpm_status_, GetTpmOwned(_)).WillOnce(Return(false));
  EXPECT_CALL(mock_data_store_, Read(_)).Times(0);
  EXPECT_CALL(mock_tpm_utility_, TakeOwnership(_, _, _)).Times(0);
  bool already_owned;
  EXPECT_FALSE(tpm_initializer_->InitializeTpm(&already_owned));
}

TEST_F(Tpm2InitializerTest, InitializeTpmLocalDataReadError) {
  EXPECT_CALL(mock_tpm_status_, GetTpmOwned(_))
      .WillRepeatedly(
          DoAll(SetArgPointee<0>(TpmStatus::kTpmUnowned), Return(true)));
  EXPECT_CALL(mock_data_store_, Read(_)).WillRepeatedly(Return(false));
  EXPECT_CALL(mock_tpm_utility_, TakeOwnership(_, _, _)).Times(0);
  bool already_owned;
  EXPECT_FALSE(tpm_initializer_->InitializeTpm(&already_owned));
}

TEST_F(Tpm2InitializerTest, InitializeTpmLocalDataWriteError) {
  EXPECT_CALL(mock_tpm_status_, GetTpmOwned(_))
      .WillRepeatedly(
          DoAll(SetArgPointee<0>(TpmStatus::kTpmUnowned), Return(true)));
  EXPECT_CALL(mock_data_store_, Write(_)).WillRepeatedly(Return(false));
  EXPECT_CALL(mock_tpm_utility_, TakeOwnership(_, _, _)).Times(0);
  bool already_owned;
  EXPECT_FALSE(tpm_initializer_->InitializeTpm(&already_owned));
}

TEST_F(Tpm2InitializerTest, InitializeTpmOwnershipError) {
  EXPECT_CALL(mock_tpm_status_, GetTpmOwned(_))
      .WillRepeatedly(
          DoAll(SetArgPointee<0>(TpmStatus::kTpmUnowned), Return(true)));
  EXPECT_CALL(mock_tpm_utility_, TakeOwnership(_, _, _))
      .WillRepeatedly(Return(trunks::TPM_RC_FAILURE));
  bool already_owned;
  EXPECT_FALSE(tpm_initializer_->InitializeTpm(&already_owned));
}

TEST_F(Tpm2InitializerTest, InitializeTpmSuccess) {
  EXPECT_CALL(mock_tpm_status_, GetTpmOwned(_))
      .WillOnce(DoAll(SetArgPointee<0>(TpmStatus::kTpmUnowned), Return(true)));
  std::string owner_random_bytes("\xFF\xF7\x00\x01\xD2\xA3", 6);
  std::string owner_password =
      base::HexEncode(owner_random_bytes.data(), owner_random_bytes.size());
  EXPECT_EQ(owner_random_bytes.size() * 2, owner_password.size());
  std::string endorsement_password = "hunter2";
  std::string lockout_password = "sesame";
  EXPECT_CALL(mock_tpm_utility_, GenerateRandom(_, _, _))
      .Times(3)  // Once for owner, endorsement and lockout passwords
      .WillOnce(DoAll(SetArgPointee<2>(owner_random_bytes),
                      Return(trunks::TPM_RC_SUCCESS)))
      .WillOnce(DoAll(SetArgPointee<2>(endorsement_password),
                      Return(trunks::TPM_RC_SUCCESS)))
      .WillOnce(DoAll(SetArgPointee<2>(lockout_password),
                      Return(trunks::TPM_RC_SUCCESS)));
  EXPECT_CALL(mock_tpm_utility_, TakeOwnership(_, _, _))
      .WillOnce(Return(trunks::TPM_RC_SUCCESS));
  bool already_owned = true;
  EXPECT_TRUE(tpm_initializer_->InitializeTpm(&already_owned));
  EXPECT_LT(0, fake_local_data_.owner_dependency_size());
  EXPECT_EQ(owner_password, fake_local_data_.owner_password());
  EXPECT_EQ(endorsement_password, fake_local_data_.endorsement_password());
  EXPECT_EQ(lockout_password, fake_local_data_.lockout_password());
  EXPECT_FALSE(already_owned);
}

TEST_F(Tpm2InitializerTest, InitializeTpmSuccessAfterError) {
  EXPECT_CALL(mock_tpm_status_, GetTpmOwned(_))
      .WillOnce(DoAll(SetArgPointee<0>(TpmStatus::kTpmUnowned), Return(true)));
  std::string owner_password("owner");
  std::string endorsement_password("endorsement");
  std::string lockout_password("lockout");
  fake_local_data_.add_owner_dependency("test");
  fake_local_data_.set_owner_password(owner_password);
  fake_local_data_.set_endorsement_password(endorsement_password);
  fake_local_data_.set_lockout_password(lockout_password);
  EXPECT_CALL(
      mock_tpm_utility_,
      TakeOwnership(owner_password, endorsement_password, lockout_password))
      .WillOnce(Return(trunks::TPM_RC_SUCCESS));
  bool already_owned = true;
  EXPECT_TRUE(tpm_initializer_->InitializeTpm(&already_owned));
  EXPECT_LT(0, fake_local_data_.owner_dependency_size());
  EXPECT_EQ(owner_password, fake_local_data_.owner_password());
  EXPECT_EQ(endorsement_password, fake_local_data_.endorsement_password());
  EXPECT_EQ(lockout_password, fake_local_data_.lockout_password());
  EXPECT_FALSE(already_owned);
}

TEST_F(Tpm2InitializerTest, PruneStoredPasswordsSuccess) {
  EXPECT_CALL(mock_trunks_tpm_state_, Initialize())
      .WillOnce(Return(trunks::TPM_RC_SUCCESS));
  EXPECT_CALL(mock_trunks_tpm_state_, IsEndorsementPasswordSet())
      .WillOnce(Return(false));

  fake_local_data_.add_owner_dependency("test");
  fake_local_data_.set_owner_password("owner");
  fake_local_data_.set_endorsement_password("endorsement");
  fake_local_data_.set_lockout_password("lockout");

  NvramPolicyRecord record;
  record.set_index(1234);
  *fake_local_data_.add_nvram_policy() = record;

  tpm_initializer_->PruneStoredPasswords();

  // Passwords and owner dependencies are removed.
  LocalData expected_local_data;
  *expected_local_data.add_nvram_policy() = record;

  EXPECT_EQ(fake_local_data_.SerializeAsString(),
            expected_local_data.SerializeAsString());
}

TEST_F(Tpm2InitializerTest, PruneStoredPasswordsRefreshTpmStateError) {
  EXPECT_CALL(mock_trunks_tpm_state_, Initialize())
      .WillOnce(Return(trunks::TPM_RC_FAILURE));

  fake_local_data_.set_owner_password("owner");
  // Local data isn't touched.
  LocalData expected_local_data = fake_local_data_;

  tpm_initializer_->PruneStoredPasswords();

  EXPECT_EQ(fake_local_data_.SerializeAsString(),
            expected_local_data.SerializeAsString());
}

TEST_F(Tpm2InitializerTest, PruneStoredPasswordsDataInUse) {
  EXPECT_CALL(mock_trunks_tpm_state_, Initialize())
      .WillOnce(Return(trunks::TPM_RC_SUCCESS));
  EXPECT_CALL(mock_trunks_tpm_state_, IsEndorsementPasswordSet())
      .WillOnce(Return(true));

  fake_local_data_.set_owner_password("owner");
  // Local data isn't touched.
  LocalData expected_local_data = fake_local_data_;

  tpm_initializer_->PruneStoredPasswords();

  EXPECT_EQ(fake_local_data_.SerializeAsString(),
            expected_local_data.SerializeAsString());
}

TEST_F(Tpm2InitializerTest, PruneStoredPasswordsReadDataError) {
  EXPECT_CALL(mock_trunks_tpm_state_, Initialize())
      .WillOnce(Return(trunks::TPM_RC_SUCCESS));
  EXPECT_CALL(mock_trunks_tpm_state_, IsEndorsementPasswordSet())
      .WillOnce(Return(false));
  EXPECT_CALL(mock_data_store_, Read(_)).WillOnce(Return(false));

  fake_local_data_.set_owner_password("owner");
  // Local data isn't touched.
  LocalData expected_local_data = fake_local_data_;

  tpm_initializer_->PruneStoredPasswords();

  EXPECT_EQ(fake_local_data_.SerializeAsString(),
            expected_local_data.SerializeAsString());
}

TEST_F(Tpm2InitializerTest, PruneStoredPasswordsWriteDataError) {
  EXPECT_CALL(mock_trunks_tpm_state_, Initialize())
      .WillOnce(Return(trunks::TPM_RC_SUCCESS));
  EXPECT_CALL(mock_trunks_tpm_state_, IsEndorsementPasswordSet())
      .WillOnce(Return(false));
  EXPECT_CALL(mock_data_store_, Write(_)).WillOnce(Return(false));

  fake_local_data_.set_owner_password("owner");
  // Local data isn't touched.
  LocalData expected_local_data = fake_local_data_;

  tpm_initializer_->PruneStoredPasswords();

  EXPECT_EQ(fake_local_data_.SerializeAsString(),
            expected_local_data.SerializeAsString());
}

// TODO(http://crosbug.com/p/59837): restore when TPM_RC_PCR_CHANGED is
// properly handled. Until then, VerifiedBootHelper won't extend PCRs.
#if 0
TEST_F(Tpm2InitializerTest, PCRSpoofGuard) {
  // Setup empty PCRs that need to be extended.
  EXPECT_CALL(mock_tpm_utility_, ReadPCR(_, _))
      .WillRepeatedly(DoAll(SetArgPointee<1>(std::string(32, 0)),
                            Return(trunks::TPM_RC_SUCCESS)));
  // Expect at least four PCRs to be extended.
  EXPECT_CALL(mock_tpm_utility_, ExtendPCR(_, _, _))
      .Times(AtLeast(4))
      .WillRepeatedly(Return(trunks::TPM_RC_SUCCESS));
  tpm_initializer_->VerifiedBootHelper();
}

TEST_F(Tpm2InitializerTest, PCRSpoofGuardReadFailure) {
  EXPECT_CALL(mock_tpm_utility_, ReadPCR(_, _))
      .WillRepeatedly(Return(trunks::TPM_RC_FAILURE));
  tpm_initializer_->VerifiedBootHelper();
}

TEST_F(Tpm2InitializerTest, PCRSpoofGuardExtendFailure) {
  EXPECT_CALL(mock_tpm_utility_, ReadPCR(_, _))
      .WillRepeatedly(DoAll(SetArgPointee<1>(std::string(32, 0)),
                            Return(trunks::TPM_RC_SUCCESS)));
  EXPECT_CALL(mock_tpm_utility_, ExtendPCR(_, _, _))
      .WillRepeatedly(Return(trunks::TPM_RC_FAILURE));
  tpm_initializer_->VerifiedBootHelper();
}
#endif

TEST_F(Tpm2InitializerTest, DAResetSuccess) {
  fake_local_data_.set_lockout_password("lockout");
  EXPECT_CALL(mock_tpm_utility_, ResetDictionaryAttackLock(_))
      .WillRepeatedly(Return(trunks::TPM_RC_SUCCESS));
  EXPECT_EQ(tpm_initializer_->ResetDictionaryAttackLock(),
            DictionaryAttackResetStatus::kResetAttemptSucceeded);
}

TEST_F(Tpm2InitializerTest, DAResetNoLockoutPassword) {
  fake_local_data_.clear_lockout_password();
  EXPECT_NE(tpm_initializer_->ResetDictionaryAttackLock(),
            DictionaryAttackResetStatus::kResetAttemptSucceeded);
}

TEST_F(Tpm2InitializerTest, DAResetFailure) {
  fake_local_data_.set_lockout_password("lockout");
  EXPECT_CALL(mock_tpm_utility_, ResetDictionaryAttackLock(_))
      .Times(AtLeast(1))
      .WillRepeatedly(Return(trunks::TPM_RC_FAILURE));
  EXPECT_NE(tpm_initializer_->ResetDictionaryAttackLock(),
            DictionaryAttackResetStatus::kResetAttemptSucceeded);
}

TEST_F(Tpm2InitializerTest, DisableDASuccess) {
  fake_local_data_.set_lockout_password("lockout");
  EXPECT_CALL(mock_tpm_utility_, SetDictionaryAttackParameters(_, 0, 0, _))
      .WillOnce(Return(trunks::TPM_RC_SUCCESS));
  EXPECT_EQ(tpm_initializer_->DisableDictionaryAttackMitigation(),
            TpmInitializerStatus::kSuccess);
}

TEST_F(Tpm2InitializerTest, DisableDANoLockoutPassword) {
  fake_local_data_.clear_lockout_password();
  EXPECT_CALL(mock_tpm_utility_, SetDictionaryAttackParameters(_, _, _, _))
      .Times(0);
  EXPECT_EQ(tpm_initializer_->DisableDictionaryAttackMitigation(),
            TpmInitializerStatus::kFailure);
}

TEST_F(Tpm2InitializerTest, DisableDAFailure) {
  fake_local_data_.set_lockout_password("lockout");
  EXPECT_CALL(mock_tpm_utility_, SetDictionaryAttackParameters(_, 0, 0, _))
      .WillOnce(Return(trunks::TPM_RC_FAILURE));
  EXPECT_EQ(tpm_initializer_->DisableDictionaryAttackMitigation(),
            TpmInitializerStatus::kFailure);
}

}  // namespace tpm_manager
