// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "tpm_manager/server/tpm_initializer_impl.h"

#include <libhwsec/test_utils/tpm1/test_fixture.h>

#include "tpm_manager/common/typedefs.h"
#include "tpm_manager/server/mock_local_data_store.h"
#include "tpm_manager/server/mock_openssl_crypto_util.h"
#include "tpm_manager/server/mock_tpm_status.h"

namespace tpm_manager {

namespace {

using testing::_;
using testing::DoAll;
using testing::NiceMock;
using testing::Return;
using testing::SetArgPointee;

constexpr TSS_HCONTEXT kFakeContext = 99999;
constexpr TSS_HTPM kFakeTpm = 66666;

}  // namespace

class TpmInitializerTest : public ::hwsec::Tpm1HwsecTest {
 public:
  TpmInitializerTest()
      : tpm_initializer_(&mock_data_store_, &mock_tpm_status_),
        fake_local_data_(mock_data_store_.GetMutableFakeData()) {
    ON_CALL_OVERALLS(Ospi_Context_Create(_))
        .WillByDefault(
            DoAll(SetArgPointee<0>(kFakeContext), Return(TSS_SUCCESS)));
    ON_CALL_OVERALLS(Ospi_Context_GetTpmObject(_, _))
        .WillByDefault(DoAll(SetArgPointee<1>(kFakeTpm), Return(TSS_SUCCESS)));
  }
  ~TpmInitializerTest() override = default;

 protected:
  NiceMock<MockLocalDataStore> mock_data_store_;
  NiceMock<MockTpmStatus> mock_tpm_status_;
  TpmInitializerImpl tpm_initializer_;
  // Holds a reference of the internal |LocalData| of |mock_data_store_|.
  LocalData& fake_local_data_;
};

TEST_F(TpmInitializerTest, DAResetSuccess) {
  EXPECT_CALL(mock_tpm_status_, GetTpmOwned(_))
      .WillOnce(DoAll(SetArgPointee<0>(TpmStatus::kTpmOwned), Return(true)));
  fake_local_data_.mutable_owner_delegate()->set_blob("blob");
  fake_local_data_.mutable_owner_delegate()->set_secret("secret");
  fake_local_data_.mutable_owner_delegate()->set_has_reset_lock_permissions(
      true);
  EXPECT_CALL_OVERALLS(Ospi_TPM_SetStatus(_, TSS_TPMSTATUS_RESETLOCK, _))
      .WillOnce(Return(TSS_SUCCESS));
  EXPECT_EQ(tpm_initializer_.ResetDictionaryAttackLock(),
            DictionaryAttackResetStatus::kResetAttemptSucceeded);
}

TEST_F(TpmInitializerTest, DAResetSuccessWithOwnerPassword) {
  EXPECT_CALL(mock_tpm_status_, GetTpmOwned(_))
      .WillOnce(DoAll(SetArgPointee<0>(TpmStatus::kTpmOwned), Return(true)));
  fake_local_data_.set_owner_password("owner password");
  EXPECT_CALL_OVERALLS(Ospi_TPM_SetStatus(_, TSS_TPMSTATUS_RESETLOCK, _))
      .WillOnce(Return(TSS_SUCCESS));
  EXPECT_EQ(tpm_initializer_.ResetDictionaryAttackLock(),
            DictionaryAttackResetStatus::kResetAttemptSucceeded);
}

TEST_F(TpmInitializerTest, DAResetNoAuth) {
  EXPECT_CALL(mock_tpm_status_, GetTpmOwned(_))
      .WillOnce(DoAll(SetArgPointee<0>(TpmStatus::kTpmOwned), Return(true)));
  EXPECT_EQ(tpm_initializer_.ResetDictionaryAttackLock(),
            DictionaryAttackResetStatus::kDelegateNotAvailable);
}

TEST_F(TpmInitializerTest, DAResetDelegateNoPermission) {
  EXPECT_CALL(mock_tpm_status_, GetTpmOwned(_))
      .WillOnce(DoAll(SetArgPointee<0>(TpmStatus::kTpmOwned), Return(true)));
  fake_local_data_.mutable_owner_delegate()->set_blob("blob");
  fake_local_data_.mutable_owner_delegate()->set_secret("secret");
  fake_local_data_.mutable_owner_delegate()->set_has_reset_lock_permissions(
      false);
  EXPECT_EQ(tpm_initializer_.ResetDictionaryAttackLock(),
            DictionaryAttackResetStatus::kDelegateNotAllowed);
}

TEST_F(TpmInitializerTest, DAResetFailed) {
  EXPECT_CALL(mock_tpm_status_, GetTpmOwned(_))
      .WillOnce(DoAll(SetArgPointee<0>(TpmStatus::kTpmOwned), Return(true)));
  fake_local_data_.mutable_owner_delegate()->set_blob("blob");
  fake_local_data_.mutable_owner_delegate()->set_secret("secret");
  fake_local_data_.mutable_owner_delegate()->set_has_reset_lock_permissions(
      true);
  EXPECT_CALL_OVERALLS(Ospi_TPM_SetStatus(_, TSS_TPMSTATUS_RESETLOCK, _))
      .WillOnce(Return(TPM_ERROR(TPM_E_BAD_PARAMETER)));
  EXPECT_EQ(tpm_initializer_.ResetDictionaryAttackLock(),
            DictionaryAttackResetStatus::kResetAttemptFailed);
}

TEST_F(TpmInitializerTest, DAResetFailedFailedAuthNoRepeat) {
  EXPECT_CALL(mock_tpm_status_, GetTpmOwned(_))
      .WillOnce(DoAll(SetArgPointee<0>(TpmStatus::kTpmOwned), Return(true)));
  fake_local_data_.mutable_owner_delegate()->set_blob("blob");
  fake_local_data_.mutable_owner_delegate()->set_secret("secret");
  fake_local_data_.mutable_owner_delegate()->set_has_reset_lock_permissions(
      true);
  EXPECT_CALL_OVERALLS(Ospi_TPM_SetStatus(_, TSS_TPMSTATUS_RESETLOCK, _))
      .WillOnce(Return(TPM_ERROR(TPM_E_AUTHFAIL)));
  EXPECT_EQ(tpm_initializer_.ResetDictionaryAttackLock(),
            DictionaryAttackResetStatus::kResetAttemptFailed);
  // Makes sure the bad auth is flagged.
  EXPECT_CALL(mock_tpm_status_, GetTpmOwned(_)).Times(0);
  EXPECT_EQ(tpm_initializer_.ResetDictionaryAttackLock(),
            DictionaryAttackResetStatus::kResetAttemptFailed);
}

TEST_F(TpmInitializerTest, DAResetFailedWrongPcr0) {
  EXPECT_CALL(mock_tpm_status_, GetTpmOwned(_))
      .WillOnce(DoAll(SetArgPointee<0>(TpmStatus::kTpmOwned), Return(true)));
  fake_local_data_.mutable_owner_delegate()->set_blob("blob");
  fake_local_data_.mutable_owner_delegate()->set_secret("secret");
  fake_local_data_.mutable_owner_delegate()->set_has_reset_lock_permissions(
      true);
  EXPECT_CALL_OVERALLS(Ospi_TPM_SetStatus(_, TSS_TPMSTATUS_RESETLOCK, _))
      .WillOnce(Return(TPM_ERROR(TPM_E_WRONGPCRVAL)));
  EXPECT_EQ(tpm_initializer_.ResetDictionaryAttackLock(),
            DictionaryAttackResetStatus::kInvalidPcr0State);
}

TEST_F(TpmInitializerTest, DisableDictionaryAttackMitigationNotSupported) {
  EXPECT_EQ(tpm_initializer_.DisableDictionaryAttackMitigation(),
            TpmInitializerStatus::kNotSupport);
}

}  // namespace tpm_manager
