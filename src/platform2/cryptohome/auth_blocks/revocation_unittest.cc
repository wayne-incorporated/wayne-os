// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/auth_blocks/revocation.h"

#include <string>

#include <brillo/secure_blob.h>
#include <gtest/gtest.h>
#include <libhwsec-foundation/error/testing_helper.h>

#include "cryptohome/mock_le_credential_manager.h"

using cryptohome::error::CryptohomeError;
using cryptohome::error::CryptohomeLECredError;
using cryptohome::error::ErrorActionSet;
using cryptohome::error::PossibleAction;
using cryptohome::error::PrimaryAction;
using hwsec_foundation::error::testing::IsOk;
using hwsec_foundation::error::testing::NotOk;
using hwsec_foundation::error::testing::ReturnError;
using testing::_;
using testing::DoAll;
using testing::NiceMock;
using testing::Return;
using testing::SaveArg;
using testing::SetArgPointee;

namespace cryptohome {
namespace revocation {

namespace {
const char kFakePerCredentialSecret[] = "fake per-credential secret";
const char kFakeHESecret[] = "fake high entropy secret";
}  // namespace

TEST(RevocationTest, Create) {
  brillo::SecureBlob per_credential_secret(kFakePerCredentialSecret);
  NiceMock<MockLECredentialManager> le_cred_manager;
  RevocationState state;
  KeyBlobs key_blobs = {.vkk_key = per_credential_secret};
  EXPECT_CALL(le_cred_manager, InsertCredential(_, _, _, _, _, _, _))
      .WillOnce(ReturnError<CryptohomeLECredError>());
  ASSERT_THAT(Create(&le_cred_manager, &state, &key_blobs), IsOk());
}

TEST(RevocationTest, Derive) {
  brillo::SecureBlob he_secret(kFakeHESecret);
  brillo::SecureBlob per_credential_secret(kFakePerCredentialSecret);
  NiceMock<MockLECredentialManager> le_cred_manager;
  RevocationState state = {.le_label = 0};
  KeyBlobs key_blobs = {.vkk_key = per_credential_secret};
  EXPECT_CALL(le_cred_manager, CheckCredential(_, _, _, _))
      .WillOnce(DoAll(SetArgPointee<2>(he_secret),
                      ReturnError<CryptohomeLECredError>()));
  ASSERT_THAT(Derive(&le_cred_manager, state, &key_blobs), IsOk());
}

TEST(RevocationTest, DeriveFailsWithoutLabel) {
  brillo::SecureBlob per_credential_secret(kFakePerCredentialSecret);
  NiceMock<MockLECredentialManager> le_cred_manager;
  KeyBlobs key_blobs = {.vkk_key = per_credential_secret};
  RevocationState state;
  auto status = Derive(&le_cred_manager, state, &key_blobs);
  ASSERT_THAT(status, NotOk());
  EXPECT_EQ(status->local_crypto_error(), CryptoError::CE_OTHER_CRYPTO);
}

TEST(RevocationTest, Revoke) {
  NiceMock<MockLECredentialManager> le_cred_manager;
  RevocationState state = {.le_label = 0};
  uint64_t label;
  EXPECT_CALL(le_cred_manager, RemoveCredential(_))
      .WillOnce(
          DoAll(SaveArg<0>(&label), ReturnError<CryptohomeLECredError>()));
  ASSERT_THAT(
      Revoke(AuthBlockType::kCryptohomeRecovery, &le_cred_manager, state),
      IsOk());
  EXPECT_EQ(label, state.le_label.value());
}

TEST(RevocationTest, RevokeFailsWithoutLabel) {
  NiceMock<MockLECredentialManager> le_cred_manager;
  RevocationState state;
  auto status =
      Revoke(AuthBlockType::kCryptohomeRecovery, &le_cred_manager, state);
  ASSERT_THAT(status, NotOk());
  EXPECT_EQ(status->local_crypto_error(), CryptoError::CE_OTHER_CRYPTO);
}

TEST(RevocationTest, RevokeSucceedsWithLeCredErrorInvalidLabel) {
  const CryptohomeError::ErrorLocationPair kErrorLocationForTesting1 =
      CryptohomeError::ErrorLocationPair(
          static_cast<::cryptohome::error::CryptohomeError::ErrorLocation>(1),
          std::string("Testing1"));
  NiceMock<MockLECredentialManager> le_cred_manager;
  RevocationState state = {.le_label = 0};
  uint64_t label;
  EXPECT_CALL(le_cred_manager, RemoveCredential(_))
      .WillOnce(DoAll(SaveArg<0>(&label),
                      ReturnError<CryptohomeLECredError>(
                          kErrorLocationForTesting1,
                          ErrorActionSet({PossibleAction::kFatal}),
                          LE_CRED_ERROR_INVALID_LABEL)));
  // Revoke succeeds after LE_CRED_ERROR_INVALID_LABEL.
  ASSERT_THAT(
      Revoke(AuthBlockType::kCryptohomeRecovery, &le_cred_manager, state),
      IsOk());
  EXPECT_EQ(label, state.le_label.value());
}

TEST(RevocationTest, RevokeSucceedsWithLeCredErrorHashTree) {
  const CryptohomeError::ErrorLocationPair kErrorLocationForTesting1 =
      CryptohomeError::ErrorLocationPair(
          static_cast<::cryptohome::error::CryptohomeError::ErrorLocation>(1),
          std::string("Testing1"));
  NiceMock<MockLECredentialManager> le_cred_manager;
  RevocationState state = {.le_label = 0};
  uint64_t label;
  EXPECT_CALL(le_cred_manager, RemoveCredential(_))
      .WillOnce(DoAll(SaveArg<0>(&label),
                      ReturnError<CryptohomeLECredError>(
                          kErrorLocationForTesting1,
                          ErrorActionSet({PossibleAction::kFatal}),
                          LE_CRED_ERROR_HASH_TREE)));
  // Revoke succeeds after LE_CRED_ERROR_HASH_TREE.
  ASSERT_THAT(
      Revoke(AuthBlockType::kCryptohomeRecovery, &le_cred_manager, state),
      IsOk());
  EXPECT_EQ(label, state.le_label.value());
}

TEST(RevocationTest, RevokeFailsWithLeCredErrorUnclassified) {
  const CryptohomeError::ErrorLocationPair kErrorLocationForTesting1 =
      CryptohomeError::ErrorLocationPair(
          static_cast<::cryptohome::error::CryptohomeError::ErrorLocation>(1),
          std::string("Testing1"));
  NiceMock<MockLECredentialManager> le_cred_manager;
  RevocationState state = {.le_label = 0};
  uint64_t label;
  EXPECT_CALL(le_cred_manager, RemoveCredential(_))
      .WillOnce(DoAll(SaveArg<0>(&label),
                      ReturnError<CryptohomeLECredError>(
                          kErrorLocationForTesting1,
                          ErrorActionSet({PossibleAction::kFatal}),
                          LE_CRED_ERROR_UNCLASSIFIED)));
  // Revoke fails after LE_CRED_ERROR_UNCLASSIFIED.
  auto status =
      Revoke(AuthBlockType::kCryptohomeRecovery, &le_cred_manager, state);
  ASSERT_THAT(status, NotOk());
  EXPECT_EQ(status->local_crypto_error(), CryptoError::CE_OTHER_CRYPTO);
}

TEST(RevocationTest, RevokeFailsWithLeCredErrorInvalidLeSecret) {
  const CryptohomeError::ErrorLocationPair kErrorLocationForTesting1 =
      CryptohomeError::ErrorLocationPair(
          static_cast<::cryptohome::error::CryptohomeError::ErrorLocation>(1),
          std::string("Testing1"));
  NiceMock<MockLECredentialManager> le_cred_manager;
  RevocationState state = {.le_label = 0};
  uint64_t label;
  EXPECT_CALL(le_cred_manager, RemoveCredential(_))
      .WillOnce(DoAll(SaveArg<0>(&label),
                      ReturnError<CryptohomeLECredError>(
                          kErrorLocationForTesting1,
                          ErrorActionSet({PossibleAction::kFatal}),
                          LE_CRED_ERROR_INVALID_LE_SECRET)));
  // Revoke fails after LE_CRED_ERROR_INVALID_LE_SECRET.
  auto status =
      Revoke(AuthBlockType::kCryptohomeRecovery, &le_cred_manager, state);
  ASSERT_THAT(status, NotOk());
  EXPECT_EQ(status->local_crypto_error(), CryptoError::CE_OTHER_CRYPTO);
}

}  // namespace revocation
}  // namespace cryptohome
