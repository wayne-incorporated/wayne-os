// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <string>
#include <utility>

#include <absl/types/variant.h>
#include <base/functional/callback_forward.h>
#include <base/test/task_environment.h>
#include <base/test/test_future.h>
#include <brillo/secure_blob.h>
#include <gtest/gtest.h>
#include <libhwsec-foundation/error/testing_helper.h>

#include "cryptohome/auth_blocks/mock_auth_block_utility.h"
#include "cryptohome/auth_factor/auth_factor.h"
#include "cryptohome/auth_factor/auth_factor_manager.h"
#include "cryptohome/auth_factor/auth_factor_metadata.h"
#include "cryptohome/auth_factor/auth_factor_type.h"
#include "cryptohome/filesystem_layout.h"
#include "cryptohome/flatbuffer_schemas/auth_block_state.h"
#include "cryptohome/flatbuffer_schemas/auth_block_state_test_utils.h"
#include "cryptohome/mock_platform.h"

using base::test::TestFuture;
using brillo::SecureBlob;
using cryptohome::error::CryptohomeError;
using hwsec_foundation::error::testing::IsOk;
using hwsec_foundation::status::MakeStatus;
using hwsec_foundation::status::OkStatus;
using hwsec_foundation::status::StatusChain;
using testing::ElementsAre;
using testing::IsEmpty;
using testing::NiceMock;
using testing::Not;
using testing::Pair;

namespace cryptohome {
namespace {

constexpr char kSomeIdpLabel[] = "some-idp";
constexpr char kChromeosVersion[] = "a.b.c_1_2_3";
constexpr char kChromeVersion[] = "a.b.c.d";

AuthBlockState CreatePasswordAuthBlockState(const std::string& suffix = "") {
  TpmBoundToPcrAuthBlockState tpm_bound_to_pcr_auth_block_state = {
      .scrypt_derived = false,
      .salt = SecureBlob("fake salt " + suffix),
      .tpm_key = SecureBlob("fake tpm key " + suffix),
      .extended_tpm_key = SecureBlob("fake extended tpm key " + suffix),
      .tpm_public_key_hash = SecureBlob("fake tpm public key hash"),
  };
  AuthBlockState auth_block_state = {.state =
                                         tpm_bound_to_pcr_auth_block_state};
  return auth_block_state;
}

std::unique_ptr<AuthFactor> CreatePasswordAuthFactor() {
  AuthFactorMetadata metadata = {
      .common =
          auth_factor::CommonMetadata{
              .chromeos_version_last_updated = kChromeosVersion,
              .chrome_version_last_updated = kChromeVersion,
          },
      .metadata = auth_factor::PasswordMetadata()};
  return std::make_unique<AuthFactor>(AuthFactorType::kPassword, kSomeIdpLabel,
                                      metadata, CreatePasswordAuthBlockState());
}

}  // namespace

class AuthFactorManagerTest : public ::testing::Test {
 protected:
  const ObfuscatedUsername kObfuscatedUsername{"obfuscated1"};

  MockPlatform platform_;
  AuthFactorManager auth_factor_manager_{&platform_};
  base::test::SingleThreadTaskEnvironment task_environment_ = {
      base::test::TaskEnvironment::TimeSource::MOCK_TIME};
  scoped_refptr<base::SequencedTaskRunner> task_runner_ =
      base::SequencedTaskRunner::GetCurrentDefault();
};

// Test the `SaveAuthFactor()` method correctly serializes the factor into a
// file.
TEST_F(AuthFactorManagerTest, Save) {
  std::unique_ptr<AuthFactor> auth_factor = CreatePasswordAuthFactor();

  // Persist the auth factor.
  EXPECT_TRUE(
      auth_factor_manager_.SaveAuthFactor(kObfuscatedUsername, *auth_factor)
          .ok());
  EXPECT_TRUE(platform_.FileExists(
      AuthFactorPath(kObfuscatedUsername,
                     /*auth_factor_type_string=*/"password", kSomeIdpLabel)));

  // Load the auth factor and verify it's the same.
  CryptohomeStatusOr<std::unique_ptr<AuthFactor>> loaded_auth_factor_status =
      auth_factor_manager_.LoadAuthFactor(
          kObfuscatedUsername, AuthFactorType::kPassword, kSomeIdpLabel);
  ASSERT_TRUE(loaded_auth_factor_status.ok());
  ASSERT_TRUE(loaded_auth_factor_status.value());
  AuthFactor& loaded_auth_factor = **loaded_auth_factor_status;
  EXPECT_EQ(loaded_auth_factor.type(), AuthFactorType::kPassword);
  EXPECT_EQ(loaded_auth_factor.label(), kSomeIdpLabel);
  EXPECT_EQ(loaded_auth_factor.metadata().common.chromeos_version_last_updated,
            kChromeosVersion);
  EXPECT_EQ(loaded_auth_factor.metadata().common.chrome_version_last_updated,
            kChromeVersion);
  EXPECT_TRUE(absl::holds_alternative<auth_factor::PasswordMetadata>(
      loaded_auth_factor.metadata().metadata));
  EXPECT_EQ(auth_factor->auth_block_state(),
            loaded_auth_factor.auth_block_state());
  // TODO(b/204441443): Check other fields too. Consider using a GTest matcher.
}

// Test the `SaveAuthFactor()` method fails when the label is empty.
TEST_F(AuthFactorManagerTest, SaveBadEmptyLabel) {
  // Create an auth factor as a clone of a correct object, but with an empty
  // label.
  std::unique_ptr<AuthFactor> good_auth_factor = CreatePasswordAuthFactor();
  AuthFactor bad_auth_factor(good_auth_factor->type(),
                             /*label=*/std::string(),
                             good_auth_factor->metadata(),
                             good_auth_factor->auth_block_state());

  // Verify the manager refuses to save this auth factor.
  EXPECT_FALSE(
      auth_factor_manager_.SaveAuthFactor(kObfuscatedUsername, bad_auth_factor)
          .ok());
}

// Test the `SaveAuthFactor()` method fails when the label contains forbidden
// characters.
TEST_F(AuthFactorManagerTest, SaveBadMalformedLabel) {
  // Create an auth factor as a clone of a correct object, but with a malformed
  // label.
  std::unique_ptr<AuthFactor> good_auth_factor = CreatePasswordAuthFactor();
  AuthFactor bad_auth_factor(good_auth_factor->type(),
                             /*label=*/"foo.' bar'",
                             good_auth_factor->metadata(),
                             good_auth_factor->auth_block_state());

  // Verify the manager refuses to save this auth factor.
  EXPECT_FALSE(
      auth_factor_manager_.SaveAuthFactor(kObfuscatedUsername, bad_auth_factor)
          .ok());
}

// Test that `ListAuthFactors()` returns an empty map when there's no auth
// factor added.
TEST_F(AuthFactorManagerTest, ListEmpty) {
  AuthFactorManager::LabelToTypeMap factor_map =
      auth_factor_manager_.ListAuthFactors(kObfuscatedUsername);
  EXPECT_THAT(factor_map, IsEmpty());
}

// Test that `ListAuthFactors()` returns the auth factor that was added.
TEST_F(AuthFactorManagerTest, ListSingle) {
  // Create the auth factor file.
  std::unique_ptr<AuthFactor> auth_factor = CreatePasswordAuthFactor();
  EXPECT_TRUE(
      auth_factor_manager_.SaveAuthFactor(kObfuscatedUsername, *auth_factor)
          .ok());

  // Verify the factor is listed.
  AuthFactorManager::LabelToTypeMap factor_map =
      auth_factor_manager_.ListAuthFactors(kObfuscatedUsername);
  EXPECT_THAT(factor_map,
              ElementsAre(Pair(kSomeIdpLabel, AuthFactorType::kPassword)));
}

// Test that `ListAuthFactors()` ignores an auth factor without a file name
// extension (and hence without a label).
TEST_F(AuthFactorManagerTest, ListBadNoExtension) {
  // Create files with correct and malformed names.
  platform_.WriteFile(AuthFactorsDirPath(kObfuscatedUsername)
                          .Append("password")
                          .AddExtension(kSomeIdpLabel),
                      /*blob=*/{});
  platform_.WriteFile(
      AuthFactorsDirPath(kObfuscatedUsername).Append("password"), /*blob=*/{});

  // Verify the malformed file is ignored, and the good one is still listed.
  AuthFactorManager::LabelToTypeMap factor_map =
      auth_factor_manager_.ListAuthFactors(kObfuscatedUsername);
  EXPECT_THAT(factor_map,
              ElementsAre(Pair(kSomeIdpLabel, AuthFactorType::kPassword)));
}

// Test that `ListAuthFactors()` ignores an auth factor with an empty file name
// extension (and hence without a label).
TEST_F(AuthFactorManagerTest, ListBadEmptyExtension) {
  // Create files with correct and malformed names.
  platform_.WriteFile(AuthFactorsDirPath(kObfuscatedUsername)
                          .Append("password")
                          .AddExtension(kSomeIdpLabel),
                      /*blob=*/{});
  platform_.WriteFile(
      AuthFactorsDirPath(kObfuscatedUsername).Append("password."), /*blob=*/{});

  // Verify the malformed file is ignored, and the good one is still listed.
  AuthFactorManager::LabelToTypeMap factor_map =
      auth_factor_manager_.ListAuthFactors(kObfuscatedUsername);
  EXPECT_THAT(factor_map,
              ElementsAre(Pair(kSomeIdpLabel, AuthFactorType::kPassword)));
}

// Test that `ListAuthFactors()` ignores an auth factor with multiple file name
// extensions (and hence with an incorrect label).
TEST_F(AuthFactorManagerTest, ListBadMultipleExtensions) {
  // Create files with correct and malformed names.
  platform_.WriteFile(AuthFactorsDirPath(kObfuscatedUsername)
                          .Append("password")
                          .AddExtension(kSomeIdpLabel),
                      /*blob=*/{});
  platform_.WriteFile(
      AuthFactorsDirPath(kObfuscatedUsername).Append("password.label.garbage"),
      /*blob=*/{});
  platform_.WriteFile(
      AuthFactorsDirPath(kObfuscatedUsername).Append("password.tar.gz"),
      /*blob=*/{});

  // Verify the malformed files are ignored, and the good one is still listed.
  AuthFactorManager::LabelToTypeMap factor_map =
      auth_factor_manager_.ListAuthFactors(kObfuscatedUsername);
  EXPECT_THAT(factor_map,
              ElementsAre(Pair(kSomeIdpLabel, AuthFactorType::kPassword)));
}

// Test that `ListAuthFactors()` ignores an auth factor with the file name
// consisting of just an extension (and hence without a factor type).
TEST_F(AuthFactorManagerTest, ListBadEmptyType) {
  // Create files with correct and malformed names.
  platform_.WriteFile(AuthFactorsDirPath(kObfuscatedUsername)
                          .Append("password")
                          .AddExtension(kSomeIdpLabel),
                      /*blob=*/{});
  platform_.WriteFile(AuthFactorsDirPath(kObfuscatedUsername).Append(".label"),
                      /*blob=*/{});

  // Verify the malformed file is ignored, and the good one is still listed.
  AuthFactorManager::LabelToTypeMap factor_map =
      auth_factor_manager_.ListAuthFactors(kObfuscatedUsername);
  EXPECT_THAT(factor_map,
              ElementsAre(Pair(kSomeIdpLabel, AuthFactorType::kPassword)));
}

// Test that `ListAuthFactors()` ignores an auth factor whose file name has a
// garbage instead of the factor type.
TEST_F(AuthFactorManagerTest, ListBadUnknownType) {
  // Create files with correct and malformed names.
  platform_.WriteFile(AuthFactorsDirPath(kObfuscatedUsername)
                          .Append("password")
                          .AddExtension(kSomeIdpLabel),
                      /*blob=*/{});
  platform_.WriteFile(
      AuthFactorsDirPath(kObfuscatedUsername).Append("fancytype.label"),
      /*blob=*/{});

  // Verify the malformed file is ignored, and the good one is still listed.
  AuthFactorManager::LabelToTypeMap factor_map =
      auth_factor_manager_.ListAuthFactors(kObfuscatedUsername);
  EXPECT_THAT(factor_map,
              ElementsAre(Pair(kSomeIdpLabel, AuthFactorType::kPassword)));
}

// TODO(b:208348570): Test clash of labels once more than one factor type is
// supported by AuthFactorManager.

TEST_F(AuthFactorManagerTest, RemoveSuccess) {
  std::unique_ptr<AuthFactor> auth_factor = CreatePasswordAuthFactor();

  // Persist the auth factor.
  EXPECT_THAT(
      auth_factor_manager_.SaveAuthFactor(kObfuscatedUsername, *auth_factor),
      IsOk());
  CryptohomeStatusOr<std::unique_ptr<AuthFactor>> loaded_auth_factor =
      auth_factor_manager_.LoadAuthFactor(
          kObfuscatedUsername, AuthFactorType::kPassword, kSomeIdpLabel);
  EXPECT_THAT(loaded_auth_factor, IsOk());

  NiceMock<MockAuthBlockUtility> auth_block_utility;

  // Delete auth factor.
  TestFuture<CryptohomeStatus> remove_result;
  auth_factor_manager_.RemoveAuthFactor(kObfuscatedUsername, *auth_factor,
                                        &auth_block_utility,
                                        remove_result.GetCallback());
  EXPECT_TRUE(remove_result.IsReady());
  EXPECT_THAT(remove_result.Take(), IsOk());

  // Try to load the auth factor.
  CryptohomeStatusOr<std::unique_ptr<AuthFactor>> loaded_auth_factor_1 =
      auth_factor_manager_.LoadAuthFactor(
          kObfuscatedUsername, AuthFactorType::kPassword, kSomeIdpLabel);
  EXPECT_THAT(loaded_auth_factor_1, Not(IsOk()));
  EXPECT_FALSE(platform_.FileExists(
      AuthFactorPath(kObfuscatedUsername,
                     /*auth_factor_type_string=*/"password", kSomeIdpLabel)
          .AddExtension(cryptohome::kChecksumExtension)));
}

TEST_F(AuthFactorManagerTest, RemoveFailureWithAuthBlock) {
  const CryptohomeError::ErrorLocationPair
      error_location_for_testing_auth_factor =
          CryptohomeError::ErrorLocationPair(
              static_cast<::cryptohome::error::CryptohomeError::ErrorLocation>(
                  1),
              std::string("MockErrorLocationAuthFactor"));

  std::unique_ptr<AuthFactor> auth_factor = CreatePasswordAuthFactor();

  // Persist the auth factor.
  EXPECT_THAT(
      auth_factor_manager_.SaveAuthFactor(kObfuscatedUsername, *auth_factor),
      IsOk());
  CryptohomeStatusOr<std::unique_ptr<AuthFactor>> loaded_auth_factor =
      auth_factor_manager_.LoadAuthFactor(
          kObfuscatedUsername, AuthFactorType::kPassword, kSomeIdpLabel);
  EXPECT_THAT(loaded_auth_factor, IsOk());

  NiceMock<MockAuthBlockUtility> auth_block_utility;

  // Intentionally fail the PrepareAuthBlockForRemoval for password factor.
  EXPECT_CALL(auth_block_utility, PrepareAuthBlockForRemoval(_, _))
      .WillOnce([&](const AuthBlockState& auth_state,
                    AuthBlockUtility::CryptohomeStatusCallback callback) {
        std::move(callback).Run(MakeStatus<error::CryptohomeCryptoError>(
            error_location_for_testing_auth_factor,
            error::ErrorActionSet(
                {error::PossibleAction::kDevCheckUnexpectedState}),
            CryptoError::CE_OTHER_CRYPTO));
      });

  // Try to delete auth factor.
  TestFuture<CryptohomeStatus> remove_result;
  auth_factor_manager_.RemoveAuthFactor(kObfuscatedUsername, *auth_factor,
                                        &auth_block_utility,
                                        remove_result.GetCallback());
  EXPECT_TRUE(remove_result.IsReady());
  EXPECT_THAT(remove_result.Take(), Not(IsOk()));
  EXPECT_TRUE(platform_.FileExists(
      AuthFactorPath(kObfuscatedUsername,
                     /*auth_factor_type_string=*/"password", kSomeIdpLabel)
          .AddExtension(cryptohome::kChecksumExtension)));
}

TEST_F(AuthFactorManagerTest, RemoveFailureWithFactorFile) {
  std::unique_ptr<AuthFactor> auth_factor = CreatePasswordAuthFactor();

  // Persist the auth factor.
  EXPECT_THAT(
      auth_factor_manager_.SaveAuthFactor(kObfuscatedUsername, *auth_factor),
      IsOk());
  CryptohomeStatusOr<std::unique_ptr<AuthFactor>> loaded_auth_factor =
      auth_factor_manager_.LoadAuthFactor(
          kObfuscatedUsername, AuthFactorType::kPassword, kSomeIdpLabel);
  EXPECT_THAT(loaded_auth_factor, IsOk());

  NiceMock<MockAuthBlockUtility> auth_block_utility;

  // Intentionally fail the auth factor file removal.
  auto auth_factor_file_path =
      AuthFactorPath(kObfuscatedUsername,
                     /*auth_factor_type_string=*/"password", kSomeIdpLabel);
  EXPECT_CALL(platform_, DeleteFileSecurely(auth_factor_file_path))
      .WillOnce(Return(false));
  EXPECT_CALL(platform_, DeleteFile(auth_factor_file_path))
      .WillOnce(Return(false));

  // Try to delete auth factor.
  TestFuture<CryptohomeStatus> remove_result;
  auth_factor_manager_.RemoveAuthFactor(kObfuscatedUsername, *auth_factor,
                                        &auth_block_utility,
                                        remove_result.GetCallback());
  EXPECT_TRUE(remove_result.IsReady());
  EXPECT_THAT(remove_result.Take(), Not(IsOk()));
  EXPECT_TRUE(platform_.FileExists(
      AuthFactorPath(kObfuscatedUsername,
                     /*auth_factor_type_string=*/"password", kSomeIdpLabel)
          .AddExtension(cryptohome::kChecksumExtension)));
}

TEST_F(AuthFactorManagerTest, RemoveOkWithChecksumFileRemovalFailure) {
  std::unique_ptr<AuthFactor> auth_factor = CreatePasswordAuthFactor();

  // Persist the auth factor.
  EXPECT_THAT(
      auth_factor_manager_.SaveAuthFactor(kObfuscatedUsername, *auth_factor),
      IsOk());
  CryptohomeStatusOr<std::unique_ptr<AuthFactor>> loaded_auth_factor =
      auth_factor_manager_.LoadAuthFactor(
          kObfuscatedUsername, AuthFactorType::kPassword, kSomeIdpLabel);
  EXPECT_THAT(loaded_auth_factor, IsOk());

  NiceMock<MockAuthBlockUtility> auth_block_utility;

  auto auth_factor_file_path =
      AuthFactorPath(kObfuscatedUsername,
                     /*auth_factor_type_string=*/"password", kSomeIdpLabel);
  auto auth_factor_checksum_file_path =
      auth_factor_file_path.AddExtension(kChecksumExtension);
  // Removes the auth factor file.
  EXPECT_CALL(platform_, DeleteFileSecurely(auth_factor_file_path))
      .WillOnce(Return(true));
  // Intentionally fail the auth factor checksum removal.
  EXPECT_CALL(platform_, DeleteFileSecurely(auth_factor_checksum_file_path))
      .WillOnce(Return(false));
  EXPECT_CALL(platform_, DeleteFile(auth_factor_checksum_file_path))
      .WillOnce(Return(false));

  // Try to delete auth factor and it should still succeed.
  TestFuture<CryptohomeStatus> remove_result;
  auth_factor_manager_.RemoveAuthFactor(kObfuscatedUsername, *auth_factor,
                                        &auth_block_utility,
                                        remove_result.GetCallback());
  EXPECT_TRUE(remove_result.IsReady());
  EXPECT_THAT(remove_result.Take(), IsOk());
  EXPECT_TRUE(platform_.FileExists(auth_factor_checksum_file_path));
}

TEST_F(AuthFactorManagerTest, Update) {
  NiceMock<MockAuthBlockUtility> auth_block_utility;
  std::unique_ptr<AuthFactor> auth_factor = CreatePasswordAuthFactor();
  // Persist the auth factor.
  EXPECT_TRUE(
      auth_factor_manager_.SaveAuthFactor(kObfuscatedUsername, *auth_factor)
          .ok());
  EXPECT_TRUE(platform_.FileExists(
      AuthFactorPath(kObfuscatedUsername,
                     /*auth_factor_type_string=*/"password", kSomeIdpLabel)));

  // Load the auth factor and verify it's the same.
  CryptohomeStatusOr<std::unique_ptr<AuthFactor>> loaded_auth_factor =
      auth_factor_manager_.LoadAuthFactor(
          kObfuscatedUsername, AuthFactorType::kPassword, kSomeIdpLabel);
  ASSERT_TRUE(loaded_auth_factor.ok());
  ASSERT_TRUE(loaded_auth_factor.value());
  EXPECT_EQ(loaded_auth_factor.value()->auth_block_state(),
            auth_factor->auth_block_state());

  AuthBlockState new_state = CreatePasswordAuthBlockState("new auth factor");
  AuthFactor new_auth_factor(auth_factor->type(), auth_factor->label(),
                             auth_factor->metadata(), new_state);
  TestFuture<CryptohomeStatus> update_result;
  // Update the auth factor.
  auth_factor_manager_.UpdateAuthFactor(
      kObfuscatedUsername, auth_factor->label(), new_auth_factor,
      &auth_block_utility, update_result.GetCallback());
  EXPECT_TRUE(update_result.IsReady());
  EXPECT_THAT(update_result.Take(), IsOk());
  EXPECT_TRUE(platform_.FileExists(
      AuthFactorPath(kObfuscatedUsername,
                     /*auth_factor_type_string=*/"password", kSomeIdpLabel)));

  // Load the auth factor and verify it's the same.
  CryptohomeStatusOr<std::unique_ptr<AuthFactor>> loaded_auth_factor_1 =
      auth_factor_manager_.LoadAuthFactor(
          kObfuscatedUsername, AuthFactorType::kPassword, kSomeIdpLabel);
  ASSERT_TRUE(loaded_auth_factor_1.ok());
  ASSERT_TRUE(loaded_auth_factor_1.value());
  EXPECT_EQ(loaded_auth_factor_1.value()->auth_block_state(), new_state);
  EXPECT_NE(loaded_auth_factor_1.value()->auth_block_state(),
            auth_factor->auth_block_state());
}

// Test that UpdateAuthFactor fails if the removal of
// the old auth block state failed.
TEST_F(AuthFactorManagerTest, UpdateFailureWithRemoval) {
  NiceMock<MockAuthBlockUtility> auth_block_utility;
  // Intentionally fail the PrepareAuthBlockForRemoval for password factor.
  const CryptohomeError::ErrorLocationPair
      error_location_for_testing_auth_factor =
          CryptohomeError::ErrorLocationPair(
              static_cast<::cryptohome::error::CryptohomeError::ErrorLocation>(
                  1),
              std::string("MockErrorLocationAuthFactor"));
  EXPECT_CALL(auth_block_utility, PrepareAuthBlockForRemoval(_, _))
      .WillOnce([&](const AuthBlockState& auth_state,
                    AuthBlockUtility::CryptohomeStatusCallback callback) {
        std::move(callback).Run(MakeStatus<error::CryptohomeCryptoError>(
            error_location_for_testing_auth_factor,
            error::ErrorActionSet(
                {error::PossibleAction::kDevCheckUnexpectedState}),
            CryptoError::CE_OTHER_CRYPTO));
      });
  std::unique_ptr<AuthFactor> auth_factor = CreatePasswordAuthFactor();
  // Persist the auth factor.
  EXPECT_TRUE(
      auth_factor_manager_.SaveAuthFactor(kObfuscatedUsername, *auth_factor)
          .ok());
  EXPECT_TRUE(platform_.FileExists(
      AuthFactorPath(kObfuscatedUsername,
                     /*auth_factor_type_string=*/"password", kSomeIdpLabel)));

  // Load the auth factor and verify it's the same.
  CryptohomeStatusOr<std::unique_ptr<AuthFactor>> loaded_auth_factor =
      auth_factor_manager_.LoadAuthFactor(
          kObfuscatedUsername, AuthFactorType::kPassword, kSomeIdpLabel);
  ASSERT_TRUE(loaded_auth_factor.ok());
  ASSERT_TRUE(loaded_auth_factor.value());
  EXPECT_EQ(loaded_auth_factor.value()->auth_block_state(),
            auth_factor->auth_block_state());

  AuthBlockState new_state = CreatePasswordAuthBlockState("new auth factor");
  AuthFactor new_auth_factor(auth_factor->type(), auth_factor->label(),
                             auth_factor->metadata(), new_state);
  TestFuture<CryptohomeStatus> update_result;
  // Update the auth factor.
  auth_factor_manager_.UpdateAuthFactor(
      kObfuscatedUsername, auth_factor->label(), new_auth_factor,
      &auth_block_utility, update_result.GetCallback());
  EXPECT_TRUE(update_result.IsReady());
  EXPECT_THAT(update_result.Take(), Not(IsOk()));
}

TEST_F(AuthFactorManagerTest, UpdateFailsWhenNoAuthFactor) {
  NiceMock<MockAuthBlockUtility> auth_block_utility;
  std::unique_ptr<AuthFactor> auth_factor = CreatePasswordAuthFactor();
  // Try to update the auth factor.
  TestFuture<CryptohomeStatus> update_result;
  auth_factor_manager_.UpdateAuthFactor(
      kObfuscatedUsername, auth_factor->label(), *auth_factor,
      &auth_block_utility, update_result.GetCallback());
  EXPECT_TRUE(update_result.IsReady());
  EXPECT_THAT(update_result.Take(), Not(IsOk()));
}

}  // namespace cryptohome
