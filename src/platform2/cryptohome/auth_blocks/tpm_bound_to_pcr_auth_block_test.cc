// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/auth_blocks/tpm_bound_to_pcr_auth_block.h"

#include <memory>
#include <optional>
#include <utility>
#include <variant>

#include <base/test/bind.h>
#include <base/test/task_environment.h>
#include <base/test/test_future.h>
#include <gtest/gtest.h>
#include <libhwsec-foundation/crypto/aes.h>
#include <libhwsec-foundation/crypto/rsa.h>
#include <libhwsec-foundation/crypto/scrypt.h>
#include <libhwsec-foundation/error/testing_helper.h>

#include "cryptohome/auth_blocks/auth_block.h"
#include "cryptohome/auth_blocks/auth_block_utils.h"
#include "cryptohome/flatbuffer_schemas/auth_block_state.h"
#include "cryptohome/mock_cryptohome_keys_manager.h"

namespace cryptohome {
namespace {

using base::test::TestFuture;
using ::hwsec::TPMError;
using ::hwsec::TPMRetryAction;
using ::hwsec_foundation::DeriveSecretsScrypt;
using ::hwsec_foundation::kDefaultAesKeySize;
using ::hwsec_foundation::kDefaultPassBlobSize;
using hwsec_foundation::error::testing::IsOk;
using hwsec_foundation::error::testing::NotOk;
using ::hwsec_foundation::error::testing::ReturnError;
using ::hwsec_foundation::error::testing::ReturnValue;
using ::testing::_;
using ::testing::DoAll;
using ::testing::Exactly;
using ::testing::Invoke;
using ::testing::NiceMock;
using ::testing::Return;
using ::testing::SaveArg;
using ::testing::SetArgPointee;

using CreateTestFuture = TestFuture<CryptohomeStatus,
                                    std::unique_ptr<KeyBlobs>,
                                    std::unique_ptr<AuthBlockState>>;

using DeriveTestFuture = TestFuture<CryptohomeStatus,
                                    std::unique_ptr<KeyBlobs>,
                                    std::optional<AuthBlock::SuggestedAction>>;

constexpr char kUsername[] = "fake_username";

void SetupMockHwsec(NiceMock<hwsec::MockCryptohomeFrontend>& hwsec) {
  ON_CALL(hwsec, GetPubkeyHash(_))
      .WillByDefault(ReturnValue(brillo::BlobFromString("public key hash")));
  ON_CALL(hwsec, IsEnabled()).WillByDefault(ReturnValue(true));
  ON_CALL(hwsec, IsReady()).WillByDefault(ReturnValue(true));
}

}  // namespace

class TpmBoundToPcrTest : public ::testing::Test {
  void SetUp() override {
    SetupMockHwsec(hwsec_);
    auth_block_ = std::make_unique<TpmBoundToPcrAuthBlock>(
        &hwsec_, &cryptohome_keys_manager_);
  }

 protected:
  NiceMock<hwsec::MockCryptohomeFrontend> hwsec_;
  NiceMock<MockCryptohomeKeysManager> cryptohome_keys_manager_;
  std::unique_ptr<TpmBoundToPcrAuthBlock> auth_block_;

  base::test::TaskEnvironment task_environment_;
};

TEST_F(TpmBoundToPcrTest, CreateTest) {
  // Set up inputs to the test.
  brillo::SecureBlob vault_key(20, 'C');
  SerializedVaultKeyset serialized;

  // Set up the mock expectations.
  brillo::SecureBlob scrypt_derived_key;
  brillo::SecureBlob auth_value(256, 'a');

  EXPECT_CALL(hwsec_, GetAuthValue(_, _))
      .WillOnce(
          DoAll(SaveArg<1>(&scrypt_derived_key), ReturnValue(auth_value)));
  EXPECT_CALL(hwsec_, SealWithCurrentUser(_, auth_value, _)).Times(Exactly(2));
  ON_CALL(hwsec_, SealWithCurrentUser(_, _, _))
      .WillByDefault(ReturnValue(brillo::Blob()));

  AuthInput user_input = {vault_key,
                          /*locked_to_single_user=*/std::nullopt, Username(),
                          ObfuscatedUsername(kUsername),
                          /*reset_secret=*/std::nullopt};

  CreateTestFuture result;
  auth_block_->Create(user_input, result.GetCallback());
  ASSERT_TRUE(result.IsReady());

  auto [status, key_blobs, auth_state] = result.Take();
  ASSERT_THAT(status, IsOk());
  EXPECT_TRUE(
      std::holds_alternative<TpmBoundToPcrAuthBlockState>(auth_state->state));

  EXPECT_NE(key_blobs->vkk_key, std::nullopt);
  EXPECT_NE(key_blobs->vkk_iv, std::nullopt);
  EXPECT_NE(key_blobs->chaps_iv, std::nullopt);

  auto& tpm_state = std::get<TpmBoundToPcrAuthBlockState>(auth_state->state);

  EXPECT_TRUE(tpm_state.salt.has_value());
  const brillo::SecureBlob& salt = tpm_state.salt.value();
  brillo::SecureBlob scrypt_derived_key_result(kDefaultPassBlobSize);
  EXPECT_TRUE(
      DeriveSecretsScrypt(vault_key, salt, {&scrypt_derived_key_result}));
  EXPECT_EQ(scrypt_derived_key, scrypt_derived_key_result);
}

TEST_F(TpmBoundToPcrTest, CreateFailTpm) {
  // Set up inputs to the test.
  brillo::SecureBlob vault_key(20, 'C');
  SerializedVaultKeyset serialized;

  // Set up the mock expectations.
  EXPECT_CALL(hwsec_, GetAuthValue(_, _))
      .WillOnce(DoAll(ReturnValue(brillo::Blob())));

  ON_CALL(hwsec_, SealWithCurrentUser(_, _, _))
      .WillByDefault(ReturnError<TPMError>("fake", TPMRetryAction::kNoRetry));

  AuthInput user_input = {vault_key,
                          /*locked_to_single_user=*/std::nullopt, Username(),
                          ObfuscatedUsername(kUsername),
                          /*reset_secret=*/std::nullopt};
  AuthBlockState auth_state;
  CreateTestFuture result;
  auth_block_->Create(user_input, result.GetCallback());
  ASSERT_TRUE(result.IsReady());

  ASSERT_THAT(result.Get<0>(), NotOk());
  ASSERT_EQ(result.Get<0>()->local_legacy_error(),
            user_data_auth::CRYPTOHOME_ERROR_AUTHORIZATION_KEY_FAILED);
}

// Test the Create operation fails when there's no user_input provided.
TEST_F(TpmBoundToPcrTest, CreateFailNoUserInput) {
  // Prepare.
  AuthInput auth_input = {.obfuscated_username = ObfuscatedUsername(kUsername)};

  // Test.
  CreateTestFuture result;
  auth_block_->Create(auth_input, result.GetCallback());
  ASSERT_TRUE(result.IsReady());

  ASSERT_THAT(result.Get<0>(), NotOk());
  ASSERT_EQ(result.Get<0>()->local_legacy_error(),
            user_data_auth::CRYPTOHOME_ERROR_AUTHORIZATION_KEY_FAILED);
}

// Test the Create operation fails when there's no obfuscated_username provided.
TEST_F(TpmBoundToPcrTest, CreateFailNoObfuscated) {
  // Prepare.
  brillo::SecureBlob user_input(20, 'C');
  AuthInput auth_input = {.user_input = user_input};

  // Test.
  CreateTestFuture result;
  auth_block_->Create(auth_input, result.GetCallback());
  ASSERT_TRUE(result.IsReady());

  ASSERT_THAT(result.Get<0>(), NotOk());
  ASSERT_EQ(result.Get<0>()->local_legacy_error(),
            user_data_auth::CRYPTOHOME_ERROR_AUTHORIZATION_KEY_FAILED);
}

TEST_F(TpmBoundToPcrTest, DecryptBoundToPcrTest) {
  AuthBlockState auth_state;
  TpmBoundToPcrAuthBlockState state;
  state.scrypt_derived = true;
  state.salt = brillo::SecureBlob(PKCS5_SALT_LEN, 'S');
  state.tpm_key = brillo::SecureBlob(20, 'T');
  state.extended_tpm_key = brillo::SecureBlob(20, 'T');
  auth_state.state = std::move(state);

  AuthInput auth_input;
  auth_input.user_input = brillo::SecureBlob(20, 'I');
  auth_input.locked_to_single_user = false;

  brillo::SecureBlob pass_blob(kDefaultPassBlobSize);
  ASSERT_TRUE(
      DeriveSecretsScrypt(*auth_input.user_input, *state.salt, {&pass_blob}));

  EXPECT_CALL(hwsec_, PreloadSealedData(_)).WillOnce(Invoke([&](auto&&) {
    return hwsec::ScopedKey(hwsec::Key{.token = 5566},
                            hwsec_.GetFakeMiddlewareDerivative());
  }));
  brillo::SecureBlob auth_value(256, 'a');
  EXPECT_CALL(hwsec_, GetAuthValue(_, pass_blob))
      .WillOnce(ReturnValue(auth_value));
  EXPECT_CALL(hwsec_, UnsealWithCurrentUser(_, auth_value, _))
      .WillOnce([](std::optional<hwsec::Key> preload_data, auto&&, auto&&) {
        EXPECT_TRUE(preload_data.has_value());
        EXPECT_EQ(preload_data->token, 5566);
        return brillo::SecureBlob();
      });

  // Test
  DeriveTestFuture derive_result;
  auth_block_->Derive(auth_input, auth_state, derive_result.GetCallback());
  ASSERT_TRUE(derive_result.IsReady());
  auto [derive_status, derive_key_blobs, suggested_action] =
      derive_result.Take();
  ASSERT_THAT(derive_status, IsOk());
}

TEST_F(TpmBoundToPcrTest, DecryptBoundToPcrNoPreloadTest) {
  // Setup
  AuthBlockState auth_state;
  TpmBoundToPcrAuthBlockState state;
  state.scrypt_derived = true;
  state.salt = brillo::SecureBlob(PKCS5_SALT_LEN, 'S');
  state.tpm_key = brillo::SecureBlob(20, 'T');
  state.extended_tpm_key = brillo::SecureBlob(20, 'T');
  auth_state.state = std::move(state);

  AuthInput auth_input;
  auth_input.user_input = brillo::SecureBlob(20, 'I');
  auth_input.locked_to_single_user = false;

  EXPECT_CALL(hwsec_, PreloadSealedData(_)).WillOnce(ReturnValue(std::nullopt));
  brillo::SecureBlob auth_value(256, 'a');
  brillo::SecureBlob pass_blob(kDefaultPassBlobSize);
  ASSERT_TRUE(
      DeriveSecretsScrypt(*auth_input.user_input, *state.salt, {&pass_blob}));

  EXPECT_CALL(hwsec_, GetAuthValue(_, pass_blob))
      .WillOnce(ReturnValue(auth_value));
  EXPECT_CALL(hwsec_, UnsealWithCurrentUser(_, auth_value, _))
      .WillOnce([](std::optional<hwsec::Key> preload_data, auto&&, auto&&) {
        EXPECT_FALSE(preload_data.has_value());
        return brillo::SecureBlob();
      });

  // Test
  DeriveTestFuture derive_result;
  auth_block_->Derive(auth_input, auth_state, derive_result.GetCallback());
  ASSERT_TRUE(derive_result.IsReady());
  auto [derive_status, derive_key_blobs, suggested_action] =
      derive_result.Take();
  ASSERT_THAT(derive_status, IsOk());
}

TEST_F(TpmBoundToPcrTest, DecryptBoundToPcrPreloadFailedTest) {
  AuthBlockState auth_state;
  TpmBoundToPcrAuthBlockState state;
  state.scrypt_derived = true;
  state.salt = brillo::SecureBlob(PKCS5_SALT_LEN, 'S');
  state.tpm_key = brillo::SecureBlob(20, 'T');
  state.extended_tpm_key = brillo::SecureBlob(20, 'T');
  auth_state.state = std::move(state);

  AuthInput auth_input;
  auth_input.user_input = brillo::SecureBlob(20, 'I');
  auth_input.locked_to_single_user = false;

  EXPECT_CALL(hwsec_, PreloadSealedData(_))
      .WillOnce(ReturnError<TPMError>("fake", TPMRetryAction::kNoRetry));

  DeriveTestFuture derive_result;
  auth_block_->Derive(auth_input, auth_state, derive_result.GetCallback());
  ASSERT_TRUE(derive_result.IsReady());
  auto [derive_status, derive_key_blobs, suggested_action] =
      derive_result.Take();
  ASSERT_THAT(derive_status, NotOk());
}

TEST_F(TpmBoundToPcrTest, DeriveTest) {
  // Setup
  AuthBlockState auth_state;
  TpmBoundToPcrAuthBlockState state;
  state.scrypt_derived = true;
  state.salt = brillo::SecureBlob(PKCS5_SALT_LEN, 'S');
  state.tpm_key = brillo::SecureBlob(20, 'T');
  state.extended_tpm_key = brillo::SecureBlob(20, 'T');
  auth_state.state = std::move(state);

  // Make sure TpmAuthBlock calls DecryptTpmBoundToPcr in this case.
  EXPECT_CALL(hwsec_, PreloadSealedData(_)).WillOnce(ReturnValue(std::nullopt));
  EXPECT_CALL(hwsec_, GetAuthValue(_, _))
      .WillOnce(ReturnValue(brillo::SecureBlob()));
  EXPECT_CALL(hwsec_, UnsealWithCurrentUser(_, _, _))
      .WillOnce(ReturnValue(brillo::SecureBlob()));

  AuthInput auth_input;
  auth_input.user_input = brillo::SecureBlob(20, 'I');
  auth_input.locked_to_single_user = false;

  DeriveTestFuture derive_result;
  auth_block_->Derive(auth_input, auth_state, derive_result.GetCallback());
  ASSERT_TRUE(derive_result.IsReady());
  auto [derive_status, derive_key_blobs, suggested_action] =
      derive_result.Take();
  ASSERT_THAT(derive_status, IsOk());

  // Assert that the returned key blobs isn't uninitialized.
  EXPECT_NE(derive_key_blobs->vkk_iv, std::nullopt);
  EXPECT_NE(derive_key_blobs->vkk_key, std::nullopt);
  EXPECT_EQ(derive_key_blobs->vkk_iv.value(),
            derive_key_blobs->chaps_iv.value());
  EXPECT_EQ(suggested_action, std::nullopt);
}

// Test TpmBoundToPcrAuthBlock derive fails when there's no user_input provided.
TEST_F(TpmBoundToPcrTest, DeriveFailureNoUserInput) {
  brillo::SecureBlob tpm_key(20, 'C');
  brillo::SecureBlob salt(PKCS5_SALT_LEN, 'A');
  AuthBlockState auth_state;
  TpmBoundToPcrAuthBlockState state;
  state.scrypt_derived = true;
  state.salt = salt;
  state.tpm_key = tpm_key;
  state.extended_tpm_key = tpm_key;
  auth_state.state = std::move(state);

  AuthInput auth_input = {};
  DeriveTestFuture derive_result;
  auth_block_->Derive(auth_input, auth_state, derive_result.GetCallback());
  ASSERT_TRUE(derive_result.IsReady());
  auto [derive_status, derive_key_blobs, suggested_action] =
      derive_result.Take();

  // Verify
  ASSERT_THAT(derive_status, NotOk());
  EXPECT_EQ(derive_status->local_legacy_error(),
            user_data_auth::CRYPTOHOME_ERROR_AUTHORIZATION_KEY_FAILED);
}

// Check required field |salt| in TpmBoundToPcrAuthBlockState.
TEST_F(TpmBoundToPcrTest, DeriveFailureMissingSalt) {
  brillo::SecureBlob tpm_key(20, 'C');
  brillo::SecureBlob user_input("foo");
  AuthBlockState auth_state;
  TpmBoundToPcrAuthBlockState state;
  state.scrypt_derived = true;
  state.tpm_key = tpm_key;
  state.extended_tpm_key = tpm_key;
  auth_state.state = std::move(state);

  AuthInput auth_input = {.user_input = user_input};
  DeriveTestFuture derive_result;
  auth_block_->Derive(auth_input, auth_state, derive_result.GetCallback());
  ASSERT_TRUE(derive_result.IsReady());
  auto [derive_status, derive_key_blobs, suggested_action] =
      derive_result.Take();

  // Verify
  ASSERT_THAT(derive_status, NotOk());
  EXPECT_EQ(derive_status->local_legacy_error(),
            user_data_auth::CRYPTOHOME_ERROR_AUTHORIZATION_KEY_FAILED);
}

// Check required field |tpm_key| in TpmBoundToPcrAuthBlockState.
TEST_F(TpmBoundToPcrTest, DeriveFailureMissingTpmKey) {
  brillo::SecureBlob tpm_key(20, 'C');
  brillo::SecureBlob salt(PKCS5_SALT_LEN, 'A');
  brillo::SecureBlob user_input("foo");

  AuthBlockState auth_state;
  TpmBoundToPcrAuthBlockState state;
  state.scrypt_derived = true;
  state.salt = salt;
  state.extended_tpm_key = tpm_key;
  auth_state.state = std::move(state);

  AuthInput auth_input = {.user_input = user_input};
  DeriveTestFuture derive_result;
  auth_block_->Derive(auth_input, auth_state, derive_result.GetCallback());
  ASSERT_TRUE(derive_result.IsReady());
  auto [derive_status, derive_key_blobs, suggested_action] =
      derive_result.Take();

  // Verify
  ASSERT_THAT(derive_status, NotOk());
  EXPECT_EQ(derive_status->local_legacy_error(),
            user_data_auth::CRYPTOHOME_ERROR_AUTHORIZATION_KEY_FAILED);
}

// Check required field |extended_tpm_key| in TpmBoundToPcrAuthBlockState.
TEST_F(TpmBoundToPcrTest, DeriveFailureMissingExtendedTpmKey) {
  brillo::SecureBlob tpm_key(20, 'C');
  brillo::SecureBlob salt(PKCS5_SALT_LEN, 'A');
  brillo::SecureBlob user_input("foo");

  AuthBlockState auth_state;
  TpmBoundToPcrAuthBlockState state;
  state.scrypt_derived = true;
  state.salt = salt;
  state.tpm_key = tpm_key;
  auth_state.state = std::move(state);

  AuthInput auth_input = {.user_input = user_input};
  DeriveTestFuture derive_result;
  auth_block_->Derive(auth_input, auth_state, derive_result.GetCallback());
  ASSERT_TRUE(derive_result.IsReady());
  auto [derive_status, derive_key_blobs, suggested_action] =
      derive_result.Take();

  // Verify
  ASSERT_THAT(derive_status, NotOk());
  EXPECT_EQ(derive_status->local_legacy_error(),
            user_data_auth::CRYPTOHOME_ERROR_AUTHORIZATION_KEY_FAILED);
}
}  // namespace cryptohome
