// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/auth_blocks/tpm_not_bound_to_pcr_auth_block.h"

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
using hwsec_foundation::error::testing::IsOk;
using hwsec_foundation::error::testing::NotOk;
using ::hwsec_foundation::error::testing::ReturnError;
using ::hwsec_foundation::error::testing::ReturnValue;
using ::testing::_;
using ::testing::NiceMock;

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

class TpmNotBoundToPcrTest : public ::testing::Test {
  void SetUp() override {
    SetupMockHwsec(hwsec_);
    auth_block_ = std::make_unique<TpmNotBoundToPcrAuthBlock>(
        &hwsec_, &cryptohome_keys_manager_);
  }

 protected:
  NiceMock<hwsec::MockCryptohomeFrontend> hwsec_;
  NiceMock<MockCryptohomeKeysManager> cryptohome_keys_manager_;
  std::unique_ptr<TpmNotBoundToPcrAuthBlock> auth_block_;

  base::test::TaskEnvironment task_environment_;
};

TEST_F(TpmNotBoundToPcrTest, Success) {
  // Set up inputs to the test.
  brillo::SecureBlob vault_key(20, 'C');
  SerializedVaultKeyset serialized;

  // Set up the mock expectations.
  brillo::Blob encrypt_out(64, 'X');

  EXPECT_CALL(hwsec_, Encrypt(_, _)).WillOnce(ReturnValue(encrypt_out));
  EXPECT_CALL(hwsec_, GetPubkeyHash(_)).WillOnce(ReturnValue(brillo::Blob()));

  AuthInput user_input = {vault_key,
                          /*locked_to_single_user=*/std::nullopt, Username(),
                          ObfuscatedUsername(kUsername),
                          /*reset_secret=*/std::nullopt};

  CreateTestFuture result;
  auth_block_->Create(user_input, result.GetCallback());
  ASSERT_TRUE(result.IsReady());

  auto [status, key_blobs, auth_state] = result.Take();
  ASSERT_THAT(status, IsOk());
  EXPECT_TRUE(std::holds_alternative<TpmNotBoundToPcrAuthBlockState>(
      auth_state->state));
  EXPECT_NE(key_blobs->vkk_key, std::nullopt);
  EXPECT_NE(key_blobs->vkk_iv, std::nullopt);
  EXPECT_NE(key_blobs->chaps_iv, std::nullopt);

  auto& tpm_state = std::get<TpmNotBoundToPcrAuthBlockState>(auth_state->state);

  EXPECT_TRUE(tpm_state.salt.has_value());
  const brillo::SecureBlob& salt = tpm_state.salt.value();
  brillo::SecureBlob aes_skey_result(kDefaultAesKeySize);
  EXPECT_TRUE(DeriveSecretsScrypt(vault_key, salt, {&aes_skey_result}));

  brillo::SecureBlob tpm_key_retult;
  EXPECT_TRUE(hwsec_foundation::ObscureRsaMessage(
      brillo::SecureBlob(encrypt_out.begin(), encrypt_out.end()),
      aes_skey_result, &tpm_key_retult));

  EXPECT_EQ(tpm_state.tpm_key.value(), tpm_key_retult);

  EXPECT_CALL(hwsec_, Decrypt(_, encrypt_out))
      .WillOnce(ReturnValue(brillo::SecureBlob()));

  TpmNotBoundToPcrAuthBlockState state;
  state.scrypt_derived = true;
  state.salt = tpm_state.salt.value();
  state.tpm_key = tpm_key_retult;
  AuthBlockState derive_state;
  derive_state.state = std::move(state);
  AuthInput auth_input = {.user_input = vault_key};
  DeriveTestFuture derive_result;
  auth_block_->Derive(auth_input, derive_state, derive_result.GetCallback());
  ASSERT_TRUE(derive_result.IsReady());
  auto [derive_status, derive_key_blobs, suggested_action] =
      derive_result.Take();
  ASSERT_THAT(derive_status, IsOk());
}

TEST_F(TpmNotBoundToPcrTest, CreateFailTpm) {
  // Set up inputs to the test.
  brillo::SecureBlob vault_key(20, 'C');
  SerializedVaultKeyset serialized;

  ON_CALL(hwsec_, Encrypt(_, _))
      .WillByDefault(ReturnError<TPMError>("fake", TPMRetryAction::kNoRetry));

  AuthInput user_input = {vault_key,
                          /*locked_to_single_user=*/std::nullopt, Username(),
                          ObfuscatedUsername(kUsername),
                          /*reset_secret=*/std::nullopt};
  CreateTestFuture result;
  auth_block_->Create(user_input, result.GetCallback());
  ASSERT_TRUE(result.IsReady());

  ASSERT_THAT(result.Get<0>(), NotOk());
  ASSERT_EQ(result.Get<0>()->local_legacy_error(),
            user_data_auth::CRYPTOHOME_ERROR_AUTHORIZATION_KEY_FAILED);
}

// Test the Create operation fails when there's no user_input provided.
TEST_F(TpmNotBoundToPcrTest, CreateFailNoUserInput) {
  // Prepare.
  AuthInput auth_input;

  // Test.
  CreateTestFuture result;
  auth_block_->Create(auth_input, result.GetCallback());
  ASSERT_TRUE(result.IsReady());

  ASSERT_THAT(result.Get<0>(), NotOk());
  ASSERT_EQ(result.Get<0>()->local_legacy_error(),
            user_data_auth::CRYPTOHOME_ERROR_AUTHORIZATION_KEY_FAILED);
}

// Check required field |salt| in TpmNotBoundToPcrAuthBlockState.
TEST_F(TpmNotBoundToPcrTest, DeriveFailureMissingSalt) {
  // Setup
  brillo::SecureBlob tpm_key(20, 'C');
  AuthBlockState auth_state;
  TpmNotBoundToPcrAuthBlockState state;
  state.scrypt_derived = true;
  state.tpm_key = tpm_key;
  auth_state.state = std::move(state);
  AuthInput auth_input = {};
  // Test
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

// Check required field |tpm_key| in TpmNotBoundToPcrAuthBlockState.
TEST_F(TpmNotBoundToPcrTest, DeriveFailureMissingTpmKey) {
  brillo::SecureBlob salt(PKCS5_SALT_LEN, 'A');
  AuthBlockState auth_state;
  TpmNotBoundToPcrAuthBlockState state;
  state.scrypt_derived = true;
  state.salt = salt;
  auth_state.state = std::move(state);
  AuthInput auth_input = {};
  // Test
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

// Test TpmNotBoundToPcrAuthBlock derive fails when there's no user_input
// provided.
TEST_F(TpmNotBoundToPcrTest, DeriveFailureNoUserInput) {
  brillo::SecureBlob tpm_key(20, 'C');
  brillo::SecureBlob salt(PKCS5_SALT_LEN, 'A');
  AuthBlockState auth_state;
  TpmBoundToPcrAuthBlockState state;
  state.scrypt_derived = true;
  state.salt = salt;
  state.tpm_key = tpm_key;
  state.extended_tpm_key = tpm_key;
  auth_state.state = std::move(state);

  AuthInput auth_input;
  // Test
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

TEST_F(TpmNotBoundToPcrTest, DeriveSuccess) {
  brillo::SecureBlob tpm_key(20, 'A');
  brillo::SecureBlob salt(PKCS5_SALT_LEN, 'B');
  brillo::SecureBlob vault_key(20, 'C');
  brillo::SecureBlob aes_key(kDefaultAesKeySize);
  brillo::SecureBlob encrypt_out(64, 'X');
  ASSERT_TRUE(DeriveSecretsScrypt(vault_key, salt, {&aes_key}));
  ASSERT_TRUE(
      hwsec_foundation::ObscureRsaMessage(encrypt_out, aes_key, &tpm_key));

  brillo::Blob encrypt_out_blob(encrypt_out.begin(), encrypt_out.end());
  EXPECT_CALL(hwsec_, Decrypt(_, encrypt_out_blob))
      .WillOnce(ReturnValue(brillo::SecureBlob()));
  AuthBlockState auth_state;
  TpmNotBoundToPcrAuthBlockState state;
  state.scrypt_derived = true;
  state.salt = salt;
  state.tpm_key = tpm_key;
  auth_state.state = std::move(state);
  AuthInput auth_input = {.user_input = vault_key};

  // Test
  DeriveTestFuture derive_result;
  auth_block_->Derive(auth_input, auth_state, derive_result.GetCallback());
  ASSERT_TRUE(derive_result.IsReady());
  auto [derive_status, derive_key_blobs, suggested_action] =
      derive_result.Take();

  // Verify
  ASSERT_THAT(derive_status, IsOk());
}

}  // namespace cryptohome
