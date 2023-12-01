// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/auth_blocks/tpm_ecc_auth_block.h"

#include <atomic>
#include <memory>
#include <optional>
#include <utility>
#include <variant>

#include <base/test/bind.h>
#include <base/test/task_environment.h>
#include <base/test/test_future.h>
#include <gtest/gtest.h>
#include <libhwsec-foundation/crypto/aes.h>
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

using CreateTestFuture = TestFuture<CryptohomeStatus,
                                    std::unique_ptr<KeyBlobs>,
                                    std::unique_ptr<AuthBlockState>>;

using DeriveTestFuture = TestFuture<CryptohomeStatus,
                                    std::unique_ptr<KeyBlobs>,
                                    std::optional<AuthBlock::SuggestedAction>>;

constexpr char kUsername[] = "fake_username";

TpmEccAuthBlockState GetDefaultEccAuthBlockState() {
  TpmEccAuthBlockState auth_block__state;
  auth_block__state.salt = brillo::SecureBlob(32, 'A');
  auth_block__state.vkk_iv = brillo::SecureBlob(32, 'B');
  auth_block__state.sealed_hvkkm = brillo::SecureBlob(32, 'C');
  auth_block__state.extended_sealed_hvkkm = brillo::SecureBlob(32, 'D');
  auth_block__state.auth_value_rounds = 5;
  return auth_block__state;
}

void SetupMockHwsec(NiceMock<hwsec::MockCryptohomeFrontend>& hwsec) {
  ON_CALL(hwsec, GetPubkeyHash(_))
      .WillByDefault(ReturnValue(brillo::BlobFromString("public key hash")));
  ON_CALL(hwsec, IsEnabled()).WillByDefault(ReturnValue(true));
  ON_CALL(hwsec, IsReady()).WillByDefault(ReturnValue(true));
}

}  // namespace

class TpmEccAuthBlockTest : public ::testing::Test {
  void SetUp() override {
    SetupMockHwsec(hwsec_);
    auth_block_ =
        std::make_unique<TpmEccAuthBlock>(&hwsec_, &cryptohome_keys_manager_);
  }

 protected:
  NiceMock<hwsec::MockCryptohomeFrontend> hwsec_;
  NiceMock<MockCryptohomeKeysManager> cryptohome_keys_manager_;
  std::unique_ptr<TpmEccAuthBlock> auth_block_;

  base::test::TaskEnvironment task_environment_;
};

// Test the TpmEccAuthBlock::Create works correctly.
TEST_F(TpmEccAuthBlockTest, CreateTest) {
  // Set up inputs to the test.
  brillo::SecureBlob vault_key(20, 'C');

  // Set up the mock expectations.
  brillo::SecureBlob scrypt_derived_key;
  brillo::SecureBlob auth_value(32, 'a');
  EXPECT_CALL(hwsec_, GetManufacturer()).WillOnce(ReturnValue(0x43524f53));
  EXPECT_CALL(hwsec_, GetAuthValue(_, _))
      .Times(Exactly(5))
      .WillOnce(DoAll(SaveArg<1>(&scrypt_derived_key), ReturnValue(auth_value)))
      .WillRepeatedly(ReturnValue(auth_value));
  EXPECT_CALL(hwsec_, SealWithCurrentUser(_, auth_value, _))
      .WillOnce(ReturnValue(brillo::Blob()))
      .WillOnce(ReturnValue(brillo::Blob()));

  AuthInput user_input = {vault_key,
                          /*locked_to_single_user=*/std::nullopt, Username(),
                          ObfuscatedUsername(kUsername),
                          /*reset_secret=*/std::nullopt};

  CreateTestFuture result;
  auth_block_->Create(user_input, result.GetCallback());
  ASSERT_TRUE(result.IsReady());

  auto [status, key_blobs, auth_state] = result.Take();

  EXPECT_TRUE(std::holds_alternative<TpmEccAuthBlockState>(auth_state->state));
  EXPECT_NE(key_blobs->vkk_key, std::nullopt);
  EXPECT_NE(key_blobs->vkk_iv, std::nullopt);
  EXPECT_NE(key_blobs->chaps_iv, std::nullopt);

  auto& tpm_state = std::get<TpmEccAuthBlockState>(auth_state->state);

  EXPECT_TRUE(tpm_state.salt.has_value());
  const brillo::SecureBlob& salt = tpm_state.salt.value();
  brillo::SecureBlob scrypt_derived_key_result(kDefaultPassBlobSize);
  EXPECT_TRUE(
      DeriveSecretsScrypt(vault_key, salt, {&scrypt_derived_key_result}));
  EXPECT_EQ(scrypt_derived_key, scrypt_derived_key_result);
}

// Test the retry function of TpmEccAuthBlock::Create works correctly.
TEST_F(TpmEccAuthBlockTest, CreateRetryTest) {
  // Set up inputs to the test.
  brillo::SecureBlob vault_key(20, 'C');

  // Set up the mock expectations.
  brillo::SecureBlob scrypt_derived_key;
  brillo::SecureBlob auth_value(32, 'a');
  EXPECT_CALL(hwsec_, GetManufacturer())
      .Times(Exactly(2))
      .WillRepeatedly(ReturnValue(0x43524f53));

  // Add some communication errors and retry errors that may come from TPM
  // daemon.
  EXPECT_CALL(hwsec_, GetAuthValue(_, _))
      .Times(Exactly(6))
      .WillOnce(
          ReturnError<TPMError>("ECC scalar out of range",
                                TPMRetryAction::kEllipticCurveScalarOutOfRange))
      .WillOnce(DoAll(SaveArg<1>(&scrypt_derived_key), ReturnValue(auth_value)))
      .WillRepeatedly(ReturnValue(auth_value));

  // Add some communication errors that may come from TPM daemon.
  EXPECT_CALL(hwsec_, SealWithCurrentUser(_, auth_value, _))
      .WillOnce(ReturnValue(brillo::Blob()))
      .WillOnce(ReturnValue(brillo::Blob()));

  AuthInput user_input = {vault_key,
                          /*locked_to_single_user=*/std::nullopt, Username(),
                          ObfuscatedUsername(kUsername),
                          /*reset_secret=*/std::nullopt};

  CreateTestFuture result;
  auth_block_->Create(user_input, result.GetCallback());
  ASSERT_TRUE(result.IsReady());

  auto [status, key_blobs, auth_state] = result.Take();

  EXPECT_TRUE(std::holds_alternative<TpmEccAuthBlockState>(auth_state->state));
  EXPECT_NE(key_blobs->vkk_key, std::nullopt);
  EXPECT_NE(key_blobs->vkk_iv, std::nullopt);
  EXPECT_NE(key_blobs->chaps_iv, std::nullopt);

  auto& tpm_state = std::get<TpmEccAuthBlockState>(auth_state->state);

  EXPECT_TRUE(tpm_state.salt.has_value());
  const brillo::SecureBlob& salt = tpm_state.salt.value();
  brillo::SecureBlob scrypt_derived_key_result(kDefaultPassBlobSize);
  EXPECT_TRUE(
      DeriveSecretsScrypt(vault_key, salt, {&scrypt_derived_key_result}));
  EXPECT_EQ(scrypt_derived_key, scrypt_derived_key_result);
}

// Test the retry function of TpmEccAuthBlock::Create failed as expected.
TEST_F(TpmEccAuthBlockTest, CreateRetryFailTest) {
  // Set up inputs to the test.
  brillo::SecureBlob vault_key(20, 'C');

  // Set up the mock expectations.
  brillo::SecureBlob scrypt_derived_key;
  brillo::SecureBlob auth_value(32, 'a');
  EXPECT_CALL(hwsec_, GetManufacturer())
      .WillRepeatedly(ReturnValue(0x43524f53));
  // The TpmEccAuthBlock shouldn't retry forever if the TPM always returning
  // error.
  EXPECT_CALL(hwsec_, GetAuthValue(_, _))
      .WillRepeatedly(ReturnError<TPMError>("reboot", TPMRetryAction::kReboot));

  AuthInput user_input = {vault_key,
                          /*locked_to_single_user=*/std::nullopt, Username(),
                          ObfuscatedUsername(kUsername),
                          /*reset_secret=*/std::nullopt};
  CreateTestFuture result;
  auth_block_->Create(user_input, result.GetCallback());
  ASSERT_TRUE(result.IsReady());

  EXPECT_EQ(user_data_auth::CRYPTOHOME_ERROR_TPM_NEEDS_REBOOT,
            result.Get<0>()->local_legacy_error());
}

// Test the Create operation fails when there's no user_input provided.
TEST_F(TpmEccAuthBlockTest, CreateFailNoUserInput) {
  // Prepare.
  NiceMock<hwsec::MockCryptohomeFrontend> hwsec;
  NiceMock<MockCryptohomeKeysManager> cryptohome_keys_manager_;
  AuthInput auth_input = {.obfuscated_username = ObfuscatedUsername(kUsername)};

  // Test.
  CreateTestFuture result;
  auth_block_->Create(auth_input, result.GetCallback());
  ASSERT_TRUE(result.IsReady());

  EXPECT_EQ(user_data_auth::CRYPTOHOME_ERROR_AUTHORIZATION_KEY_FAILED,
            result.Get<0>()->local_legacy_error());
}

// Test the Create operation fails when there's no obfuscated_username provided.
TEST_F(TpmEccAuthBlockTest, CreateFailNoObfuscated) {
  // Prepare.
  brillo::SecureBlob user_input(20, 'C');
  NiceMock<hwsec::MockCryptohomeFrontend> hwsec;
  NiceMock<MockCryptohomeKeysManager> cryptohome_keys_manager_;
  AuthInput auth_input = {.user_input = user_input};

  // Test.
  CreateTestFuture result;
  auth_block_->Create(auth_input, result.GetCallback());
  ASSERT_TRUE(result.IsReady());

  EXPECT_EQ(user_data_auth::CRYPTOHOME_ERROR_AUTHORIZATION_KEY_FAILED,
            result.Get<0>()->local_legacy_error());
}

// Test SealToPcr in TpmEccAuthBlock::Create failed as expected.
TEST_F(TpmEccAuthBlockTest, CreateSealToPcrFailTest) {
  // Set up inputs to the test.
  brillo::SecureBlob vault_key(20, 'C');

  // Set up the mock expectations.
  brillo::SecureBlob auth_value(32, 'a');
  EXPECT_CALL(hwsec_, GetManufacturer()).WillOnce(ReturnValue(0x49465800));
  EXPECT_CALL(hwsec_, GetAuthValue(_, _))
      .Times(2)
      .WillRepeatedly(ReturnValue(auth_value));

  EXPECT_CALL(hwsec_, SealWithCurrentUser(_, auth_value, _))
      .WillOnce(ReturnError<TPMError>("fake", TPMRetryAction::kNoRetry));

  AuthInput user_input = {vault_key,
                          /*locked_to_single_user=*/std::nullopt, Username(),
                          ObfuscatedUsername(kUsername),
                          /*reset_secret=*/std::nullopt};
  CreateTestFuture result;
  auth_block_->Create(user_input, result.GetCallback());
  ASSERT_TRUE(result.IsReady());

  EXPECT_EQ(user_data_auth::CRYPTOHOME_ERROR_AUTHORIZATION_KEY_FAILED,
            result.Get<0>()->local_legacy_error());
}

// Test second SealToPcr in TpmEccAuthBlock::Create failed as expected.
TEST_F(TpmEccAuthBlockTest, CreateSecondSealToPcrFailTest) {
  // Set up inputs to the test.
  brillo::SecureBlob vault_key(20, 'C');

  // Set up the mock expectations.
  brillo::SecureBlob auth_value(32, 'a');
  EXPECT_CALL(hwsec_, GetManufacturer()).WillOnce(ReturnValue(0x49465800));
  EXPECT_CALL(hwsec_, GetAuthValue(_, _))
      .Times(2)
      .WillRepeatedly(ReturnValue(auth_value));

  EXPECT_CALL(hwsec_, SealWithCurrentUser(_, auth_value, _))
      .WillOnce(ReturnValue(brillo::Blob()))
      .WillOnce(ReturnError<TPMError>("fake", TPMRetryAction::kNoRetry));

  AuthInput user_input = {vault_key,
                          /*locked_to_single_user=*/std::nullopt,
                          Username(kUsername), ObfuscatedUsername(),
                          /*reset_secret=*/std::nullopt};
  CreateTestFuture result;
  auth_block_->Create(user_input, result.GetCallback());
  ASSERT_TRUE(result.IsReady());

  EXPECT_EQ(user_data_auth::CRYPTOHOME_ERROR_AUTHORIZATION_KEY_FAILED,
            result.Get<0>()->local_legacy_error());
}

// Test GetEccAuthValue in TpmEccAuthBlock::Create failed as expected.
TEST_F(TpmEccAuthBlockTest, CreateEccAuthValueFailTest) {
  // Set up inputs to the test.
  brillo::SecureBlob vault_key(20, 'C');

  // Set up the mock expectations.
  brillo::SecureBlob auth_value(32, 'a');

  EXPECT_CALL(hwsec_, GetManufacturer())
      .WillOnce(ReturnError<TPMError>("fake", TPMRetryAction::kNoRetry));
  EXPECT_CALL(hwsec_, GetAuthValue(_, _))
      .WillOnce(ReturnError<TPMError>("fake", TPMRetryAction::kNoRetry));

  AuthInput user_input = {vault_key,
                          /*locked_to_single_user=*/std::nullopt, Username(),
                          ObfuscatedUsername(kUsername),
                          /*reset_secret=*/std::nullopt};
  CreateTestFuture result;
  auth_block_->Create(user_input, result.GetCallback());
  ASSERT_TRUE(result.IsReady());

  EXPECT_EQ(user_data_auth::CRYPTOHOME_ERROR_AUTHORIZATION_KEY_FAILED,
            result.Get<0>()->local_legacy_error());
}

// Test TpmEccAuthBlock::DeriveTest works correctly.
TEST_F(TpmEccAuthBlockTest, DeriveTest) {
  TpmEccAuthBlockState auth_block__state = GetDefaultEccAuthBlockState();

  brillo::Blob fake_hash(32, 'X');
  auth_block__state.tpm_public_key_hash =
      brillo::SecureBlob(fake_hash.begin(), fake_hash.end());

  // Set up the mock expectations.
  EXPECT_CALL(hwsec_, GetPubkeyHash(_)).WillOnce(ReturnValue(fake_hash));
  EXPECT_CALL(hwsec_, PreloadSealedData(_)).WillOnce(Invoke([&](auto&&) {
    return hwsec::ScopedKey(hwsec::Key{.token = 5566},
                            hwsec_.GetFakeMiddlewareDerivative());
  }));
  EXPECT_CALL(hwsec_, GetAuthValue(_, _))
      .Times(Exactly(5))
      .WillRepeatedly(ReturnValue(brillo::SecureBlob()));

  brillo::SecureBlob fake_hvkkm(32, 'F');
  EXPECT_CALL(hwsec_, UnsealWithCurrentUser(_, _, _))
      .WillOnce(ReturnValue(fake_hvkkm));

  AuthInput auth_input;
  auth_input.user_input = brillo::SecureBlob(20, 'E');
  auth_input.locked_to_single_user = false;
  AuthBlockState auth_state{.state = std::move(auth_block__state)};

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
}

// Test TpmEccAuthBlock::Derive failure when there's no auth_input provided.
TEST_F(TpmEccAuthBlockTest, DeriveFailNoAuthInput) {
  TpmEccAuthBlockState auth_block__state = GetDefaultEccAuthBlockState();
  AuthBlockState auth_state{.state = std::move(auth_block__state)};

  NiceMock<hwsec::MockCryptohomeFrontend> hwsec;
  NiceMock<MockCryptohomeKeysManager> cryptohome_keys_manager_;
  AuthInput auth_input;

  DeriveTestFuture derive_result;
  auth_block_->Derive(auth_input, auth_state, derive_result.GetCallback());
  ASSERT_TRUE(derive_result.IsReady());
  auto [derive_status, derive_key_blobs, suggested_action] =
      derive_result.Take();
  ASSERT_THAT(derive_status, NotOk());
  EXPECT_EQ(user_data_auth::CRYPTOHOME_ERROR_AUTHORIZATION_KEY_FAILED,
            derive_status->local_legacy_error());
}

// Test GetEccAuthValue in TpmEccAuthBlock::Derive failed as expected.
TEST_F(TpmEccAuthBlockTest, DeriveGetEccAuthFailTest) {
  TpmEccAuthBlockState auth_block__state = GetDefaultEccAuthBlockState();

  // Set up the mock expectations.
  EXPECT_CALL(hwsec_, PreloadSealedData(_)).WillOnce(ReturnValue(std::nullopt));

  EXPECT_CALL(hwsec_, GetAuthValue(_, _))
      .WillOnce(ReturnError<TPMError>("fake", TPMRetryAction::kNoRetry));

  AuthInput auth_input;
  auth_input.user_input = brillo::SecureBlob(20, 'E');
  auth_input.locked_to_single_user = false;

  AuthBlockState auth_state{.state = std::move(auth_block__state)};

  DeriveTestFuture derive_result;
  auth_block_->Derive(auth_input, auth_state, derive_result.GetCallback());
  ASSERT_TRUE(derive_result.IsReady());
  auto [derive_status, derive_key_blobs, suggested_action] =
      derive_result.Take();
  ASSERT_THAT(derive_status, NotOk());
  EXPECT_EQ(user_data_auth::CRYPTOHOME_ERROR_AUTHORIZATION_KEY_FAILED,
            derive_status->local_legacy_error());
}

// Test PreloadSealedData in TpmEccAuthBlock::Derive failed as expected.
TEST_F(TpmEccAuthBlockTest, DerivePreloadSealedDataFailTest) {
  TpmEccAuthBlockState auth_block__state = GetDefaultEccAuthBlockState();

  // Set up the mock expectations.

  EXPECT_CALL(hwsec_, PreloadSealedData(_))
      .WillOnce(ReturnError<TPMError>("fake", TPMRetryAction::kNoRetry));

  AuthInput auth_input;
  auth_input.user_input = brillo::SecureBlob(20, 'E');
  auth_input.locked_to_single_user = false;

  AuthBlockState auth_state{.state = std::move(auth_block__state)};
  DeriveTestFuture derive_result;
  auth_block_->Derive(auth_input, auth_state, derive_result.GetCallback());
  ASSERT_TRUE(derive_result.IsReady());
  auto [derive_status, derive_key_blobs, suggested_action] =
      derive_result.Take();
  ASSERT_THAT(derive_status, NotOk());
  EXPECT_EQ(user_data_auth::CRYPTOHOME_ERROR_AUTHORIZATION_KEY_FAILED,
            derive_status->local_legacy_error());
}

// Test GetPublicKeyHash in TpmEccAuthBlock::Derive failed as expected.
TEST_F(TpmEccAuthBlockTest, DeriveGetPublicKeyHashFailTest) {
  TpmEccAuthBlockState auth_block__state = GetDefaultEccAuthBlockState();

  auth_block__state.tpm_public_key_hash = brillo::SecureBlob(32, 'X');

  // Set up the mock expectations.
  EXPECT_CALL(hwsec_, GetPubkeyHash(_))
      .WillOnce(ReturnError<TPMError>("fake", TPMRetryAction::kNoRetry));

  AuthInput auth_input;
  auth_input.user_input = brillo::SecureBlob(20, 'E');
  auth_input.locked_to_single_user = false;

  AuthBlockState auth_state{.state = std::move(auth_block__state)};
  DeriveTestFuture derive_result;
  auth_block_->Derive(auth_input, auth_state, derive_result.GetCallback());
  ASSERT_TRUE(derive_result.IsReady());
  auto [derive_status, derive_key_blobs, suggested_action] =
      derive_result.Take();
  ASSERT_THAT(derive_status, NotOk());
  EXPECT_EQ(user_data_auth::CRYPTOHOME_ERROR_AUTHORIZATION_KEY_FAILED,
            derive_status->local_legacy_error());
}

// Test PublicKeyHashMismatch in TpmEccAuthBlock::Derive failed as expected.
TEST_F(TpmEccAuthBlockTest, DerivePublicKeyHashMismatchTest) {
  TpmEccAuthBlockState auth_block__state = GetDefaultEccAuthBlockState();

  auth_block__state.tpm_public_key_hash = brillo::SecureBlob(32, 'X');

  brillo::Blob fake_hash(32, 'Z');
  // Set up the mock expectations.
  EXPECT_CALL(hwsec_, GetPubkeyHash(_)).WillOnce(ReturnValue(fake_hash));

  AuthInput auth_input;
  auth_input.user_input = brillo::SecureBlob(20, 'E');
  auth_input.locked_to_single_user = false;

  AuthBlockState auth_state{.state = std::move(auth_block__state)};

  DeriveTestFuture derive_result;
  auth_block_->Derive(auth_input, auth_state, derive_result.GetCallback());
  ASSERT_TRUE(derive_result.IsReady());
  auto [derive_status, derive_key_blobs, suggested_action] =
      derive_result.Take();
  ASSERT_THAT(derive_status, NotOk());
  EXPECT_EQ(user_data_auth::CRYPTOHOME_ERROR_VAULT_UNRECOVERABLE,
            derive_status->local_legacy_error());
}

// Test the retry function in TpmEccAuthBlock::Derive failed as expected.
TEST_F(TpmEccAuthBlockTest, DeriveRetryFailTest) {
  TpmEccAuthBlockState auth_block__state = GetDefaultEccAuthBlockState();

  // Set up the mock expectations.
  EXPECT_CALL(hwsec_, PreloadSealedData(_)).WillOnce(ReturnValue(std::nullopt));

  // The TpmEccAuthBlock shouldn't retry forever if the TPM always returning
  // error.
  EXPECT_CALL(hwsec_, GetAuthValue(_, _))
      .WillRepeatedly(ReturnError<TPMError>("reboot", TPMRetryAction::kReboot));

  AuthInput auth_input;
  auth_input.user_input = brillo::SecureBlob(20, 'E');
  auth_input.locked_to_single_user = true;

  AuthBlockState auth_state{.state = std::move(auth_block__state)};

  DeriveTestFuture derive_result;
  auth_block_->Derive(auth_input, auth_state, derive_result.GetCallback());
  ASSERT_TRUE(derive_result.IsReady());
  auto [derive_status, derive_key_blobs, suggested_action] =
      derive_result.Take();
  ASSERT_THAT(derive_status, NotOk());
  EXPECT_EQ(user_data_auth::CRYPTOHOME_ERROR_TPM_NEEDS_REBOOT,
            derive_status->local_legacy_error());
}

// Test Unseal in TpmEccAuthBlock::Derive failed as expected.
TEST_F(TpmEccAuthBlockTest, DeriveUnsealFailTest) {
  TpmEccAuthBlockState auth_block__state = GetDefaultEccAuthBlockState();

  auth_block__state.tpm_public_key_hash = brillo::SecureBlob("public key hash");

  // Set up the mock expectations.
  EXPECT_CALL(hwsec_, PreloadSealedData(_)).WillOnce(ReturnValue(std::nullopt));
  EXPECT_CALL(hwsec_, GetAuthValue(_, _))
      .Times(Exactly(5))
      .WillRepeatedly(ReturnValue(brillo::SecureBlob()));

  brillo::SecureBlob fake_hvkkm(32, 'F');
  EXPECT_CALL(hwsec_, UnsealWithCurrentUser(_, _, _))
      .WillOnce(ReturnError<TPMError>("fake", TPMRetryAction::kNoRetry));

  AuthInput auth_input;
  auth_input.user_input = brillo::SecureBlob(20, 'E');
  auth_input.locked_to_single_user = false;

  AuthBlockState auth_state{.state = std::move(auth_block__state)};

  DeriveTestFuture derive_result;
  auth_block_->Derive(auth_input, auth_state, derive_result.GetCallback());
  ASSERT_TRUE(derive_result.IsReady());
  auto [derive_status, derive_key_blobs, suggested_action] =
      derive_result.Take();
  ASSERT_THAT(derive_status, NotOk());
  EXPECT_EQ(user_data_auth::CRYPTOHOME_ERROR_AUTHORIZATION_KEY_FAILED,
            derive_status->local_legacy_error());
}

// Test CryptohomeKey in TpmEccAuthBlock::Derive failed as expected.
TEST_F(TpmEccAuthBlockTest, DeriveCryptohomeKeyFailTest) {
  TpmEccAuthBlockState auth_block__state = GetDefaultEccAuthBlockState();

  // Set up the mock expectations.

  EXPECT_CALL(*cryptohome_keys_manager_.get_mock_cryptohome_key_loader(),
              HasCryptohomeKey())
      .WillRepeatedly(Return(false));

  AuthInput auth_input;
  auth_input.user_input = brillo::SecureBlob(20, 'E');
  auth_input.locked_to_single_user = true;

  AuthBlockState auth_state{.state = std::move(auth_block__state)};

  DeriveTestFuture derive_result;
  auth_block_->Derive(auth_input, auth_state, derive_result.GetCallback());
  ASSERT_TRUE(derive_result.IsReady());
  auto [derive_status, derive_key_blobs, suggested_action] =
      derive_result.Take();
  ASSERT_THAT(derive_status, NotOk());
  EXPECT_EQ(user_data_auth::CRYPTOHOME_ERROR_TPM_NEEDS_REBOOT,
            derive_status->local_legacy_error());
}
}  // namespace cryptohome
