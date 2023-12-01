// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/auth_blocks/challenge_credential_auth_block.h"

#include <stdint.h>

#include <atomic>
#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/functional/bind.h>
#include <base/run_loop.h>
#include <base/test/bind.h>
#include <base/test/task_environment.h>
#include <brillo/secure_blob.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <libhwsec/frontend/cryptohome/mock_frontend.h>
#include <libhwsec-foundation/crypto/libscrypt_compat.h>
#include <libhwsec-foundation/crypto/sha.h>
#include <libhwsec-foundation/error/testing_helper.h>
#include <libhwsec-foundation/crypto/secure_blob_util.h>

#include "cryptohome/challenge_credentials/challenge_credentials_helper_impl.h"
#include "cryptohome/challenge_credentials/challenge_credentials_test_utils.h"
#include "cryptohome/challenge_credentials/mock_challenge_credentials_helper.h"
#include "cryptohome/challenge_credentials/signature_sealing_test_utils.h"
#include "cryptohome/error/cryptohome_crypto_error.h"
#include "cryptohome/error/utilities.h"
#include "cryptohome/flatbuffer_schemas/auth_block_state.h"
#include "cryptohome/key_objects.h"
#include "cryptohome/mock_key_challenge_service.h"
#include "cryptohome/proto_bindings/key.pb.h"
#include "cryptohome/proto_bindings/rpc.pb.h"
#include "cryptohome/username.h"

using cryptohome::error::CryptohomeCryptoError;
using cryptohome::error::CryptohomeTPMError;
using cryptohome::error::ErrorActionSet;
using cryptohome::error::PossibleAction;
using cryptohome::error::PossibleActionsInclude;
using cryptohome::error::PrimaryAction;
using cryptohome::error::PrimaryActionIs;
using hwsec::TPMRetryAction;
using hwsec_foundation::error::testing::IsOk;
using hwsec_foundation::error::testing::ReturnValue;
using hwsec_foundation::status::MakeStatus;
using hwsec_foundation::status::OkStatus;
using hwsec_foundation::status::StatusChain;

using HwsecAlgorithm = hwsec::CryptohomeFrontend::SignatureSealingAlgorithm;

using testing::_;
using testing::AtLeast;
using testing::NiceMock;
using testing::Return;

namespace cryptohome {

namespace {

MATCHER_P(ChallengeAlgorithmIs, algorithm, "") {
  return arg.signature_request_data().signature_algorithm() == algorithm;
}

void VerifyCreateCallback(base::RunLoop* run_loop,
                          AuthInput* auth_input,
                          CryptohomeStatus error,
                          std::unique_ptr<KeyBlobs> blobs,
                          std::unique_ptr<AuthBlockState> auth_state) {
  ASSERT_TRUE(error.ok());

  // Because the salt is generated randomly inside the auth block, this
  // test cannot check the exact values returned. The salt() could be
  // passed through in some test specific harness, but the underlying
  // scrypt code is tested in so many other places, it's unnecessary.
  ASSERT_TRUE(std::holds_alternative<ChallengeCredentialAuthBlockState>(
      auth_state->state));

  auto& tpm_state =
      std::get<ChallengeCredentialAuthBlockState>(auth_state->state);

  EXPECT_FALSE(blobs->vkk_key->empty());
  EXPECT_TRUE(tpm_state.scrypt_state.salt.has_value());
  EXPECT_FALSE(tpm_state.scrypt_state.salt->empty());

  EXPECT_FALSE(blobs->scrypt_chaps_key->empty());
  EXPECT_TRUE(tpm_state.scrypt_state.chaps_salt.has_value());
  EXPECT_FALSE(tpm_state.scrypt_state.chaps_salt->empty());

  EXPECT_FALSE(blobs->scrypt_reset_seed_key->empty());
  EXPECT_TRUE(tpm_state.scrypt_state.reset_seed_salt.has_value());
  EXPECT_FALSE(tpm_state.scrypt_state.reset_seed_salt->empty());

  ASSERT_TRUE(tpm_state.keyset_challenge_info.has_value());
  EXPECT_EQ(
      tpm_state.keyset_challenge_info.value().public_key_spki_der,
      auth_input->challenge_credential_auth_input.value().public_key_spki_der);
  EXPECT_EQ(tpm_state.keyset_challenge_info.value().salt_signature_algorithm,
            auth_input->challenge_credential_auth_input.value()
                .challenge_signature_algorithms[0]);
  run_loop->Quit();
}
}  // namespace

class ChallengeCredentialAuthBlockTest : public ::testing::Test {
 public:
  ChallengeCredentialAuthBlockTest() = default;
  ChallengeCredentialAuthBlockTest(const ChallengeCredentialAuthBlockTest&) =
      delete;
  ChallengeCredentialAuthBlockTest& operator=(
      const ChallengeCredentialAuthBlockTest&) = delete;

  ~ChallengeCredentialAuthBlockTest() override = default;

  void SetUp() override {
    auto mock_key_challenge_service =
        std::make_unique<NiceMock<MockKeyChallengeService>>();
    auth_block_ = std::make_unique<ChallengeCredentialAuthBlock>(
        &challenge_credentials_helper_, std::move(mock_key_challenge_service),
        kFakeAccountId);
  }

 protected:
  base::test::TaskEnvironment task_environment_;

  NiceMock<MockChallengeCredentialsHelper> challenge_credentials_helper_;
  const Username kFakeAccountId{"account_id"};
  std::unique_ptr<ChallengeCredentialAuthBlock> auth_block_;

  const error::CryptohomeError::ErrorLocationPair kErrorLocationPlaceholder =
      error::CryptohomeError::ErrorLocationPair(
          static_cast<::cryptohome::error::CryptohomeError::ErrorLocation>(1),
          "Testing1");
};

// The ChallengeCredentialAuthBlock::Create should work correctly.
TEST_F(ChallengeCredentialAuthBlockTest, Create) {
  AuthInput auth_input{
      .obfuscated_username = ObfuscatedUsername("obfuscated_username"),
      .challenge_credential_auth_input =
          ChallengeCredentialAuthInput{
              .public_key_spki_der =
                  brillo::BlobFromString("public_key_spki_der"),
              .challenge_signature_algorithms =
                  {structure::ChallengeSignatureAlgorithm::
                       kRsassaPkcs1V15Sha256},
          },
  };

  EXPECT_CALL(challenge_credentials_helper_,
              GenerateNew(kFakeAccountId, _, _, _, _))
      .WillOnce([&](auto&&, auto public_key_info, auto&&, auto&&,
                    auto&& callback) {
        auto info = std::make_unique<structure::SignatureChallengeInfo>();
        info->public_key_spki_der = public_key_info.public_key_spki_der;
        info->salt_signature_algorithm = public_key_info.signature_algorithm[0];
        auto passkey = std::make_unique<brillo::SecureBlob>("passkey");
        std::move(callback).Run(
            ChallengeCredentialsHelper::GenerateNewOrDecryptResult(
                std::move(info), std::move(passkey)));
      });

  base::RunLoop run_loop;
  AuthBlock::CreateCallback create_callback =
      base::BindOnce(VerifyCreateCallback, &run_loop, &auth_input);

  auth_block_->Create(auth_input, std::move(create_callback));

  run_loop.Run();
}

// The ChallengeCredentialAuthBlock::Create should fail when the challenge
// service failed.
TEST_F(ChallengeCredentialAuthBlockTest, CreateCredentialsFailed) {
  EXPECT_CALL(challenge_credentials_helper_,
              GenerateNew(kFakeAccountId, _, _, _, _))
      .WillOnce(
          [&](auto&&, auto public_key_info, auto&&, auto&&, auto&& callback) {
            std::move(callback).Run(MakeStatus<CryptohomeCryptoError>(
                kErrorLocationPlaceholder,
                ErrorActionSet(PrimaryAction::kIncorrectAuth),
                CryptoError::CE_OTHER_CRYPTO));
          });

  base::RunLoop run_loop;
  AuthBlock::CreateCallback create_callback = base::BindLambdaForTesting(
      [&](CryptohomeStatus error, std::unique_ptr<KeyBlobs> blobs,
          std::unique_ptr<AuthBlockState> auth_state) {
        EXPECT_TRUE(
            PrimaryActionIs(error.err_status(), PrimaryAction::kIncorrectAuth));
        run_loop.Quit();
      });

  AuthInput auth_input{
      .obfuscated_username = ObfuscatedUsername("obfuscated_username"),
      .challenge_credential_auth_input =
          ChallengeCredentialAuthInput{
              .public_key_spki_der =
                  brillo::BlobFromString("public_key_spki_der"),
              .challenge_signature_algorithms =
                  {structure::ChallengeSignatureAlgorithm::
                       kRsassaPkcs1V15Sha256},
          },
  };

  auth_block_->Create(auth_input, std::move(create_callback));

  run_loop.Run();
}

// The ChallengeCredentialAuthBlock::Create should fail when called
// multiple create.
TEST_F(ChallengeCredentialAuthBlockTest, MutipleCreateFailed) {
  AuthInput auth_input{
      .obfuscated_username = ObfuscatedUsername("obfuscated_username"),
      .challenge_credential_auth_input =
          ChallengeCredentialAuthInput{
              .public_key_spki_der =
                  brillo::BlobFromString("public_key_spki_der"),
              .challenge_signature_algorithms =
                  {structure::ChallengeSignatureAlgorithm::
                       kRsassaPkcs1V15Sha256},
          },
  };

  EXPECT_CALL(challenge_credentials_helper_,
              GenerateNew(kFakeAccountId, _, _, _, _))
      .WillOnce([&](auto&&, auto public_key_info, auto&&, auto&&,
                    auto&& callback) {
        auto info = std::make_unique<structure::SignatureChallengeInfo>();
        info->public_key_spki_der = public_key_info.public_key_spki_der;
        info->salt_signature_algorithm = public_key_info.signature_algorithm[0];
        auto passkey = std::make_unique<brillo::SecureBlob>("passkey");
        std::move(callback).Run(
            ChallengeCredentialsHelper::GenerateNewOrDecryptResult(
                std::move(info), std::move(passkey)));
      });

  base::RunLoop run_loop;
  AuthBlock::CreateCallback create_callback =
      base::BindOnce(VerifyCreateCallback, &run_loop, &auth_input);

  auth_block_->Create(auth_input, std::move(create_callback));

  run_loop.Run();

  base::RunLoop run_loop2;
  AuthBlock::CreateCallback create_callback2 = base::BindLambdaForTesting(
      [&](CryptohomeStatus error, std::unique_ptr<KeyBlobs> blobs,
          std::unique_ptr<AuthBlockState> auth_state) {
        // The second create would failed.
        EXPECT_TRUE(PossibleActionsInclude(
            error.err_status(), PossibleAction::kDevCheckUnexpectedState));
        run_loop2.Quit();
      });

  auth_block_->Create(auth_input, std::move(create_callback2));

  run_loop2.Run();
}

// The ChallengeCredentialAuthBlock::Create should fail when missing
// obfuscated username.
TEST_F(ChallengeCredentialAuthBlockTest, CreateMissingObfuscatedUsername) {
  base::RunLoop run_loop;
  AuthBlock::CreateCallback create_callback = base::BindLambdaForTesting(
      [&](CryptohomeStatus error, std::unique_ptr<KeyBlobs> blobs,
          std::unique_ptr<AuthBlockState> auth_state) {
        EXPECT_TRUE(PossibleActionsInclude(
            error.err_status(), PossibleAction::kDevCheckUnexpectedState));
        run_loop.Quit();
      });

  AuthInput auth_input{
      .challenge_credential_auth_input =
          ChallengeCredentialAuthInput{
              .public_key_spki_der =
                  brillo::BlobFromString("public_key_spki_der"),
              .challenge_signature_algorithms =
                  {structure::ChallengeSignatureAlgorithm::
                       kRsassaPkcs1V15Sha256},
          },
  };
  auth_block_->Create(auth_input, std::move(create_callback));
  run_loop.Run();
}

// The ChallengeCredentialAuthBlock::Create should fail when missing auth
// input.
TEST_F(ChallengeCredentialAuthBlockTest,
       CreateMissingChallengeCredentialAuthInput) {
  base::RunLoop run_loop;
  AuthBlock::CreateCallback create_callback = base::BindLambdaForTesting(
      [&](CryptohomeStatus error, std::unique_ptr<KeyBlobs> blobs,
          std::unique_ptr<AuthBlockState> auth_state) {
        EXPECT_TRUE(PossibleActionsInclude(
            error.err_status(), PossibleAction::kDevCheckUnexpectedState));
        run_loop.Quit();
      });

  AuthInput auth_input{
      .obfuscated_username = ObfuscatedUsername("obfuscated_username"),
  };
  auth_block_->Create(auth_input, std::move(create_callback));
  run_loop.Run();
}

// The ChallengeCredentialAuthBlock::Create should fail when missing
// algorithm.
TEST_F(ChallengeCredentialAuthBlockTest, CreateMissingAlgorithm) {
  base::RunLoop run_loop;
  AuthBlock::CreateCallback create_callback = base::BindLambdaForTesting(
      [&](CryptohomeStatus error, std::unique_ptr<KeyBlobs> blobs,
          std::unique_ptr<AuthBlockState> auth_state) {
        EXPECT_TRUE(PossibleActionsInclude(
            error.err_status(), PossibleAction::kDevCheckUnexpectedState));
        run_loop.Quit();
      });

  AuthInput auth_input{
      .obfuscated_username = ObfuscatedUsername("obfuscated_username"),
      .challenge_credential_auth_input =
          ChallengeCredentialAuthInput{
              .public_key_spki_der =
                  brillo::BlobFromString("public_key_spki_der"),
          },
  };
  auth_block_->Create(auth_input, std::move(create_callback));

  run_loop.Run();
}

// The ChallengeCredentialAuthBlock::Derive should work correctly.
TEST_F(ChallengeCredentialAuthBlockTest, Derive) {
  AuthBlockState auth_state{
      .state =
          ChallengeCredentialAuthBlockState{
              .scrypt_state =
                  ScryptAuthBlockState{
                      .salt = brillo::SecureBlob("salt"),
                      .chaps_salt = brillo::SecureBlob("chaps_salt"),
                      .reset_seed_salt = brillo::SecureBlob("reset_seed_salt"),
                      .work_factor =
                          hwsec_foundation::kDefaultScryptParams.n_factor,
                      .block_size =
                          hwsec_foundation::kDefaultScryptParams.r_factor,
                      .parallel_factor =
                          hwsec_foundation::kDefaultScryptParams.p_factor,
                  },
              .keyset_challenge_info =
                  structure::SignatureChallengeInfo{
                      .public_key_spki_der =
                          brillo::BlobFromString("public_key_spki_der"),
                      .salt_signature_algorithm = structure::
                          ChallengeSignatureAlgorithm::kRsassaPkcs1V15Sha256,
                  },
          },
  };

  brillo::SecureBlob scrypt_passkey = {
      0x31, 0x35, 0x64, 0x64, 0x38, 0x38, 0x66, 0x36, 0x35, 0x31, 0x30,
      0x65, 0x30, 0x64, 0x35, 0x64, 0x35, 0x35, 0x36, 0x35, 0x35, 0x35,
      0x38, 0x36, 0x31, 0x32, 0x62, 0x37, 0x39, 0x36, 0x30, 0x65};

  brillo::SecureBlob derived_key = {
      0x67, 0xeb, 0xcd, 0x84, 0x49, 0x5e, 0xa2, 0xf3, 0xb1, 0xe6, 0xe7,
      0x5b, 0x13, 0xb9, 0x16, 0x2f, 0x5a, 0x39, 0xc8, 0xfe, 0x6a, 0x60,
      0xd4, 0x7a, 0xd8, 0x2b, 0x44, 0xc4, 0x45, 0x53, 0x1a, 0x85, 0x4a,
      0x97, 0x9f, 0x2d, 0x06, 0xf5, 0xd0, 0xd3, 0xa6, 0xe7, 0xac, 0x9b,
      0x02, 0xaf, 0x3c, 0x08, 0xce, 0x43, 0x46, 0x32, 0x6d, 0xd7, 0x2b,
      0xe9, 0xdf, 0x8b, 0x38, 0x0e, 0x60, 0x3d, 0x64, 0x12};

  brillo::SecureBlob derived_chaps_key = {
      0x7a, 0xc3, 0x70, 0x54, 0x4d, 0x04, 0x4c, 0xa6, 0x48, 0xcc, 0x4d,
      0xcf, 0x94, 0x13, 0xa7, 0x97, 0x28, 0x80, 0x9f, 0xec, 0xa0, 0xaf,
      0x2d, 0x3c, 0xef, 0xf0, 0x34, 0xd6, 0xbd, 0x02, 0x45, 0x1e, 0x3d,
      0xe1, 0xc2, 0x42, 0xd8, 0x40, 0x75, 0x85, 0x15, 0x87, 0xaf, 0x29,
      0x2c, 0x44, 0xbc, 0x77, 0x86, 0x87, 0xd2, 0x0b, 0xea, 0xba, 0x51,
      0x8d, 0xc4, 0x3a, 0xf8, 0x05, 0xb6, 0x20, 0x5d, 0xfd};

  brillo::SecureBlob derived_reset_seed_key = {
      0xd4, 0x78, 0x3b, 0xfb, 0x81, 0xfe, 0xb3, 0x84, 0x23, 0x06, 0x18,
      0xc0, 0x30, 0x1c, 0x40, 0xcb, 0x71, 0x04, 0x46, 0xeb, 0x91, 0x9e,
      0xa2, 0x7b, 0xd7, 0xcf, 0xcb, 0x5e, 0x67, 0xd3, 0x5a, 0x07, 0x7c,
      0x5f, 0xc2, 0x92, 0x3f, 0x98, 0x32, 0x75, 0x80, 0xe8, 0xed, 0xda,
      0x2c, 0x1e, 0x41, 0x1c, 0xd2, 0x07, 0x48, 0x39, 0x2a, 0xfd, 0x6c,
      0xd6, 0x6f, 0x1c, 0x8e, 0xca, 0x00, 0x79, 0x91, 0x52};

  AuthInput auth_input{
      .locked_to_single_user = true,
      .challenge_credential_auth_input =
          ChallengeCredentialAuthInput{
              .challenge_signature_algorithms =
                  {structure::ChallengeSignatureAlgorithm::
                       kRsassaPkcs1V15Sha256},
          },
  };

  EXPECT_CALL(challenge_credentials_helper_,
              Decrypt(kFakeAccountId, _, _, _, _))
      .WillOnce([&](auto&&, auto&&, auto&&, auto&&, auto&& callback) {
        auto passkey = std::make_unique<brillo::SecureBlob>(scrypt_passkey);
        std::move(callback).Run(
            ChallengeCredentialsHelper::GenerateNewOrDecryptResult(
                nullptr, std::move(passkey)));
      });

  base::RunLoop run_loop;
  AuthBlock::DeriveCallback derive_callback = base::BindLambdaForTesting(
      [&](CryptohomeStatus error, std::unique_ptr<KeyBlobs> blobs,
          std::optional<AuthBlock::SuggestedAction> suggested_action) {
        ASSERT_TRUE(error.ok());
        EXPECT_EQ(derived_key, blobs->vkk_key);
        EXPECT_EQ(derived_chaps_key, blobs->scrypt_chaps_key);
        EXPECT_EQ(derived_reset_seed_key, blobs->scrypt_reset_seed_key);
        EXPECT_EQ(suggested_action, std::nullopt);
        run_loop.Quit();
      });

  auth_block_->Derive(auth_input, auth_state, std::move(derive_callback));

  run_loop.Run();
}

// The ChallengeCredentialAuthBlock::Derive should fail when the key
// challenge service failed.
TEST_F(ChallengeCredentialAuthBlockTest, DeriveFailed) {
  AuthBlockState auth_state{
      .state =
          ChallengeCredentialAuthBlockState{
              .keyset_challenge_info =
                  structure::SignatureChallengeInfo{
                      .public_key_spki_der =
                          brillo::BlobFromString("public_key_spki_der"),
                      .salt_signature_algorithm = structure::
                          ChallengeSignatureAlgorithm::kRsassaPkcs1V15Sha256,
                  },
          },
  };

  AuthInput auth_input{
      .challenge_credential_auth_input =
          ChallengeCredentialAuthInput{
              .challenge_signature_algorithms =
                  {structure::ChallengeSignatureAlgorithm::
                       kRsassaPkcs1V15Sha256},
          },
  };

  EXPECT_CALL(challenge_credentials_helper_,
              Decrypt(kFakeAccountId, _, _, _, _))
      .WillOnce([&](auto&&, auto&&, auto&&, auto&&, auto&& callback) {
        std::move(callback).Run(MakeStatus<CryptohomeCryptoError>(
            kErrorLocationPlaceholder,
            ErrorActionSet(PrimaryAction::kIncorrectAuth),
            CryptoError::CE_OTHER_CRYPTO));
      });

  base::RunLoop run_loop;
  AuthBlock::DeriveCallback derive_callback = base::BindLambdaForTesting(
      [&](CryptohomeStatus error, std::unique_ptr<KeyBlobs> blobs,
          std::optional<AuthBlock::SuggestedAction> suggested_action) {
        EXPECT_TRUE(
            PrimaryActionIs(error.err_status(), PrimaryAction::kIncorrectAuth));
        run_loop.Quit();
      });

  auth_block_->Derive(auth_input, auth_state, std::move(derive_callback));

  run_loop.Run();
}

// The ChallengeCredentialAuthBlock::Derive should fail when missing
// algorithms.
TEST_F(ChallengeCredentialAuthBlockTest, DeriveMissingAlgorithms) {
  base::RunLoop run_loop;
  AuthBlock::DeriveCallback derive_callback = base::BindLambdaForTesting(
      [&](CryptohomeStatus error, std::unique_ptr<KeyBlobs> blobs,
          std::optional<AuthBlock::SuggestedAction> suggested_action) {
        EXPECT_TRUE(PossibleActionsInclude(
            error.err_status(), PossibleAction::kDevCheckUnexpectedState));
        run_loop.Quit();
      });

  AuthBlockState auth_state{};
  AuthInput auth_input{
      .locked_to_single_user = false,
  };
  auth_block_->Derive(auth_input, auth_state, std::move(derive_callback));
  run_loop.Run();
}

// The ChallengeCredentialAuthBlock::Derive should fail when missing state.
TEST_F(ChallengeCredentialAuthBlockTest, DeriveNoState) {
  base::RunLoop run_loop;
  AuthBlock::DeriveCallback derive_callback = base::BindLambdaForTesting(
      [&](CryptohomeStatus error, std::unique_ptr<KeyBlobs> blobs,
          std::optional<AuthBlock::SuggestedAction> suggested_action) {
        EXPECT_TRUE(PossibleActionsInclude(
            error.err_status(), PossibleAction::kDevCheckUnexpectedState));
        run_loop.Quit();
      });

  AuthBlockState auth_state{};
  AuthInput auth_input{
      .locked_to_single_user = false,
      .challenge_credential_auth_input =
          ChallengeCredentialAuthInput{
              .challenge_signature_algorithms =
                  {structure::ChallengeSignatureAlgorithm::
                       kRsassaPkcs1V15Sha256},
          },
  };
  auth_block_->Derive(auth_input, auth_state, std::move(derive_callback));
  run_loop.Run();
}

// The ChallengeCredentialAuthBlock::Derive should fail when missing keyset
// info.
TEST_F(ChallengeCredentialAuthBlockTest, DeriveNoKeysetInfo) {
  base::RunLoop run_loop;
  AuthBlock::DeriveCallback derive_callback = base::BindLambdaForTesting(
      [&](CryptohomeStatus error, std::unique_ptr<KeyBlobs> blobs,
          std::optional<AuthBlock::SuggestedAction> suggested_action) {
        EXPECT_TRUE(PossibleActionsInclude(
            error.err_status(), PossibleAction::kDevCheckUnexpectedState));
        run_loop.Quit();
      });

  AuthBlockState auth_state{
      .state = ChallengeCredentialAuthBlockState{},
  };
  AuthInput auth_input{
      .locked_to_single_user = false,
      .challenge_credential_auth_input =
          ChallengeCredentialAuthInput{
              .challenge_signature_algorithms =
                  {structure::ChallengeSignatureAlgorithm::
                       kRsassaPkcs1V15Sha256},
          },
  };
  auth_block_->Derive(auth_input, auth_state, std::move(derive_callback));

  run_loop.Run();
}

// The ChallengeCredentialAuthBlock::Derive should fail when missing scrypt
// state.
TEST_F(ChallengeCredentialAuthBlockTest, DeriveNoScryptState) {
  base::RunLoop run_loop;
  AuthBlock::DeriveCallback derive_callback = base::BindLambdaForTesting(
      [&](CryptohomeStatus error, std::unique_ptr<KeyBlobs> blobs,
          std::optional<AuthBlock::SuggestedAction> suggested_action) {
        EXPECT_TRUE(
            PossibleActionsInclude(error.err_status(), PossibleAction::kAuth));
        run_loop.Quit();
      });

  EXPECT_CALL(challenge_credentials_helper_,
              Decrypt(kFakeAccountId, _, _, _, _))
      .WillOnce([&](auto&&, auto&&, auto&&, auto&&, auto&& callback) {
        auto passkey = std::make_unique<brillo::SecureBlob>("passkey");
        std::move(callback).Run(
            ChallengeCredentialsHelper::GenerateNewOrDecryptResult(
                nullptr, std::move(passkey)));
      });

  AuthBlockState auth_state{
      .state =
          ChallengeCredentialAuthBlockState{
              .keyset_challenge_info =
                  structure::SignatureChallengeInfo{
                      .public_key_spki_der =
                          brillo::BlobFromString("public_key_spki_der"),
                      .salt_signature_algorithm = structure::
                          ChallengeSignatureAlgorithm::kRsassaPkcs1V15Sha256,
                  },
          },
  };
  AuthInput auth_input{
      .challenge_credential_auth_input =
          ChallengeCredentialAuthInput{
              .challenge_signature_algorithms =
                  {structure::ChallengeSignatureAlgorithm::
                       kRsassaPkcs1V15Sha256},
          },
  };
  auth_block_->Derive(auth_input, auth_state, std::move(derive_callback));

  run_loop.Run();
}

// Test fixture that sets up a real `ChallengeCredentialsHelperImpl` and mocks
// at the `SignatureSealingBackend` level, hence achieving more extensive test
// coverage than the fixture above.
class ChallengeCredentialAuthBlockFullTest : public ::testing::Test {
 protected:
  const ObfuscatedUsername kObfuscatedUsername{"obfuscated_username"};
  const brillo::Blob kPublicKeySpkiDer =
      brillo::BlobFromString("public_key_spki_der");

  ChallengeCredentialAuthBlockFullTest() {
    ON_CALL(hwsec_, IsReady()).WillByDefault(ReturnValue(true));
    ON_CALL(hwsec_, IsSrkRocaVulnerable()).WillByDefault(ReturnValue(false));

    EXPECT_CALL(hwsec_, GetRandomBlob(_)).WillRepeatedly([](size_t length) {
      return brillo::Blob(length, 0);
    });

    challenge_credentials_helper_ =
        std::make_unique<ChallengeCredentialsHelperImpl>(&hwsec_);
  }

  ~ChallengeCredentialAuthBlockFullTest() = default;

  void CreateAuthBlock() {
    auto owned_key_challenge_service =
        std::make_unique<MockKeyChallengeService>();
    key_challenge_service_ = owned_key_challenge_service.get();
    auth_block_ = std::make_unique<ChallengeCredentialAuthBlock>(
        challenge_credentials_helper_.get(),
        std::move(owned_key_challenge_service), kFakeAccountId);
  }

  void BackendWillSeal(const std::vector<HwsecAlgorithm>& key_algorithms) {
    EXPECT_CALL(hwsec_, GetRandomSecureBlob(_))
        .WillOnce(ReturnValue(kTpmProtectedSecret));

    SignatureSealedCreationMocker mocker(&hwsec_);
    mocker.set_public_key_spki_der(kPublicKeySpkiDer);
    mocker.set_key_algorithms(key_algorithms);
    mocker.set_obfuscated_username(kObfuscatedUsername);
    mocker.set_secret_value(kTpmProtectedSecret);
    mocker.SetUpSuccessfulMock();
  }

  void BackendWillUnseal(const std::vector<HwsecAlgorithm>& key_algorithms,
                         HwsecAlgorithm unsealing_algorithm) {
    SignatureSealedUnsealingMocker mocker(&hwsec_);
    mocker.set_public_key_spki_der(kPublicKeySpkiDer);
    mocker.set_key_algorithms(key_algorithms);
    mocker.set_chosen_algorithm(unsealing_algorithm);
    mocker.set_challenge_value(brillo::BlobFromString("challenge"));
    mocker.set_challenge_signature(kChallengeResponse);
    mocker.set_secret_value(kTpmProtectedSecret);
    mocker.SetUpSuccessfulMock();
  }

  void ChallengesWillRespond(ChallengeSignatureAlgorithm algorithm) {
    DCHECK(key_challenge_service_);
    EXPECT_CALL(*key_challenge_service_,
                ChallengeKeyMovable(_, ChallengeAlgorithmIs(algorithm), _))
        .Times(AtLeast(1))
        .WillRepeatedly([&](const AccountIdentifier& account_id,
                            const KeyChallengeRequest& request,
                            KeyChallengeService::ResponseCallback* callback) {
          auto response = std::make_unique<KeyChallengeResponse>();
          response->mutable_signature_response_data()->set_signature(
              brillo::BlobToString(kChallengeResponse));
          std::move(*callback).Run(std::move(response));
        });
  }

  CryptohomeStatus RunCreate(
      const AuthInput& auth_input,
      std::unique_ptr<KeyBlobs>& out_key_blobs,
      std::unique_ptr<AuthBlockState>& out_auth_block_state) {
    DCHECK(auth_block_);
    base::RunLoop run_loop;
    CryptohomeStatus got_error;
    auth_block_->Create(
        auth_input,
        base::BindLambdaForTesting(
            [&](CryptohomeStatus error, std::unique_ptr<KeyBlobs> key_blobs,
                std::unique_ptr<AuthBlockState> auth_block_state) {
              got_error = std::move(error);
              out_key_blobs = std::move(key_blobs);
              out_auth_block_state = std::move(auth_block_state);
              run_loop.Quit();
            }));
    run_loop.Run();
    return got_error;
  }

  CryptohomeStatus RunDerive(const AuthInput& auth_input,
                             const AuthBlockState& auth_block_state,
                             std::unique_ptr<KeyBlobs>& out_key_blobs) {
    DCHECK(auth_block_);
    base::RunLoop run_loop;
    CryptohomeStatus got_error;
    auth_block_->Derive(
        auth_input, auth_block_state,
        base::BindLambdaForTesting(
            [&](CryptohomeStatus error, std::unique_ptr<KeyBlobs> key_blobs,
                std::optional<AuthBlock::SuggestedAction> suggested_action) {
              got_error = std::move(error);
              out_key_blobs = std::move(key_blobs);
              run_loop.Quit();
            }));
    run_loop.Run();
    return got_error;
  }

 private:
  const Username kFakeAccountId{"account_id"};
  const brillo::SecureBlob kTpmProtectedSecret =
      brillo::SecureBlob("tpm_protected_secret");
  const brillo::Blob kChallengeResponse = brillo::BlobFromString("signature");
  const brillo::Blob kScryptPlaintext = brillo::BlobFromString("plaintext");

  base::test::TaskEnvironment task_environment_;
  NiceMock<hwsec::MockCryptohomeFrontend> hwsec_;
  std::unique_ptr<ChallengeCredentialsHelperImpl> challenge_credentials_helper_;
  std::unique_ptr<ChallengeCredentialAuthBlock> auth_block_;
  // Unowned - pointing to the object owned by `*auth_block_`.
  MockKeyChallengeService* key_challenge_service_ = nullptr;
};

// Verifies that Derive succeeds on the output of Create.
TEST_F(ChallengeCredentialAuthBlockFullTest, DeriveCreated) {
  constexpr auto kHwsecAlgorithm = HwsecAlgorithm::kRsassaPkcs1V15Sha256;
  constexpr auto kAlgorithm =
      structure::ChallengeSignatureAlgorithm::kRsassaPkcs1V15Sha256;
  constexpr auto kChallengeAlgorithm = CHALLENGE_RSASSA_PKCS1_V1_5_SHA256;
  const AuthInput kAuthInput{
      .obfuscated_username = kObfuscatedUsername,
      .challenge_credential_auth_input =
          ChallengeCredentialAuthInput{
              .public_key_spki_der = kPublicKeySpkiDer,
              .challenge_signature_algorithms = {kAlgorithm},
          },
  };

  // Setup: create an auth block state.
  CreateAuthBlock();
  BackendWillSeal({kHwsecAlgorithm});
  ChallengesWillRespond(kChallengeAlgorithm);
  std::unique_ptr<KeyBlobs> created_key_blobs;
  std::unique_ptr<AuthBlockState> auth_block_state;
  ASSERT_THAT(RunCreate(kAuthInput, created_key_blobs, auth_block_state),
              IsOk());
  ASSERT_TRUE(created_key_blobs);
  ASSERT_TRUE(auth_block_state);
  // Backfill the scrypt wrapped_keyset, to mimic how the caller uses
  // scrypt-based auth blocks for derivation.

  // Test: run the derivation.
  CreateAuthBlock();
  BackendWillUnseal({kHwsecAlgorithm}, kHwsecAlgorithm);
  ChallengesWillRespond(kChallengeAlgorithm);
  std::unique_ptr<KeyBlobs> derived_key_blobs;
  ASSERT_THAT(RunDerive(kAuthInput, *auth_block_state, derived_key_blobs),
              IsOk());
  ASSERT_TRUE(derived_key_blobs);

  // Assert: verify the derivation gives the same secret as the creation.
  ASSERT_TRUE(created_key_blobs->vkk_key);
  ASSERT_TRUE(derived_key_blobs->vkk_key);
  EXPECT_EQ(derived_key_blobs->vkk_key, created_key_blobs->vkk_key);
}

// Verifies that Derive succeeds on the output of Create, even when different
// algorithms are used for salt and for the TPM-backed secret.
TEST_F(ChallengeCredentialAuthBlockFullTest, DeriveCreatedDifferentAlgorithms) {
  constexpr auto kHwsecSaltAlgorithm = HwsecAlgorithm::kRsassaPkcs1V15Sha256;
  constexpr auto kSaltAlgorithm =
      structure::ChallengeSignatureAlgorithm::kRsassaPkcs1V15Sha256;
  constexpr auto kSaltChallengeAlgorithm = CHALLENGE_RSASSA_PKCS1_V1_5_SHA256;
  constexpr auto kHwsecTpmAlgorithm = HwsecAlgorithm::kRsassaPkcs1V15Sha1;
  constexpr auto kTpmAlgorithm =
      structure::ChallengeSignatureAlgorithm::kRsassaPkcs1V15Sha1;
  constexpr auto kTpmChallengeAlgorithm = CHALLENGE_RSASSA_PKCS1_V1_5_SHA1;
  const std::vector<HwsecAlgorithm> kHwsecAlgorithms = {kHwsecTpmAlgorithm,
                                                        kHwsecSaltAlgorithm};
  const std::vector<structure::ChallengeSignatureAlgorithm> kAlgorithms = {
      kTpmAlgorithm, kSaltAlgorithm};
  const AuthInput kAuthInput{
      .obfuscated_username = kObfuscatedUsername,
      .challenge_credential_auth_input =
          ChallengeCredentialAuthInput{
              .public_key_spki_der = kPublicKeySpkiDer,
              .challenge_signature_algorithms = kAlgorithms,
          },
  };

  // Setup: create an auth block state.
  CreateAuthBlock();
  BackendWillSeal(kHwsecAlgorithms);
  ChallengesWillRespond(kSaltChallengeAlgorithm);
  std::unique_ptr<KeyBlobs> created_key_blobs;
  std::unique_ptr<AuthBlockState> auth_block_state;
  ASSERT_THAT(RunCreate(kAuthInput, created_key_blobs, auth_block_state),
              IsOk());
  ASSERT_TRUE(created_key_blobs);
  ASSERT_TRUE(auth_block_state);
  // Backfill the scrypt wrapped_keyset, to mimic how the caller uses
  // scrypt-based auth blocks for derivation.

  // Test: run the derivation.
  CreateAuthBlock();
  BackendWillUnseal(kHwsecAlgorithms, kHwsecTpmAlgorithm);
  ChallengesWillRespond(kSaltChallengeAlgorithm);
  ChallengesWillRespond(kTpmChallengeAlgorithm);
  std::unique_ptr<KeyBlobs> derived_key_blobs;
  ASSERT_THAT(RunDerive(kAuthInput, *auth_block_state, derived_key_blobs),
              IsOk());
  ASSERT_TRUE(derived_key_blobs);

  // Assert: verify the derivation gives the same secret as the creation.
  ASSERT_TRUE(created_key_blobs->vkk_key);
  ASSERT_TRUE(derived_key_blobs->vkk_key);
  EXPECT_EQ(derived_key_blobs->vkk_key, created_key_blobs->vkk_key);
}

}  // namespace cryptohome
