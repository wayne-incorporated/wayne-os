// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Unit tests for VaultKeyset.

#include "cryptohome/vault_keyset.h"

#include <memory>
#include <openssl/evp.h>
#include <optional>
#include <string.h>  // For memcmp().
#include <utility>
#include <variant>
#include <vector>

#include <base/files/file_path.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/test/task_environment.h>
#include <brillo/secure_blob.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <libhwsec/frontend/cryptohome/mock_frontend.h>
#include <libhwsec/frontend/pinweaver/mock_frontend.h>
#include <libhwsec-foundation/crypto/aes.h>
#include <libhwsec-foundation/crypto/hmac.h>
#include <libhwsec-foundation/crypto/libscrypt_compat.h>
#include <libhwsec-foundation/crypto/sha.h>
#include <libhwsec-foundation/crypto/secure_blob_util.h>
#include <libhwsec-foundation/error/testing_helper.h>

#include "base/test/test_future.h"
#include "cryptohome/auth_blocks/auth_block.h"
#include "cryptohome/auth_blocks/auth_block_utils.h"
#include "cryptohome/auth_blocks/pin_weaver_auth_block.h"
#include "cryptohome/auth_blocks/scrypt_auth_block.h"
#include "cryptohome/crypto.h"
#include "cryptohome/crypto_error.h"
#include "cryptohome/cryptohome_common.h"
#include "cryptohome/fake_features.h"
#include "cryptohome/flatbuffer_schemas/auth_block_state.h"
#include "cryptohome/mock_cryptohome_keys_manager.h"
#include "cryptohome/mock_le_credential_manager.h"
#include "cryptohome/mock_platform.h"
#include "cryptohome/storage/file_system_keyset.h"

namespace cryptohome {
using base::FilePath;
using base::test::TestFuture;
using brillo::SecureBlob;
using cryptohome::error::CryptohomeCryptoError;
using cryptohome::error::CryptohomeError;
using cryptohome::error::CryptohomeLECredError;
using cryptohome::error::ErrorActionSet;
using cryptohome::error::PossibleAction;
using cryptohome::error::PrimaryAction;
using hwsec_foundation::CreateSecureRandomBlob;
using hwsec_foundation::GetSecureRandom;
using hwsec_foundation::HmacSha256;
using hwsec_foundation::kAesBlockSize;
using hwsec_foundation::SecureBlobToHex;
using hwsec_foundation::error::testing::IsOk;

using hwsec_foundation::error::testing::NotOk;
using hwsec_foundation::error::testing::ReturnError;
using hwsec_foundation::error::testing::ReturnOk;
using hwsec_foundation::error::testing::ReturnValue;
using hwsec_foundation::status::OkStatus;

using ::testing::_;
using ::testing::DoAll;
using ::testing::NiceMock;
using ::testing::Return;
using ::testing::SaveArg;
using ::testing::SetArgPointee;
using ::testing::WithArg;

namespace {
constexpr char kHexHighEntropySecret[] =
    "F3D9D5B126C36676689E18BB8517D95DF4F30947E71D4A840824425760B1D3FA";
constexpr char kHexResetSecret[] =
    "B133D2450392335BA8D33AA95AD52488254070C66F5D79AEA1A46AC4A30760D4";
constexpr char kHexWrappedKeyset[] =
    "B737B5D73E39BD390A4F361CE2FC166CF1E89EC6AEAA35D4B34456502C48B4F5EFA310077"
    "324B393E13AF633DF3072FF2EC78BD2B80D919035DB97C30F1AD418737DA3F26A4D35DF6B"
    "6A9743BD0DF3D37D8A68DE0932A9905452D05ECF92701B9805937F76EE01D10924268F057"
    "EDD66087774BB86C2CB92B01BD3A3C41C10C52838BD3A3296474598418E5191DEE9E8D831"
    "3C859C9EDB0D5F2BC1D7FC3C108A0D4ABB2D90E413086BCFFD0902AB68E2BF787817EB10C"
    "25E2E43011CAB3FB8AA";
constexpr char kHexSalt[] = "D470B9B108902241";
constexpr char kHexVaultKey[] =
    "665A58534E684F2B61516B6D42624B514E6749732B4348427450305453754158377232347"
    "37A79466C6B383D";
constexpr char kHexFekIv[] = "EA80F14BF29C6D580D536E7F0CC47F3E";
constexpr char kHexChapsIv[] = "ED85D928940E5B02ED218F29225AA34F";
constexpr char kHexWrappedChapsKey[] =
    "7D7D01EECC8DAE7906CAD56310954BBEB3CC81765210D29902AB92DDE074217771AD284F2"
    "12C13897C6CBB30CEC4CD75";

constexpr int kLegacyIndex = 1;
constexpr char kLegacyLabel[] = "legacy-1";
constexpr char kTempLabel[] = "tempLabel";

constexpr char kFilePath[] = "foo";
constexpr char kFakePasswordKey[] = "blabla";

constexpr int kPasswordRounds = 5;

std::string HexDecode(const std::string& hex) {
  std::vector<uint8_t> output;
  CHECK(base::HexStringToBytes(hex, &output));
  return std::string(output.begin(), output.end());
}

}  // namespace

class VaultKeysetTest : public ::testing::Test {
 public:
  VaultKeysetTest()
      : crypto_(&hwsec_, &pinweaver_, &cryptohome_keys_manager_, nullptr) {}
  VaultKeysetTest(const VaultKeysetTest&) = delete;
  VaultKeysetTest& operator=(const VaultKeysetTest&) = delete;

  ~VaultKeysetTest() override = default;

  static bool FindBlobInBlob(const brillo::SecureBlob& haystack,
                             const brillo::SecureBlob& needle) {
    if (needle.size() > haystack.size()) {
      return false;
    }
    for (unsigned int start = 0; start <= (haystack.size() - needle.size());
         start++) {
      if (memcmp(&haystack[start], needle.data(), needle.size()) == 0) {
        return true;
      }
    }
    return false;
  }

 protected:
  MockPlatform platform_;
  NiceMock<hwsec::MockCryptohomeFrontend> hwsec_;
  NiceMock<hwsec::MockPinWeaverFrontend> pinweaver_;
  NiceMock<MockCryptohomeKeysManager> cryptohome_keys_manager_;
  Crypto crypto_;
};

TEST_F(VaultKeysetTest, AllocateRandom) {
  // Check that allocating a random VaultKeyset works
  VaultKeyset vault_keyset;
  vault_keyset.Initialize(&platform_, &crypto_);
  vault_keyset.CreateFromFileSystemKeyset(FileSystemKeyset::CreateRandom());

  EXPECT_EQ(CRYPTOHOME_DEFAULT_KEY_SIZE, vault_keyset.GetFek().size());
  EXPECT_EQ(CRYPTOHOME_DEFAULT_KEY_SIGNATURE_SIZE,
            vault_keyset.GetFekSig().size());
  EXPECT_EQ(CRYPTOHOME_DEFAULT_KEY_SALT_SIZE, vault_keyset.GetFekSalt().size());

  EXPECT_EQ(CRYPTOHOME_DEFAULT_KEY_SIZE, vault_keyset.GetFnek().size());
  EXPECT_EQ(CRYPTOHOME_DEFAULT_KEY_SIGNATURE_SIZE,
            vault_keyset.GetFnekSig().size());
  EXPECT_EQ(CRYPTOHOME_DEFAULT_KEY_SALT_SIZE,
            vault_keyset.GetFnekSalt().size());
  EXPECT_EQ(CRYPTOHOME_CHAPS_KEY_LENGTH, vault_keyset.GetChapsKey().size());
}

TEST_F(VaultKeysetTest, SerializeTest) {
  // Check that serialize works
  VaultKeyset vault_keyset;
  vault_keyset.Initialize(&platform_, &crypto_);
  vault_keyset.CreateFromFileSystemKeyset(FileSystemKeyset::CreateRandom());

  SecureBlob blob;
  EXPECT_TRUE(vault_keyset.ToKeysBlob(&blob));

  EXPECT_TRUE(VaultKeysetTest::FindBlobInBlob(blob, vault_keyset.GetFek()));
  EXPECT_TRUE(VaultKeysetTest::FindBlobInBlob(blob, vault_keyset.GetFekSig()));
  EXPECT_TRUE(VaultKeysetTest::FindBlobInBlob(blob, vault_keyset.GetFekSalt()));

  EXPECT_TRUE(VaultKeysetTest::FindBlobInBlob(blob, vault_keyset.GetFnek()));
  EXPECT_TRUE(VaultKeysetTest::FindBlobInBlob(blob, vault_keyset.GetFnekSig()));
  EXPECT_TRUE(
      VaultKeysetTest::FindBlobInBlob(blob, vault_keyset.GetFnekSalt()));
}

TEST_F(VaultKeysetTest, DeserializeTest) {
  // Check that deserialize works
  VaultKeyset vault_keyset;
  vault_keyset.Initialize(&platform_, &crypto_);
  vault_keyset.CreateFromFileSystemKeyset(FileSystemKeyset::CreateRandom());

  SecureBlob blob;
  EXPECT_TRUE(vault_keyset.ToKeysBlob(&blob));

  VaultKeyset new_vault_keyset;
  EXPECT_TRUE(new_vault_keyset.FromKeysBlob(blob));

  EXPECT_EQ(vault_keyset.GetFek().size(), new_vault_keyset.GetFek().size());
  EXPECT_TRUE(VaultKeysetTest::FindBlobInBlob(vault_keyset.GetFek(),
                                              new_vault_keyset.GetFek()));
  EXPECT_EQ(vault_keyset.GetFekSig().size(),
            new_vault_keyset.GetFekSig().size());
  EXPECT_TRUE(VaultKeysetTest::FindBlobInBlob(vault_keyset.GetFekSig(),
                                              new_vault_keyset.GetFekSig()));
  EXPECT_EQ(vault_keyset.GetFekSalt().size(),
            new_vault_keyset.GetFekSalt().size());
  EXPECT_TRUE(VaultKeysetTest::FindBlobInBlob(vault_keyset.GetFekSalt(),
                                              new_vault_keyset.GetFekSalt()));

  EXPECT_EQ(vault_keyset.GetFnek().size(), new_vault_keyset.GetFnek().size());
  EXPECT_TRUE(VaultKeysetTest::FindBlobInBlob(vault_keyset.GetFnek(),
                                              new_vault_keyset.GetFnek()));
  EXPECT_EQ(vault_keyset.GetFnekSig().size(),
            new_vault_keyset.GetFnekSig().size());
  EXPECT_TRUE(VaultKeysetTest::FindBlobInBlob(vault_keyset.GetFnekSig(),
                                              new_vault_keyset.GetFnekSig()));
  EXPECT_EQ(vault_keyset.GetFnekSalt().size(),
            new_vault_keyset.GetFnekSalt().size());
  EXPECT_TRUE(VaultKeysetTest::FindBlobInBlob(vault_keyset.GetFnekSalt(),
                                              new_vault_keyset.GetFnekSalt()));
}

ACTION_P(CopyToSecureBlob, b) {
  b->assign(arg0.begin(), arg0.end());
  return true;
}

ACTION_P(CopyFromSecureBlob, b) {
  arg0->assign(b->begin(), b->end());
  return true;
}

TEST_F(VaultKeysetTest, WriteError) {
  // Setup.
  VaultKeyset vault_keyset;
  vault_keyset.Initialize(&platform_, &crypto_);
  vault_keyset.CreateFromFileSystemKeyset(FileSystemKeyset::CreateRandom());

  const auto reset_iv = CreateSecureRandomBlob(kAesBlockSize);
  static const int kFscryptPolicyVersion = 2;
  vault_keyset.SetResetIV(reset_iv);
  vault_keyset.SetFSCryptPolicyVersion(kFscryptPolicyVersion);
  vault_keyset.SetLegacyIndex(kLegacyIndex);
  KeyBlobs key_blobs = {.vkk_key = brillo::SecureBlob(32, 'A'),
                        .vkk_iv = brillo::SecureBlob(16, 'B'),
                        .chaps_iv = brillo::SecureBlob(16, 'C')};

  TpmBoundToPcrAuthBlockState pcr_state = {.salt = brillo::SecureBlob("salt")};
  AuthBlockState auth_state = {.state = pcr_state};
  ASSERT_THAT(vault_keyset.EncryptEx(key_blobs, auth_state),
              hwsec_foundation::error::testing::IsOk());

  EXPECT_CALL(platform_, WriteFileAtomicDurable(FilePath(kFilePath), _, _))
      .WillOnce(Return(false));
  // Test.
  EXPECT_FALSE(vault_keyset.Save(FilePath(kFilePath)));
}

TEST_F(VaultKeysetTest, ErrorSavingUnecryptedKeyset) {
  // Setup.
  VaultKeyset vault_keyset;
  vault_keyset.Initialize(&platform_, &crypto_);
  vault_keyset.CreateFromFileSystemKeyset(FileSystemKeyset::CreateRandom());

  // vault_keyset.encryptex is not called, therefore save should fail as soon as
  // it is tried.
  EXPECT_CALL(platform_, WriteFileAtomicDurable(FilePath(kFilePath), _, _))
      .Times(0);

  // Test.
  EXPECT_FALSE(vault_keyset.Save(FilePath(kFilePath)));
}

TEST_F(VaultKeysetTest, GetPcrBoundAuthBlockStateTest) {
  VaultKeyset keyset;
  keyset.Initialize(&platform_, &crypto_);

  keyset.CreateFromFileSystemKeyset(FileSystemKeyset::CreateRandom());
  keyset.SetFlags(SerializedVaultKeyset::TPM_WRAPPED |
                  SerializedVaultKeyset::SCRYPT_DERIVED |
                  SerializedVaultKeyset::PCR_BOUND);
  keyset.SetTpmPublicKeyHash(brillo::SecureBlob("yadayada"));
  keyset.SetTPMKey(brillo::SecureBlob("blabla"));
  keyset.SetExtendedTPMKey(brillo::SecureBlob("foobaz"));

  AuthBlockState auth_state;
  EXPECT_TRUE(GetAuthBlockState(keyset, auth_state));

  const TpmBoundToPcrAuthBlockState* tpm_state =
      std::get_if<TpmBoundToPcrAuthBlockState>(&auth_state.state);

  ASSERT_NE(tpm_state, nullptr);
  ASSERT_TRUE(tpm_state->scrypt_derived.has_value());
  EXPECT_TRUE(tpm_state->scrypt_derived.value());
  EXPECT_TRUE(tpm_state->extended_tpm_key.has_value());
  EXPECT_TRUE(tpm_state->tpm_key.has_value());
}

TEST_F(VaultKeysetTest, GetEccAuthBlockStateTest) {
  VaultKeyset keyset;
  keyset.Initialize(&platform_, &crypto_);

  keyset.CreateFromFileSystemKeyset(FileSystemKeyset::CreateRandom());
  keyset.SetFlags(SerializedVaultKeyset::TPM_WRAPPED |
                  SerializedVaultKeyset::SCRYPT_DERIVED |
                  SerializedVaultKeyset::ECC |
                  SerializedVaultKeyset::PCR_BOUND);
  keyset.SetTpmPublicKeyHash(brillo::SecureBlob("yadayada"));
  keyset.SetTPMKey(brillo::SecureBlob("blabla"));
  keyset.SetExtendedTPMKey(brillo::SecureBlob("foobaz"));
  keyset.password_rounds_ = 5;
  keyset.vkk_iv_ = brillo::SecureBlob("wowowow");
  keyset.auth_salt_ = brillo::SecureBlob("salt");

  AuthBlockState auth_state;
  EXPECT_TRUE(GetAuthBlockState(keyset, auth_state));

  const TpmEccAuthBlockState* tpm_state =
      std::get_if<TpmEccAuthBlockState>(&auth_state.state);

  ASSERT_NE(tpm_state, nullptr);
  EXPECT_TRUE(tpm_state->salt.has_value());
  EXPECT_TRUE(tpm_state->sealed_hvkkm.has_value());
  EXPECT_TRUE(tpm_state->extended_sealed_hvkkm.has_value());
  EXPECT_TRUE(tpm_state->tpm_public_key_hash.has_value());
  EXPECT_TRUE(tpm_state->vkk_iv.has_value());
  EXPECT_EQ(tpm_state->auth_value_rounds.value(), 5);
}

TEST_F(VaultKeysetTest, GetNotPcrBoundAuthBlockState) {
  VaultKeyset keyset;
  keyset.Initialize(&platform_, &crypto_);

  keyset.CreateFromFileSystemKeyset(FileSystemKeyset::CreateRandom());
  keyset.SetFlags(SerializedVaultKeyset::TPM_WRAPPED);
  keyset.SetTpmPublicKeyHash(brillo::SecureBlob("yadayada"));
  keyset.SetTPMKey(brillo::SecureBlob("blabla"));

  AuthBlockState auth_state;
  EXPECT_TRUE(GetAuthBlockState(keyset, auth_state));

  const TpmNotBoundToPcrAuthBlockState* tpm_state =
      std::get_if<TpmNotBoundToPcrAuthBlockState>(&auth_state.state);
  ASSERT_NE(tpm_state, nullptr);
  ASSERT_TRUE(tpm_state->scrypt_derived.has_value());
  EXPECT_FALSE(tpm_state->scrypt_derived.value());
  EXPECT_TRUE(tpm_state->tpm_key.has_value());
}

TEST_F(VaultKeysetTest, GetPinWeaverAuthBlockState) {
  VaultKeyset keyset;
  keyset.Initialize(&platform_, &crypto_);

  const uint64_t le_label = 012345;
  keyset.CreateFromFileSystemKeyset(FileSystemKeyset::CreateRandom());
  keyset.SetFlags(SerializedVaultKeyset::LE_CREDENTIAL);
  keyset.SetLELabel(le_label);

  AuthBlockState auth_state;
  EXPECT_TRUE(GetAuthBlockState(keyset, auth_state));

  const PinWeaverAuthBlockState* pin_auth_state =
      std::get_if<PinWeaverAuthBlockState>(&auth_state.state);
  ASSERT_NE(pin_auth_state, nullptr);
  EXPECT_TRUE(pin_auth_state->le_label.has_value());
  EXPECT_EQ(le_label, pin_auth_state->le_label.value());
}

TEST_F(VaultKeysetTest, GetChallengeCredentialAuthBlockState) {
  VaultKeyset keyset;
  keyset.Initialize(&platform_, &crypto_);

  keyset.CreateFromFileSystemKeyset(FileSystemKeyset::CreateRandom());
  keyset.SetFlags(SerializedVaultKeyset::SCRYPT_WRAPPED |
                  SerializedVaultKeyset::SIGNATURE_CHALLENGE_PROTECTED);
  const brillo::Blob kScryptPlaintext = brillo::BlobFromString("plaintext");
  const auto blob_to_encrypt = brillo::SecureBlob(brillo::CombineBlobs(
      {kScryptPlaintext, hwsec_foundation::Sha1(kScryptPlaintext)}));
  brillo::SecureBlob wrapped_keyset;
  brillo::SecureBlob wrapped_chaps_key;
  brillo::SecureBlob wrapped_reset_seed;
  brillo::SecureBlob derived_key = {
      0x67, 0xeb, 0xcd, 0x84, 0x49, 0x5e, 0xa2, 0xf3, 0xb1, 0xe6, 0xe7,
      0x5b, 0x13, 0xb9, 0x16, 0x2f, 0x5a, 0x39, 0xc8, 0xfe, 0x6a, 0x60,
      0xd4, 0x7a, 0xd8, 0x2b, 0x44, 0xc4, 0x45, 0x53, 0x1a, 0x85, 0x4a,
      0x97, 0x9f, 0x2d, 0x06, 0xf5, 0xd0, 0xd3, 0xa6, 0xe7, 0xac, 0x9b,
      0x02, 0xaf, 0x3c, 0x08, 0xce, 0x43, 0x46, 0x32, 0x6d, 0xd7, 0x2b,
      0xe9, 0xdf, 0x8b, 0x38, 0x0e, 0x60, 0x3d, 0x64, 0x12};
  brillo::SecureBlob scrypt_salt = brillo::SecureBlob("salt");
  brillo::SecureBlob chaps_salt = brillo::SecureBlob("chaps_salt");
  brillo::SecureBlob reset_seed_salt = brillo::SecureBlob("reset_seed_salt");

  scrypt_salt.resize(hwsec_foundation::kLibScryptSaltSize);
  chaps_salt.resize(hwsec_foundation::kLibScryptSaltSize);
  reset_seed_salt.resize(hwsec_foundation::kLibScryptSaltSize);
  ASSERT_TRUE(hwsec_foundation::LibScryptCompat::Encrypt(
      derived_key, scrypt_salt, blob_to_encrypt,
      hwsec_foundation::kDefaultScryptParams, &wrapped_keyset));
  ASSERT_TRUE(hwsec_foundation::LibScryptCompat::Encrypt(
      derived_key, chaps_salt, blob_to_encrypt,
      hwsec_foundation::kDefaultScryptParams, &wrapped_chaps_key));
  ASSERT_TRUE(hwsec_foundation::LibScryptCompat::Encrypt(
      derived_key, reset_seed_salt, blob_to_encrypt,
      hwsec_foundation::kDefaultScryptParams, &wrapped_reset_seed));
  keyset.SetWrappedKeyset(wrapped_keyset);
  keyset.SetWrappedChapsKey(wrapped_chaps_key);
  keyset.SetWrappedResetSeed(wrapped_reset_seed);

  AuthBlockState auth_state;
  EXPECT_TRUE(GetAuthBlockState(keyset, auth_state));

  const ChallengeCredentialAuthBlockState* cc_state =
      std::get_if<ChallengeCredentialAuthBlockState>(&auth_state.state);
  EXPECT_NE(cc_state, nullptr);
}

TEST_F(VaultKeysetTest, GetScryptAuthBlockState) {
  VaultKeyset keyset;
  keyset.Initialize(&platform_, &crypto_);

  keyset.CreateFromFileSystemKeyset(FileSystemKeyset::CreateRandom());
  keyset.SetFlags(SerializedVaultKeyset::SCRYPT_WRAPPED);
  const brillo::Blob kScryptPlaintext = brillo::BlobFromString("plaintext");
  const auto blob_to_encrypt = brillo::SecureBlob(brillo::CombineBlobs(
      {kScryptPlaintext, hwsec_foundation::Sha1(kScryptPlaintext)}));
  brillo::SecureBlob wrapped_keyset;
  brillo::SecureBlob wrapped_chaps_key;
  brillo::SecureBlob wrapped_reset_seed;
  brillo::SecureBlob derived_key = {
      0x67, 0xeb, 0xcd, 0x84, 0x49, 0x5e, 0xa2, 0xf3, 0xb1, 0xe6, 0xe7,
      0x5b, 0x13, 0xb9, 0x16, 0x2f, 0x5a, 0x39, 0xc8, 0xfe, 0x6a, 0x60,
      0xd4, 0x7a, 0xd8, 0x2b, 0x44, 0xc4, 0x45, 0x53, 0x1a, 0x85, 0x4a,
      0x97, 0x9f, 0x2d, 0x06, 0xf5, 0xd0, 0xd3, 0xa6, 0xe7, 0xac, 0x9b,
      0x02, 0xaf, 0x3c, 0x08, 0xce, 0x43, 0x46, 0x32, 0x6d, 0xd7, 0x2b,
      0xe9, 0xdf, 0x8b, 0x38, 0x0e, 0x60, 0x3d, 0x64, 0x12};
  brillo::SecureBlob scrypt_salt = brillo::SecureBlob("salt");
  brillo::SecureBlob chaps_salt = brillo::SecureBlob("chaps_salt");
  brillo::SecureBlob reset_seed_salt = brillo::SecureBlob("reset_seed_salt");

  scrypt_salt.resize(hwsec_foundation::kLibScryptSaltSize);
  chaps_salt.resize(hwsec_foundation::kLibScryptSaltSize);
  reset_seed_salt.resize(hwsec_foundation::kLibScryptSaltSize);
  ASSERT_TRUE(hwsec_foundation::LibScryptCompat::Encrypt(
      derived_key, scrypt_salt, blob_to_encrypt,
      hwsec_foundation::kDefaultScryptParams, &wrapped_keyset));
  ASSERT_TRUE(hwsec_foundation::LibScryptCompat::Encrypt(
      derived_key, chaps_salt, blob_to_encrypt,
      hwsec_foundation::kDefaultScryptParams, &wrapped_chaps_key));
  ASSERT_TRUE(hwsec_foundation::LibScryptCompat::Encrypt(
      derived_key, reset_seed_salt, blob_to_encrypt,
      hwsec_foundation::kDefaultScryptParams, &wrapped_reset_seed));
  keyset.SetWrappedKeyset(wrapped_keyset);
  keyset.SetWrappedChapsKey(wrapped_chaps_key);
  keyset.SetWrappedResetSeed(wrapped_reset_seed);

  AuthBlockState auth_state;
  EXPECT_TRUE(GetAuthBlockState(keyset, auth_state));

  const ScryptAuthBlockState* scrypt_state =
      std::get_if<ScryptAuthBlockState>(&auth_state.state);
  ASSERT_NE(scrypt_state, nullptr);
  EXPECT_TRUE(scrypt_state->salt.has_value());
  EXPECT_TRUE(scrypt_state->chaps_salt.has_value());
  EXPECT_TRUE(scrypt_state->reset_seed_salt.has_value());
  EXPECT_TRUE(scrypt_state->work_factor.has_value());
  EXPECT_TRUE(scrypt_state->block_size.has_value());
  EXPECT_TRUE(scrypt_state->parallel_factor.has_value());
}

TEST_F(VaultKeysetTest, GetDoubleWrappedCompatAuthBlockStateFailure) {
  VaultKeyset keyset;
  keyset.Initialize(&platform_, &crypto_);

  keyset.CreateFromFileSystemKeyset(FileSystemKeyset::CreateRandom());
  keyset.SetFlags(SerializedVaultKeyset::SCRYPT_WRAPPED |
                  SerializedVaultKeyset::TPM_WRAPPED);

  const brillo::Blob kScryptPlaintext = brillo::BlobFromString("plaintext");
  const auto blob_to_encrypt = brillo::SecureBlob(brillo::CombineBlobs(
      {kScryptPlaintext, hwsec_foundation::Sha1(kScryptPlaintext)}));
  brillo::SecureBlob wrapped_keyset;
  brillo::SecureBlob wrapped_chaps_key;
  brillo::SecureBlob wrapped_reset_seed;
  brillo::SecureBlob derived_key = {
      0x67, 0xeb, 0xcd, 0x84, 0x49, 0x5e, 0xa2, 0xf3, 0xb1, 0xe6, 0xe7,
      0x5b, 0x13, 0xb9, 0x16, 0x2f, 0x5a, 0x39, 0xc8, 0xfe, 0x6a, 0x60,
      0xd4, 0x7a, 0xd8, 0x2b, 0x44, 0xc4, 0x45, 0x53, 0x1a, 0x85, 0x4a,
      0x97, 0x9f, 0x2d, 0x06, 0xf5, 0xd0, 0xd3, 0xa6, 0xe7, 0xac, 0x9b,
      0x02, 0xaf, 0x3c, 0x08, 0xce, 0x43, 0x46, 0x32, 0x6d, 0xd7, 0x2b,
      0xe9, 0xdf, 0x8b, 0x38, 0x0e, 0x60, 0x3d, 0x64, 0x12};
  brillo::SecureBlob scrypt_salt = brillo::SecureBlob("salt");
  brillo::SecureBlob chaps_salt = brillo::SecureBlob("chaps_salt");
  brillo::SecureBlob reset_seed_salt = brillo::SecureBlob("reset_seed_salt");

  scrypt_salt.resize(hwsec_foundation::kLibScryptSaltSize);
  chaps_salt.resize(hwsec_foundation::kLibScryptSaltSize);
  reset_seed_salt.resize(hwsec_foundation::kLibScryptSaltSize);
  ASSERT_TRUE(hwsec_foundation::LibScryptCompat::Encrypt(
      derived_key, scrypt_salt, blob_to_encrypt,
      hwsec_foundation::kDefaultScryptParams, &wrapped_keyset));
  ASSERT_TRUE(hwsec_foundation::LibScryptCompat::Encrypt(
      derived_key, chaps_salt, blob_to_encrypt,
      hwsec_foundation::kDefaultScryptParams, &wrapped_chaps_key));
  ASSERT_TRUE(hwsec_foundation::LibScryptCompat::Encrypt(
      derived_key, reset_seed_salt, blob_to_encrypt,
      hwsec_foundation::kDefaultScryptParams, &wrapped_reset_seed));
  keyset.SetWrappedKeyset(wrapped_keyset);
  keyset.SetWrappedChapsKey(wrapped_chaps_key);
  keyset.SetWrappedResetSeed(wrapped_reset_seed);
  AuthBlockState auth_state;

  // A required tpm_key is not set in keyset, failure in creating
  // sub-state TpmNotBoundToPcrAuthBlockState.
  EXPECT_FALSE(GetAuthBlockState(keyset, auth_state));

  const DoubleWrappedCompatAuthBlockState* double_wrapped_state =
      std::get_if<DoubleWrappedCompatAuthBlockState>(&auth_state.state);
  EXPECT_EQ(double_wrapped_state, nullptr);
}

TEST_F(VaultKeysetTest, GetDoubleWrappedCompatAuthBlockState) {
  VaultKeyset keyset;
  keyset.Initialize(&platform_, &crypto_);

  keyset.CreateFromFileSystemKeyset(FileSystemKeyset::CreateRandom());
  keyset.SetFlags(SerializedVaultKeyset::SCRYPT_WRAPPED |
                  SerializedVaultKeyset::TPM_WRAPPED);
  keyset.SetTPMKey(brillo::SecureBlob("blabla"));
  const brillo::Blob kScryptPlaintext = brillo::BlobFromString("plaintext");
  const auto blob_to_encrypt = brillo::SecureBlob(brillo::CombineBlobs(
      {kScryptPlaintext, hwsec_foundation::Sha1(kScryptPlaintext)}));
  brillo::SecureBlob wrapped_keyset;
  brillo::SecureBlob wrapped_chaps_key;
  brillo::SecureBlob wrapped_reset_seed;
  brillo::SecureBlob derived_key = {
      0x67, 0xeb, 0xcd, 0x84, 0x49, 0x5e, 0xa2, 0xf3, 0xb1, 0xe6, 0xe7,
      0x5b, 0x13, 0xb9, 0x16, 0x2f, 0x5a, 0x39, 0xc8, 0xfe, 0x6a, 0x60,
      0xd4, 0x7a, 0xd8, 0x2b, 0x44, 0xc4, 0x45, 0x53, 0x1a, 0x85, 0x4a,
      0x97, 0x9f, 0x2d, 0x06, 0xf5, 0xd0, 0xd3, 0xa6, 0xe7, 0xac, 0x9b,
      0x02, 0xaf, 0x3c, 0x08, 0xce, 0x43, 0x46, 0x32, 0x6d, 0xd7, 0x2b,
      0xe9, 0xdf, 0x8b, 0x38, 0x0e, 0x60, 0x3d, 0x64, 0x12};
  brillo::SecureBlob scrypt_salt = brillo::SecureBlob("salt");
  brillo::SecureBlob chaps_salt = brillo::SecureBlob("chaps_salt");
  brillo::SecureBlob reset_seed_salt = brillo::SecureBlob("reset_seed_salt");

  scrypt_salt.resize(hwsec_foundation::kLibScryptSaltSize);
  chaps_salt.resize(hwsec_foundation::kLibScryptSaltSize);
  reset_seed_salt.resize(hwsec_foundation::kLibScryptSaltSize);
  ASSERT_TRUE(hwsec_foundation::LibScryptCompat::Encrypt(
      derived_key, scrypt_salt, blob_to_encrypt,
      hwsec_foundation::kDefaultScryptParams, &wrapped_keyset));
  ASSERT_TRUE(hwsec_foundation::LibScryptCompat::Encrypt(
      derived_key, chaps_salt, blob_to_encrypt,
      hwsec_foundation::kDefaultScryptParams, &wrapped_chaps_key));
  ASSERT_TRUE(hwsec_foundation::LibScryptCompat::Encrypt(
      derived_key, reset_seed_salt, blob_to_encrypt,
      hwsec_foundation::kDefaultScryptParams, &wrapped_reset_seed));
  keyset.SetWrappedKeyset(wrapped_keyset);
  keyset.SetWrappedChapsKey(wrapped_chaps_key);
  keyset.SetWrappedResetSeed(wrapped_reset_seed);

  AuthBlockState auth_state;
  EXPECT_TRUE(GetAuthBlockState(keyset, auth_state));

  const DoubleWrappedCompatAuthBlockState* double_wrapped_state =
      std::get_if<DoubleWrappedCompatAuthBlockState>(&auth_state.state);
  EXPECT_NE(double_wrapped_state, nullptr);
}

TEST_F(VaultKeysetTest, GetLegacyLabelTest) {
  VaultKeyset vault_keyset;
  vault_keyset.Initialize(&platform_, &crypto_);
  vault_keyset.SetLegacyIndex(kLegacyIndex);

  ASSERT_EQ(vault_keyset.GetLabel(), kLegacyLabel);
}

TEST_F(VaultKeysetTest, GetLabelTest) {
  VaultKeyset vault_keyset;
  vault_keyset.Initialize(&platform_, &crypto_);
  KeyData key_data;
  key_data.set_label(kTempLabel);
  vault_keyset.SetLegacyIndex(kLegacyIndex);
  vault_keyset.SetKeyData(key_data);

  ASSERT_EQ(vault_keyset.GetLabel(), kTempLabel);
}

TEST_F(VaultKeysetTest, GetEmptyLabelTest) {
  VaultKeyset vault_keyset;
  vault_keyset.Initialize(&platform_, &crypto_);
  KeyData key_data;

  // Setting empty label.
  key_data.set_label("");

  vault_keyset.SetLegacyIndex(kLegacyIndex);
  vault_keyset.SetKeyData(key_data);

  ASSERT_EQ(vault_keyset.GetLabel(), kLegacyLabel);
}

TEST_F(VaultKeysetTest, InitializeToAdd) {
  // Check if InitializeToAdd correctly copies keys
  // from parameter vault keyset to underlying data structure.

  VaultKeyset vault_keyset;
  vault_keyset.Initialize(&platform_, &crypto_);
  vault_keyset.CreateFromFileSystemKeyset(FileSystemKeyset::CreateRandom());

  const auto reset_iv = CreateSecureRandomBlob(kAesBlockSize);
  static const int kFscryptPolicyVersion = 2;
  vault_keyset.SetResetIV(reset_iv);
  vault_keyset.SetFSCryptPolicyVersion(kFscryptPolicyVersion);
  vault_keyset.SetLegacyIndex(kLegacyIndex);
  KeyBlobs key_blobs = {.vkk_key = brillo::SecureBlob(32, 'A'),
                        .vkk_iv = brillo::SecureBlob(16, 'B'),
                        .chaps_iv = brillo::SecureBlob(16, 'C')};

  TpmBoundToPcrAuthBlockState pcr_state = {.salt = brillo::SecureBlob("salt")};
  AuthBlockState auth_state = {.state = pcr_state};
  ASSERT_THAT(vault_keyset.EncryptEx(key_blobs, auth_state),
              hwsec_foundation::error::testing::IsOk());
  VaultKeyset vault_keyset_copy;
  vault_keyset_copy.InitializeToAdd(vault_keyset);

  // Check that InitializeToAdd correctly copied vault_keyset fields
  // i.e. fek/fnek keys, reset seed, reset IV, and FSCrypt policy version
  // FEK
  ASSERT_EQ(vault_keyset.GetFek(), vault_keyset_copy.GetFek());
  ASSERT_EQ(vault_keyset.GetFekSig(), vault_keyset_copy.GetFekSig());
  ASSERT_EQ(vault_keyset.GetFekSalt(), vault_keyset_copy.GetFekSalt());
  // FNEK
  ASSERT_EQ(vault_keyset.GetFnek(), vault_keyset_copy.GetFnek());
  ASSERT_EQ(vault_keyset.GetFnekSig(), vault_keyset_copy.GetFnekSig());
  ASSERT_EQ(vault_keyset.GetFnekSalt(), vault_keyset_copy.GetFnekSalt());
  // Other metadata
  ASSERT_EQ(vault_keyset.GetResetSeed(), vault_keyset_copy.GetResetSeed());
  ASSERT_EQ(vault_keyset.GetResetIV(), vault_keyset_copy.GetResetIV());
  ASSERT_EQ(vault_keyset.GetChapsKey(), vault_keyset_copy.GetChapsKey());
  ASSERT_EQ(vault_keyset.GetFSCryptPolicyVersion(),
            vault_keyset_copy.GetFSCryptPolicyVersion());

  // Other fields are empty/not changed/uninitialized
  // i.e. the wrapped_keyset_ shouldn't be copied
  ASSERT_NE(vault_keyset.GetWrappedKeyset(),
            vault_keyset_copy.GetWrappedKeyset());
  // int32_t flags_
  ASSERT_NE(vault_keyset_copy.GetFlags(), vault_keyset.GetFlags());
  // int legacy_index_
  ASSERT_NE(vault_keyset_copy.GetLegacyIndex(), vault_keyset.GetLegacyIndex());
}

TEST_F(VaultKeysetTest, GetTpmWritePasswordRounds) {
  // Test to ensure that for GetTpmNotBoundtoPcrState
  // correctly copies the password_rounds field from
  // the VaultKeyset to the auth_state parameter.

  VaultKeyset keyset;
  SerializedVaultKeyset serialized_vk;
  serialized_vk.set_flags(SerializedVaultKeyset::TPM_WRAPPED);
  serialized_vk.set_password_rounds(kPasswordRounds);

  keyset.InitializeFromSerialized(serialized_vk);
  keyset.Initialize(&platform_, &crypto_);

  keyset.SetTPMKey(brillo::SecureBlob(kFakePasswordKey));

  AuthBlockState tpm_state;
  EXPECT_TRUE(GetAuthBlockState(keyset, tpm_state));
  auto test_state =
      std::get_if<TpmNotBoundToPcrAuthBlockState>(&tpm_state.state);
  // test_state is of type TpmNotBoundToPcrAuthBlockState
  ASSERT_EQ(keyset.GetPasswordRounds(), test_state->password_rounds.value());
}

TEST_F(VaultKeysetTest, DecryptionTestWithKeyBlobs) {
  // Check that Decrypt returns the original keyset.
  // Setup

  VaultKeyset vault_keyset;
  vault_keyset.Initialize(&platform_, &crypto_);
  vault_keyset.CreateFromFileSystemKeyset(FileSystemKeyset::CreateRandom());

  SecureBlob bytes;
  EXPECT_CALL(platform_, WriteFileAtomicDurable(FilePath(kFilePath), _, _))
      .WillOnce(WithArg<1>(CopyToSecureBlob(&bytes)));

  EXPECT_CALL(platform_, ReadFile(FilePath(kFilePath), _))
      .WillOnce(WithArg<1>(CopyFromSecureBlob(&bytes)));

  KeyBlobs key_blobs = {.vkk_key = brillo::SecureBlob(32, 'A'),
                        .vkk_iv = brillo::SecureBlob(16, 'B'),
                        .chaps_iv = brillo::SecureBlob(16, 'C')};

  TpmBoundToPcrAuthBlockState pcr_state = {.salt = brillo::SecureBlob("salt")};
  AuthBlockState auth_state = {.state = pcr_state};
  ASSERT_TRUE(vault_keyset.EncryptEx(key_blobs, auth_state).ok());
  EXPECT_TRUE(vault_keyset.Save(FilePath(kFilePath)));
  EXPECT_EQ(vault_keyset.GetSourceFile(), FilePath(kFilePath));

  SecureBlob original_data;
  ASSERT_TRUE(vault_keyset.ToKeysBlob(&original_data));

  // Test
  VaultKeyset new_keyset;
  new_keyset.Initialize(&platform_, &crypto_);
  EXPECT_TRUE(new_keyset.Load(FilePath(kFilePath)));
  ASSERT_TRUE(new_keyset.DecryptEx(key_blobs).ok());

  // Verify
  SecureBlob new_data;
  ASSERT_TRUE(new_keyset.ToKeysBlob(&new_data));

  EXPECT_EQ(new_data.size(), original_data.size());
  ASSERT_TRUE(VaultKeysetTest::FindBlobInBlob(new_data, original_data));
}

TEST_F(VaultKeysetTest, DecryptWithAuthBlockFailNotLoaded) {
  // Check to decrypt a VaultKeyset that hasn't been loaded yet.

  VaultKeyset vault_keyset;
  vault_keyset.Initialize(&platform_, &crypto_);
  vault_keyset.CreateFromFileSystemKeyset(FileSystemKeyset::CreateRandom());

  KeyBlobs key_blobs = {.vkk_key = brillo::SecureBlob(32, 'A'),
                        .vkk_iv = brillo::SecureBlob(16, 'B'),
                        .chaps_iv = brillo::SecureBlob(16, 'C')};

  TpmBoundToPcrAuthBlockState pcr_state = {.salt = brillo::SecureBlob("salt")};
  AuthBlockState auth_state = {.state = pcr_state};

  EXPECT_TRUE(vault_keyset.EncryptEx(key_blobs, auth_state).ok());

  CryptoStatus status = vault_keyset.DecryptEx(key_blobs);
  // Load() needs to be called before decrypting the keyset.
  ASSERT_FALSE(status.ok());
  ASSERT_EQ(status->local_crypto_error(), CryptoError::CE_OTHER_CRYPTO);
}

TEST_F(VaultKeysetTest, KeyData) {
  VaultKeyset vk;
  vk.Initialize(&platform_, &crypto_);
  vk.SetLegacyIndex(0);
  EXPECT_FALSE(vk.HasKeyData());

  // When there's no key data stored, |GetKeyDataOrDefault()| should return an
  // empty protobuf.
  KeyData key_data = vk.GetKeyDataOrDefault();
  EXPECT_FALSE(key_data.has_type());
  EXPECT_FALSE(key_data.has_label());

  KeyData key_data2;
  key_data2.set_type(KeyData::KEY_TYPE_PASSWORD);
  key_data2.set_label("pin");
  vk.SetKeyData(key_data2);
  vk.SetLowEntropyCredential(true);
  ASSERT_TRUE(vk.HasKeyData());

  KeyData key_data3 = vk.GetKeyData();
  KeyData key_data4 = vk.GetKeyDataOrDefault();
  EXPECT_EQ(key_data3.has_type(), key_data4.has_type());
  EXPECT_EQ(key_data3.type(), key_data4.type());
  EXPECT_EQ(key_data3.has_label(), key_data4.has_label());
  EXPECT_EQ(key_data3.label(), key_data4.label());
  EXPECT_EQ(key_data3.has_policy(), key_data4.has_policy());
  EXPECT_EQ(key_data3.policy().has_low_entropy_credential(),
            key_data4.policy().has_low_entropy_credential());
  EXPECT_EQ(key_data3.policy().low_entropy_credential(),
            key_data4.policy().low_entropy_credential());

  EXPECT_TRUE(key_data3.has_type());
  EXPECT_EQ(key_data3.type(), KeyData::KEY_TYPE_PASSWORD);
  EXPECT_TRUE(key_data3.has_label());
  EXPECT_EQ(key_data3.label(), "pin");
  EXPECT_TRUE(key_data3.has_policy());
  EXPECT_TRUE(key_data3.policy().has_low_entropy_credential());
  EXPECT_TRUE(key_data3.policy().low_entropy_credential());
}

TEST_F(VaultKeysetTest, TPMBoundToPCRAuthBlockTypeToVKFlagNoScrypt) {
  VaultKeyset vault_keyset;
  // TPMBoundToPCR test, no Scrypt derived.
  TpmBoundToPcrAuthBlockState pcr_state = {.salt = brillo::SecureBlob("salt")};
  AuthBlockState auth_state = {.state = pcr_state};
  vault_keyset.SetAuthBlockState(auth_state);

  // Check that the keyset was indeed wrapped by the TPM, and the
  // keys were not derived using scrypt.
  unsigned int crypt_flags = vault_keyset.GetFlags();
  EXPECT_EQ(0, (crypt_flags & SerializedVaultKeyset::SCRYPT_WRAPPED));
  EXPECT_EQ(0, (crypt_flags & SerializedVaultKeyset::ECC));
  EXPECT_EQ(0, (crypt_flags & SerializedVaultKeyset::SCRYPT_DERIVED));
  EXPECT_EQ(0, (crypt_flags & SerializedVaultKeyset::LE_CREDENTIAL));
  EXPECT_EQ(
      0, (crypt_flags & SerializedVaultKeyset::SIGNATURE_CHALLENGE_PROTECTED));
  EXPECT_EQ(SerializedVaultKeyset::TPM_WRAPPED,
            (crypt_flags & SerializedVaultKeyset::TPM_WRAPPED));
  EXPECT_EQ(SerializedVaultKeyset::PCR_BOUND,
            (crypt_flags & SerializedVaultKeyset::PCR_BOUND));

  EXPECT_FALSE(vault_keyset.HasTPMKey());
  EXPECT_FALSE(vault_keyset.HasExtendedTPMKey());
  EXPECT_FALSE(vault_keyset.HasTpmPublicKeyHash());
}

TEST_F(VaultKeysetTest, TPMBoundToPCRAuthBlockTypeToVKFlagScrypt) {
  // TPMBoundToPCR test, Scrypt derived.
  VaultKeyset vault_keyset;
  brillo::SecureBlob tpm_key = brillo::SecureBlob("tpm_key");
  brillo::SecureBlob extended_tpm_key = brillo::SecureBlob("extended_tpm_key");
  brillo::SecureBlob tpm_public_key_hash =
      brillo::SecureBlob("tpm_public_key_hash");

  TpmBoundToPcrAuthBlockState pcr_state = {
      .scrypt_derived = true,
      .salt = brillo::SecureBlob("salt"),
      .tpm_key = tpm_key,
      .extended_tpm_key = extended_tpm_key,
      .tpm_public_key_hash = tpm_public_key_hash};
  AuthBlockState auth_state = {.state = pcr_state};
  vault_keyset.SetAuthBlockState(auth_state);
  // Check that the keyset was indeed wrapped by the TPM, and
  // the keys were derived using scrypt.
  unsigned int crypt_flags = vault_keyset.GetFlags();
  EXPECT_EQ(0, (crypt_flags & SerializedVaultKeyset::SCRYPT_WRAPPED));
  EXPECT_EQ(0, (crypt_flags & SerializedVaultKeyset::ECC));
  EXPECT_EQ(0, (crypt_flags & SerializedVaultKeyset::LE_CREDENTIAL));
  EXPECT_EQ(
      0, (crypt_flags & SerializedVaultKeyset::SIGNATURE_CHALLENGE_PROTECTED));
  EXPECT_EQ(SerializedVaultKeyset::SCRYPT_DERIVED,
            (crypt_flags & SerializedVaultKeyset::SCRYPT_DERIVED));
  EXPECT_EQ(SerializedVaultKeyset::TPM_WRAPPED,
            (crypt_flags & SerializedVaultKeyset::TPM_WRAPPED));
  EXPECT_EQ(SerializedVaultKeyset::PCR_BOUND,
            (crypt_flags & SerializedVaultKeyset::PCR_BOUND));

  EXPECT_TRUE(vault_keyset.HasTPMKey());
  EXPECT_EQ(vault_keyset.GetTPMKey(), tpm_key);

  EXPECT_TRUE(vault_keyset.HasExtendedTPMKey());
  EXPECT_EQ(vault_keyset.GetExtendedTPMKey(), extended_tpm_key);

  EXPECT_TRUE(vault_keyset.HasTpmPublicKeyHash());
  EXPECT_EQ(vault_keyset.GetTpmPublicKeyHash(), tpm_public_key_hash);
}

TEST_F(VaultKeysetTest, TPMNotBoundToPCRAuthBlockTypeToVKFlagNoScrypt) {
  VaultKeyset vault_keyset;
  // TPMNotBoundToPCR test, no Scrypt derived.
  TpmNotBoundToPcrAuthBlockState pcr_state = {.salt =
                                                  brillo::SecureBlob("salt")};
  AuthBlockState auth_state = {.state = pcr_state};
  vault_keyset.SetAuthBlockState(auth_state);

  // Check that the keyset was indeed wrapped by the TPM, and the
  // keys were not derived using scrypt.
  unsigned int crypt_flags = vault_keyset.GetFlags();
  EXPECT_EQ(0, (crypt_flags & SerializedVaultKeyset::SCRYPT_WRAPPED));
  EXPECT_EQ(0, (crypt_flags & SerializedVaultKeyset::ECC));
  EXPECT_EQ(0, (crypt_flags & SerializedVaultKeyset::SCRYPT_DERIVED));
  EXPECT_EQ(0, (crypt_flags & SerializedVaultKeyset::LE_CREDENTIAL));
  EXPECT_EQ(0, (crypt_flags & SerializedVaultKeyset::PCR_BOUND));
  EXPECT_EQ(
      0, (crypt_flags & SerializedVaultKeyset::SIGNATURE_CHALLENGE_PROTECTED));

  EXPECT_EQ(SerializedVaultKeyset::TPM_WRAPPED,
            (crypt_flags & SerializedVaultKeyset::TPM_WRAPPED));
  EXPECT_FALSE(vault_keyset.HasTPMKey());
  EXPECT_FALSE(vault_keyset.HasTpmPublicKeyHash());
}

TEST_F(VaultKeysetTest, TPMNotBoundToPCRAuthBlockTypeToVKFlagScrypt) {
  // TPMNotBoundToPCR test, Scrypt derived.
  VaultKeyset vault_keyset;
  brillo::SecureBlob tpm_key = brillo::SecureBlob("tpm_key");
  brillo::SecureBlob tpm_public_key_hash =
      brillo::SecureBlob("tpm_public_key_hash");

  TpmNotBoundToPcrAuthBlockState pcr_state = {
      .scrypt_derived = true,
      .salt = brillo::SecureBlob("salt"),
      .tpm_key = tpm_key,
      .tpm_public_key_hash = tpm_public_key_hash};
  AuthBlockState auth_state = {.state = pcr_state};
  vault_keyset.SetAuthBlockState(auth_state);
  // Check that the keyset was indeed wrapped by the TPM, and
  // the keys were derived using scrypt.
  unsigned int crypt_flags = vault_keyset.GetFlags();
  EXPECT_EQ(0, (crypt_flags & SerializedVaultKeyset::SCRYPT_WRAPPED));
  EXPECT_EQ(0, (crypt_flags & SerializedVaultKeyset::ECC));
  EXPECT_EQ(0, (crypt_flags & SerializedVaultKeyset::PCR_BOUND));
  EXPECT_EQ(0, (crypt_flags & SerializedVaultKeyset::LE_CREDENTIAL));
  EXPECT_EQ(SerializedVaultKeyset::SCRYPT_DERIVED,
            (crypt_flags & SerializedVaultKeyset::SCRYPT_DERIVED));
  EXPECT_EQ(SerializedVaultKeyset::TPM_WRAPPED,
            (crypt_flags & SerializedVaultKeyset::TPM_WRAPPED));
  EXPECT_EQ(
      0, (crypt_flags & SerializedVaultKeyset::SIGNATURE_CHALLENGE_PROTECTED));

  EXPECT_TRUE(vault_keyset.HasTPMKey());
  EXPECT_EQ(vault_keyset.GetTPMKey(), tpm_key);

  EXPECT_TRUE(vault_keyset.HasTpmPublicKeyHash());
  EXPECT_EQ(vault_keyset.GetTpmPublicKeyHash(), tpm_public_key_hash);
}

TEST_F(VaultKeysetTest, PinWeaverAuthBlockTypeToVKFlagNoValuesSet) {
  VaultKeyset vault_keyset;
  // PinWeaver test, no Scrypt derived.
  PinWeaverAuthBlockState pin_weaver_state = {.salt =
                                                  brillo::SecureBlob("salt")};
  AuthBlockState auth_state = {.state = pin_weaver_state};
  vault_keyset.SetAuthBlockState(auth_state);

  // Check that the keyset was indeed wrapped by Pin weave credentials.
  unsigned int crypt_flags = vault_keyset.GetFlags();
  EXPECT_EQ(0, (crypt_flags & SerializedVaultKeyset::SCRYPT_WRAPPED));
  EXPECT_EQ(0, (crypt_flags & SerializedVaultKeyset::ECC));
  EXPECT_EQ(0, (crypt_flags & SerializedVaultKeyset::SCRYPT_DERIVED));
  EXPECT_EQ(0, (crypt_flags & SerializedVaultKeyset::PCR_BOUND));
  EXPECT_EQ(SerializedVaultKeyset::LE_CREDENTIAL,
            (crypt_flags & SerializedVaultKeyset::LE_CREDENTIAL));
  EXPECT_EQ(
      0, (crypt_flags & SerializedVaultKeyset::SIGNATURE_CHALLENGE_PROTECTED));

  EXPECT_FALSE(vault_keyset.HasLELabel());
  EXPECT_FALSE(vault_keyset.HasResetSalt());
}

TEST_F(VaultKeysetTest, PinWeaverAuthBlockTypeToVKFlagValuesSet) {
  // PinWeaver test.
  VaultKeyset vault_keyset;
  brillo::SecureBlob reset_salt = brillo::SecureBlob("reset_salt");
  unsigned int le_label = 12345;  // random number;
  PinWeaverAuthBlockState pin_weaver_state = {
      .le_label = le_label,
      .salt = brillo::SecureBlob("salt"),
      .reset_salt = reset_salt};
  AuthBlockState auth_state = {.state = pin_weaver_state};
  vault_keyset.SetAuthBlockState(auth_state);
  // Check that the keyset was indeed wrapped by the Pin weaver.
  unsigned int crypt_flags = vault_keyset.GetFlags();
  EXPECT_EQ(0, (crypt_flags & SerializedVaultKeyset::SCRYPT_WRAPPED));
  EXPECT_EQ(0, (crypt_flags & SerializedVaultKeyset::ECC));
  EXPECT_EQ(0, (crypt_flags & SerializedVaultKeyset::SCRYPT_DERIVED));
  EXPECT_EQ(0, (crypt_flags & SerializedVaultKeyset::PCR_BOUND));
  EXPECT_EQ(
      0, (crypt_flags & SerializedVaultKeyset::SIGNATURE_CHALLENGE_PROTECTED));
  EXPECT_EQ(SerializedVaultKeyset::LE_CREDENTIAL,
            (crypt_flags & SerializedVaultKeyset::LE_CREDENTIAL));

  EXPECT_TRUE(vault_keyset.HasLELabel());
  EXPECT_TRUE(vault_keyset.HasResetSalt());
  EXPECT_EQ(vault_keyset.GetLELabel(), le_label);
  EXPECT_EQ(vault_keyset.GetResetSalt(), reset_salt);
}

TEST_F(VaultKeysetTest, ScryptAuthBlockTypeToVKFlagValuesSet) {
  // Scrypt test.
  VaultKeyset vault_keyset;
  ScryptAuthBlockState scrypt_state = {
      .salt = brillo::SecureBlob("salt"),
  };
  AuthBlockState auth_state = {.state = scrypt_state};
  vault_keyset.SetAuthBlockState(auth_state);
  // Check that the keyset was indeed wrapped by SCRYPT.
  unsigned int crypt_flags = vault_keyset.GetFlags();
  EXPECT_EQ(SerializedVaultKeyset::SCRYPT_WRAPPED,
            (crypt_flags & SerializedVaultKeyset::SCRYPT_WRAPPED));
  EXPECT_EQ(0, (crypt_flags & SerializedVaultKeyset::ECC));
  EXPECT_EQ(0, (crypt_flags & SerializedVaultKeyset::SCRYPT_DERIVED));
  EXPECT_EQ(0, (crypt_flags & SerializedVaultKeyset::PCR_BOUND));
  EXPECT_EQ(0, (crypt_flags & SerializedVaultKeyset::LE_CREDENTIAL));
  EXPECT_EQ(
      0, (crypt_flags & SerializedVaultKeyset::SIGNATURE_CHALLENGE_PROTECTED));
}

TEST_F(VaultKeysetTest, ChallengeCredentialAuthBlockTypeToVKFlagValuesSet) {
  // ChallengeCredential test.
  VaultKeyset vault_keyset;
  ChallengeCredentialAuthBlockState challenge_credential_state = {
      .keyset_challenge_info = structure::SignatureChallengeInfo{
          .sealed_secret = hwsec::Tpm2PolicySignedData{},
      }};
  AuthBlockState auth_state = {.state = challenge_credential_state};
  vault_keyset.SetAuthBlockState(auth_state);
  // Check that the keyset was indeed wrapped by SCRYPT.
  unsigned int crypt_flags = vault_keyset.GetFlags();
  EXPECT_EQ(
      SerializedVaultKeyset::SIGNATURE_CHALLENGE_PROTECTED,
      (crypt_flags & SerializedVaultKeyset::SIGNATURE_CHALLENGE_PROTECTED));
  EXPECT_EQ(0, (crypt_flags & SerializedVaultKeyset::ECC));
  EXPECT_EQ(0, (crypt_flags & SerializedVaultKeyset::SCRYPT_DERIVED));
  EXPECT_EQ(0, (crypt_flags & SerializedVaultKeyset::PCR_BOUND));
  EXPECT_EQ(0, (crypt_flags & SerializedVaultKeyset::LE_CREDENTIAL));
  EXPECT_EQ(0, (crypt_flags & SerializedVaultKeyset::SCRYPT_WRAPPED));

  EXPECT_TRUE(vault_keyset.HasSignatureChallengeInfo());
}

TEST_F(VaultKeysetTest, TpmEccAuthBlockTypeToVKFlagNoValues) {
  VaultKeyset vault_keyset;
  // TpmEcc test. Ensure that all fields are set to what is expected.
  TpmEccAuthBlockState ecc_state = {.salt = brillo::SecureBlob("salt")};
  AuthBlockState auth_state = {.state = ecc_state};
  vault_keyset.SetAuthBlockState(auth_state);

  unsigned int crypt_flags = vault_keyset.GetFlags();
  unsigned int tpm_ecc_require_flags = SerializedVaultKeyset::TPM_WRAPPED |
                                       SerializedVaultKeyset::SCRYPT_DERIVED |
                                       SerializedVaultKeyset::PCR_BOUND |
                                       SerializedVaultKeyset::ECC;
  EXPECT_NE(0, (crypt_flags & tpm_ecc_require_flags));
  EXPECT_EQ(0, (crypt_flags & SerializedVaultKeyset::LE_CREDENTIAL));
  EXPECT_EQ(
      0, (crypt_flags & SerializedVaultKeyset::SIGNATURE_CHALLENGE_PROTECTED));

  EXPECT_FALSE(vault_keyset.HasTPMKey());
  EXPECT_FALSE(vault_keyset.HasExtendedTPMKey());
  EXPECT_FALSE(vault_keyset.HasTpmPublicKeyHash());
  EXPECT_FALSE(vault_keyset.HasPasswordRounds());
  EXPECT_FALSE(vault_keyset.HasVkkIv());
}

TEST_F(VaultKeysetTest, TpmEccAuthBlockTypeToVKFlagHasValues) {
  // TpmEcc test. Ensure all values are set correctly.
  VaultKeyset vault_keyset;
  brillo::SecureBlob tpm_key = brillo::SecureBlob("tpm_key");
  brillo::SecureBlob extended_tpm_key = brillo::SecureBlob("extended_tpm_key");
  brillo::SecureBlob tpm_public_key_hash =
      brillo::SecureBlob("tpm_public_key_hash");
  brillo::SecureBlob vkk_iv = brillo::SecureBlob("vkk_iv");

  unsigned int passwords_round = 233;  // random number;.
  TpmEccAuthBlockState ecc_state = {.salt = brillo::SecureBlob("salt"),
                                    .vkk_iv = vkk_iv,
                                    .auth_value_rounds = passwords_round,
                                    .sealed_hvkkm = tpm_key,
                                    .extended_sealed_hvkkm = extended_tpm_key,
                                    .tpm_public_key_hash = tpm_public_key_hash};
  AuthBlockState auth_state = {.state = ecc_state};
  vault_keyset.SetAuthBlockState(auth_state);

  unsigned int crypt_flags = vault_keyset.GetFlags();
  unsigned int tpm_ecc_require_flags = SerializedVaultKeyset::TPM_WRAPPED |
                                       SerializedVaultKeyset::SCRYPT_DERIVED |
                                       SerializedVaultKeyset::PCR_BOUND |
                                       SerializedVaultKeyset::ECC;
  EXPECT_NE(0, (crypt_flags & tpm_ecc_require_flags));
  EXPECT_EQ(0, (crypt_flags & SerializedVaultKeyset::LE_CREDENTIAL));
  EXPECT_EQ(
      0, (crypt_flags & SerializedVaultKeyset::SIGNATURE_CHALLENGE_PROTECTED));

  EXPECT_TRUE(vault_keyset.HasTPMKey());
  EXPECT_EQ(vault_keyset.GetTPMKey(), tpm_key);

  EXPECT_TRUE(vault_keyset.HasExtendedTPMKey());
  EXPECT_EQ(vault_keyset.GetExtendedTPMKey(), extended_tpm_key);

  EXPECT_TRUE(vault_keyset.HasTpmPublicKeyHash());
  EXPECT_EQ(vault_keyset.GetTpmPublicKeyHash(), tpm_public_key_hash);

  EXPECT_TRUE(vault_keyset.HasPasswordRounds());
  EXPECT_EQ(vault_keyset.GetPasswordRounds(), passwords_round);

  EXPECT_TRUE(vault_keyset.HasVkkIv());
  EXPECT_EQ(vault_keyset.GetVkkIv(), vkk_iv);
}

class LeCredentialsManagerTest : public ::testing::Test {
 public:
  LeCredentialsManagerTest()
      : crypto_(&hwsec_, &pinweaver_, &cryptohome_keys_manager_, nullptr) {
    EXPECT_CALL(cryptohome_keys_manager_, Init())
        .WillOnce(Return());  // because HasCryptohomeKey returned false once.

    EXPECT_CALL(hwsec_, IsEnabled()).WillRepeatedly(ReturnValue(true));
    EXPECT_CALL(hwsec_, IsReady()).WillRepeatedly(ReturnValue(true));
    EXPECT_CALL(hwsec_, IsSealingSupported()).WillRepeatedly(ReturnValue(true));
    EXPECT_CALL(pinweaver_, IsEnabled()).WillRepeatedly(ReturnValue(true));

    // Raw pointer as crypto_ expects unique_ptr, which we will wrap this
    // allocation into.
    le_cred_manager_ = new MockLECredentialManager();
    EXPECT_CALL(*le_cred_manager_, CheckCredential(_, _, _, _))
        .WillRepeatedly(DoAll(
            SetArgPointee<2>(
                brillo::SecureBlob(HexDecode(kHexHighEntropySecret))),
            SetArgPointee<3>(brillo::SecureBlob(HexDecode(kHexResetSecret))),
            ReturnError<CryptohomeLECredError>()));
    crypto_.set_le_manager_for_testing(
        std::unique_ptr<LECredentialManager>(le_cred_manager_));

    crypto_.Init();

    pin_vault_keyset_.Initialize(&platform_, &crypto_);
  }

  ~LeCredentialsManagerTest() override = default;

  // Not copyable or movable
  LeCredentialsManagerTest(const LeCredentialsManagerTest&) = delete;
  LeCredentialsManagerTest& operator=(const LeCredentialsManagerTest&) = delete;
  LeCredentialsManagerTest(LeCredentialsManagerTest&&) = delete;
  LeCredentialsManagerTest& operator=(LeCredentialsManagerTest&&) = delete;

 protected:
  MockPlatform platform_;
  NiceMock<hwsec::MockCryptohomeFrontend> hwsec_;
  NiceMock<hwsec::MockPinWeaverFrontend> pinweaver_;
  NiceMock<MockCryptohomeKeysManager> cryptohome_keys_manager_;
  Crypto crypto_;
  MockLECredentialManager* le_cred_manager_;
  base::test::TaskEnvironment task_environment_;

  VaultKeyset pin_vault_keyset_;

  const CryptohomeError::ErrorLocationPair kErrorLocationForTesting1 =
      CryptohomeError::ErrorLocationPair(
          static_cast<::cryptohome::error::CryptohomeError::ErrorLocation>(1),
          std::string("Testing1"));
};

TEST_F(LeCredentialsManagerTest, EncryptWithKeyBlobs) {
  EXPECT_CALL(*le_cred_manager_, InsertCredential(_, _, _, _, _, _, _))
      .WillOnce(ReturnError<CryptohomeLECredError>());

  pin_vault_keyset_.CreateFromFileSystemKeyset(
      FileSystemKeyset::CreateRandom());
  pin_vault_keyset_.SetLowEntropyCredential(true);

  FakeFeaturesForTesting features;
  auto auth_block = std::make_unique<PinWeaverAuthBlock>(features.async,
                                                         crypto_.le_manager());

  AuthInput auth_input = {brillo::SecureBlob(HexDecode(kHexVaultKey)),
                          false,
                          Username("unused"),
                          ObfuscatedUsername("unused"),
                          /*reset_secret*/ std::nullopt,
                          pin_vault_keyset_.reset_seed_};
  base::test::TestFuture<CryptohomeStatus, std::unique_ptr<KeyBlobs>,
                         std::unique_ptr<AuthBlockState>>
      result;
  auth_block->Create(auth_input, result.GetCallback());
  ASSERT_TRUE(result.IsReady());
  auto [status, key_blobs, auth_state] = result.Take();
  ASSERT_THAT(status, IsOk());
  EXPECT_TRUE(
      std::holds_alternative<PinWeaverAuthBlockState>(auth_state->state));

  EXPECT_TRUE(pin_vault_keyset_.EncryptEx(*key_blobs, *auth_state).ok());
  EXPECT_TRUE(pin_vault_keyset_.HasResetSalt());
  EXPECT_FALSE(pin_vault_keyset_.HasWrappedResetSeed());
  EXPECT_FALSE(pin_vault_keyset_.GetAuthLocked());

  const SerializedVaultKeyset& serialized = pin_vault_keyset_.ToSerialized();
  EXPECT_FALSE(serialized.key_data().policy().auth_locked());
}

TEST_F(LeCredentialsManagerTest, EncryptWithKeyBlobsFailWithBadAuthState) {
  EXPECT_CALL(*le_cred_manager_, InsertCredential(_, _, _, _, _, _, _))
      .WillOnce(ReturnError<CryptohomeLECredError>(
          kErrorLocationForTesting1, ErrorActionSet({PossibleAction::kFatal}),
          LE_CRED_ERROR_NO_FREE_LABEL));

  pin_vault_keyset_.CreateFromFileSystemKeyset(
      FileSystemKeyset::CreateRandom());
  pin_vault_keyset_.SetLowEntropyCredential(true);

  brillo::SecureBlob reset_seed = CreateSecureRandomBlob(kAesBlockSize);

  FakeFeaturesForTesting features;
  auto auth_block = std::make_unique<PinWeaverAuthBlock>(features.async,
                                                         crypto_.le_manager());

  AuthInput auth_input = {brillo::SecureBlob(44, 'A'),
                          false,
                          Username("unused"),
                          ObfuscatedUsername("unused"),
                          /*reset_secret*/ std::nullopt,
                          pin_vault_keyset_.GetResetSeed()};
  base::test::TestFuture<CryptohomeStatus, std::unique_ptr<KeyBlobs>,
                         std::unique_ptr<AuthBlockState>>
      result;
  auth_block->Create(auth_input, result.GetCallback());
  ASSERT_TRUE(result.IsReady());
  auto [status, key_blobs, auth_state] = result.Take();
  ASSERT_THAT(status, NotOk());
}

TEST_F(LeCredentialsManagerTest, EncryptWithKeyBlobsFailWithNoResetSeed) {
  EXPECT_CALL(*le_cred_manager_, InsertCredential(_, _, _, _, _, _, _))
      .Times(0);

  pin_vault_keyset_.CreateFromFileSystemKeyset(
      FileSystemKeyset::CreateRandom());
  pin_vault_keyset_.SetLowEntropyCredential(true);

  FakeFeaturesForTesting features;
  auto auth_block = std::make_unique<PinWeaverAuthBlock>(features.async,
                                                         crypto_.le_manager());

  AuthInput auth_input = {
      brillo::SecureBlob(44, 'A'),   false, Username("unused"),
      ObfuscatedUsername("unused"),
      /*reset_secret*/ std::nullopt,
      /*reset_seed*/ std::nullopt};
  base::test::TestFuture<CryptohomeStatus, std::unique_ptr<KeyBlobs>,
                         std::unique_ptr<AuthBlockState>>
      result;
  auth_block->Create(auth_input, result.GetCallback());
  ASSERT_TRUE(result.IsReady());
  auto [status, key_blobs, auth_state] = result.Take();
  ASSERT_THAT(status, NotOk());
}

TEST_F(LeCredentialsManagerTest, DecryptWithKeyBlobs) {
  VaultKeyset vk;
  vk.Initialize(&platform_, &crypto_);

  SerializedVaultKeyset serialized;
  serialized.set_flags(SerializedVaultKeyset::LE_CREDENTIAL);
  serialized.set_le_fek_iv(HexDecode(kHexFekIv));
  serialized.set_le_chaps_iv(HexDecode(kHexChapsIv));
  serialized.set_wrapped_keyset(HexDecode(kHexWrappedKeyset));
  serialized.set_wrapped_chaps_key(HexDecode(kHexWrappedChapsKey));
  serialized.set_salt(HexDecode(kHexSalt));
  serialized.set_le_label(0644);

  vk.InitializeFromSerialized(serialized);

  FakeFeaturesForTesting features;
  auto auth_block = std::make_unique<PinWeaverAuthBlock>(features.async,
                                                         crypto_.le_manager());

  TestFuture<CryptohomeStatus, std::unique_ptr<KeyBlobs>,
             std::optional<AuthBlock::SuggestedAction>>
      result;
  AuthInput auth_input = {brillo::SecureBlob(HexDecode(kHexVaultKey)), false};
  AuthBlockState auth_state;
  ASSERT_TRUE(vk.GetPinWeaverState(&auth_state));
  auth_block->Derive(auth_input, auth_state, result.GetCallback());
  ASSERT_TRUE(result.IsReady());
  auto [status, key_blobs, suggested_action] = result.Take();
  ASSERT_THAT(status, IsOk());

  EXPECT_TRUE(vk.GetPinWeaverState(&auth_state));
  EXPECT_TRUE(vk.DecryptVaultKeysetEx(*key_blobs).ok());
}

}  // namespace cryptohome
